package union

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

// statementLifetime is how long every Entity Statement the demo signs
// stays valid.
const statementLifetime = 24 * time.Hour

// signingKey is one entity's key: the signer, its key ID, and the
// public JWK Set other entities verify it with.
type signingKey struct {
	signer crypto.Signer
	kid    string
	jwks   json.RawMessage
}

// newSigningKey generates an ES256 key published for purpose.
func newSigningKey(kid string, purpose keys.SigningPurpose) (signingKey, error) {
	signer, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return signingKey{}, err
	}
	manager, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: purpose, Algorithm: fapi.ES256, Signer: signer, KeyID: kid},
		},
	)
	if err != nil {
		return signingKey{}, err
	}
	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{{Manager: manager, Purpose: purpose, Algorithm: fapi.ES256}}, nil)
	if err != nil {
		return signingKey{}, err
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		return signingKey{}, err
	}
	return signingKey{signer: signer, kid: kid, jwks: jwks}, nil
}

// subordinate is what a superior says about one entity below it: the
// keys it vouches for, and the metadata policy and constraints it
// imposes.
type subordinate struct {
	jwks        json.RawMessage
	policy      federation.MetadataPolicy
	constraints *federation.Constraints
}

// entity is one member of the demo federation, served at its own host.
type entity struct {
	id      string // Entity Identifier, https://host:port
	host    string
	name    string
	role    string // shown in the console
	country string // "" for the Union itself

	key            signingKey
	authorityHints []string

	// metadata is the entity's own metadata, by entity type, for its
	// Entity Configuration.
	metadata func(ctx context.Context) (map[string]json.RawMessage, error)
	// trustMarks are the Trust Marks it publishes about itself.
	trustMarks func() ([]federation.RawTrustMark, error)
	// trustMarkIssuers is set on the Union only.
	trustMarkIssuers map[string][]string
	// subordinates, for an authority, is who it currently vouches for.
	subordinates func() map[string]subordinate
	// entityConfiguration overrides SelfIssuer signing (an identity
	// provider signs its own through server.Server).
	entityConfiguration func(ctx context.Context) (string, error)

	self      *federation.SelfIssuer
	subIssuer *federation.SubordinateIssuer
	mux       *http.ServeMux
}

// init builds the entity's issuers and registers its federation
// endpoints on its own mux; callers add their own pages afterwards.
func (e *entity) init() error {
	var err error
	e.self, err = federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID: e.id, AuthorityHints: e.authorityHints, Lifetime: statementLifetime,
		TrustMarkIssuers: e.trustMarkIssuers,
	}, federation.SelfIssueDependencies{
		Signer: e.key.signer, Algorithm: fapi.ES256, KeyID: e.key.kid, JWKS: e.key.jwks, Clock: federation.SystemClock{},
	})
	if err != nil {
		return fmt.Errorf("%s: self issuer: %w", e.host, err)
	}
	if e.subordinates != nil {
		e.subIssuer, err = federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{EntityID: e.id, Lifetime: statementLifetime},
			federation.SubordinateIssueDependencies{Signer: e.key.signer, Algorithm: fapi.ES256, KeyID: e.key.kid, Clock: federation.SystemClock{}})
		if err != nil {
			return fmt.Errorf("%s: subordinate issuer: %w", e.host, err)
		}
	}
	e.mux = http.NewServeMux()
	e.mux.HandleFunc("GET "+federation.WellKnownPath, e.serveEntityConfiguration)
	if e.subordinates != nil {
		e.mux.HandleFunc("GET /fetch", e.serveFetch)
	}
	return nil
}

// federationEntityMetadata is the "federation_entity" metadata every
// entity publishes: its name, and its fetch endpoint if it vouches for
// anyone.
func (e *entity) federationEntityMetadata() json.RawMessage {
	md := map[string]string{"organization_name": e.name}
	if e.subordinates != nil {
		md["federation_fetch_endpoint"] = e.id + "/fetch"
	}
	raw, _ := json.Marshal(md)
	return raw
}

// EntityConfiguration signs the entity's current Entity Configuration.
func (e *entity) EntityConfiguration(ctx context.Context) (string, error) {
	if e.entityConfiguration != nil {
		return e.entityConfiguration(ctx)
	}
	md := map[string]json.RawMessage{"federation_entity": e.federationEntityMetadata()}
	if e.metadata != nil {
		extra, err := e.metadata(ctx)
		if err != nil {
			return "", err
		}
		for k, v := range extra {
			md[k] = v
		}
	}
	var marks []federation.RawTrustMark
	if e.trustMarks != nil {
		var err error
		if marks, err = e.trustMarks(); err != nil {
			return "", err
		}
	}
	return e.self.EntityConfiguration(md, marks...)
}

func (e *entity) serveEntityConfiguration(w http.ResponseWriter, r *http.Request) {
	token, err := e.EntityConfiguration(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	federation.WriteEntityStatement(w, token)
}

// SubordinateStatement signs what the entity says about sub, or reports
// that it vouches for no such entity.
func (e *entity) SubordinateStatement(sub string) (string, bool, error) {
	s, ok := e.subordinates()[sub]
	if !ok {
		return "", false, nil
	}
	token, err := e.subIssuer.SubordinateStatement(federation.SubordinateStatementParams{
		Subject: sub, JWKS: s.jwks, MetadataPolicy: s.policy, Constraints: s.constraints,
		SourceEndpoint: e.id + "/fetch",
	})
	return token, true, err
}

func (e *entity) serveFetch(w http.ResponseWriter, r *http.Request) {
	sub, err := e.subIssuer.SubjectFromFetchRequest(r)
	if err != nil {
		federation.WriteError(w, err)
		return
	}
	token, ok, err := e.SubordinateStatement(sub)
	if err != nil {
		internalError(w, err)
		return
	}
	if !ok {
		federation.WriteError(w, federation.NewError(federation.ErrorNotFound, http.StatusNotFound, "this entity does not vouch for "+sub))
		return
	}
	federation.WriteEntityStatement(w, token)
}
