package federation_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/storage"
)

// TestNewAutomaticClientRepositoryCopiesItsConfig: editing an element of
// one of the AutomaticRegistrationConfig's slices in place after
// NewAutomaticClientRepository changes nothing about the clients it
// registers. Each case edits one slice of the config already passed in;
// the Relying Party, first resolved after the edit (a registration
// already cached would hide one), must then be registered as a
// repository built from an identical, unedited config registers it.
func TestNewAutomaticClientRepositoryCopiesItsConfig(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataNamingNoSigningAlgorithm(t))
	for name, edit := range map[string]func(*federation.AutomaticRegistrationConfig){
		"AllowedScopes": func(c *federation.AutomaticRegistrationConfig) { c.AllowedScopes[1] = "payments" },
		"AuthorizationDetailsTypes": func(c *federation.AutomaticRegistrationConfig) {
			c.AuthorizationDetailsTypes[0] = "account_information"
		},
		"AllowedResources": func(c *federation.AutomaticRegistrationConfig) { c.AllowedResources[0] = "https://rs.example/payments" },
		"AllowedClientAuthMethods": func(c *federation.AutomaticRegistrationConfig) {
			c.AllowedClientAuthMethods[0] = storage.ClientAuthMethodSelfSignedTLSClientAuth
		},
		"ClientAssertionAlgorithms": func(c *federation.AutomaticRegistrationConfig) { c.ClientAssertionAlgorithms[0] = fapi.PS256 },
		"SubjectTypes":              func(c *federation.AutomaticRegistrationConfig) { c.SubjectTypes[0] = fapi.SubjectTypePairwise },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := everySliceRegistrationConfig()
			repo := newCopiesItsConfigRepository(t, f, cfg)
			control := newCopiesItsConfigRepository(t, f, everySliceRegistrationConfig())
			edit(&cfg)
			if got, want := registrationOf(t, repo, f), registrationOf(t, control, f); !reflect.DeepEqual(got, want) {
				t.Errorf("after the config passed in was edited, the RP is registered as\n%+v\nwant what the unedited control registers\n%+v", got, want)
			}
		})
	}
}

// everySliceRegistrationConfig is a valid AutomaticRegistrationConfig
// with a value in each of its slices, built afresh by each call.
func everySliceRegistrationConfig() federation.AutomaticRegistrationConfig {
	return federation.AutomaticRegistrationConfig{
		AllowedScopes:             []string{"openid", "accounts"},
		AuthorizationDetailsTypes: []string{"payment"},
		AllowedResources:          []string{"https://rs.example/accounts", "https://rs.example/statements"},
		AllowedClientAuthMethods:  []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT},
		ClientAssertionAlgorithms: []fapi.SignatureAlgorithm{fapi.ES256},
		SubjectTypes:              []fapi.SubjectType{fapi.SubjectTypePublic},
		DefaultSubjectType:        fapi.SubjectTypePublic,
		MaxCacheAge:               time.Hour,
	}
}

func newCopiesItsConfigRepository(t *testing.T, f *automaticRegistrationFixture, cfg federation.AutomaticRegistrationConfig) *federation.AutomaticClientRepository {
	t.Helper()
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	return repo
}

// rpMetadataNamingNoSigningAlgorithm is rpMetadataBuilder without
// token_endpoint_auth_signing_alg, so the client registered from it gets
// AutomaticRegistrationConfig.ClientAssertionAlgorithms.
func rpMetadataNamingNoSigningAlgorithm(t *testing.T) func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
	return func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"redirect_uris":              []string{rpID + "/cb"},
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       json.RawMessage(jwksFor(t, "rp-oidc", rpOIDCKey)),
		})
		if err != nil {
			t.Fatalf("marshal openid_relying_party metadata: %v", err)
		}
		return raw
	}
}

// registration is how an AutomaticClientRepository registers f's Relying
// Party, as far as its config decides.
type registration struct {
	Err string
	// Scopes is those of openid, accounts and payments it may request.
	Scopes                    []string
	AuthorizationDetailsTypes []string
	AllowedResources          []string
	ClientAuthMethods         []storage.ClientAuthMethod
	ClientAssertionAlgorithms []fapi.SignatureAlgorithm
	SubjectType               fapi.SubjectType
}

func registrationOf(t *testing.T, repo *federation.AutomaticClientRepository, f *automaticRegistrationFixture) registration {
	t.Helper()
	client, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
	if err != nil {
		return registration{Err: err.Error()}
	}
	got := registration{
		AuthorizationDetailsTypes: client.AuthorizationDetailsTypes(),
		AllowedResources:          client.AllowedResources(),
		ClientAuthMethods:         client.ClientAuthMethods(),
		ClientAssertionAlgorithms: client.ClientAssertionAlgorithms(),
		SubjectType:               client.SubjectType(),
	}
	for _, scope := range []string{"openid", "accounts", "payments"} {
		if client.AllowsScope(scope) {
			got.Scopes = append(got.Scopes, scope)
		}
	}
	return got
}

// TestNewResolverCopiesTrustAnchorJWKS: overwriting the JWKS bytes of
// the Config passed to NewResolver with another key's leaves the Trust
// Anchor verified against its configured key.
func TestNewResolverCopiesTrustAnchorJWKS(t *testing.T) {
	anchor := setupSelfSignedAnchor(t)
	r, cfg := anchor.newResolver(t)
	copy(cfg.TrustAnchors[0].JWKS, jwksFor(t, "ta", generateKey(t)))
	if _, err := r.Resolve(context.Background(), anchor.entityID); err != nil {
		t.Fatalf("Resolve after the caller's Trust Anchor JWKS was overwritten: %v", err)
	}
}

// TestResolveReturnsACopyOfTrustAnchorJWKS: the ResolvedEntity.JWKS
// Resolve returns for a configured Trust Anchor is a copy, so
// overwriting it leaves the anchor verified against its configured key.
func TestResolveReturnsACopyOfTrustAnchorJWKS(t *testing.T) {
	anchor := setupSelfSignedAnchor(t)
	r, _ := anchor.newResolver(t)
	resolved, err := r.Resolve(context.Background(), anchor.entityID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	copy(resolved.JWKS, jwksFor(t, "ta", generateKey(t)))
	if _, err := r.Resolve(context.Background(), anchor.entityID); err != nil {
		t.Fatalf("Resolve after the returned JWKS was overwritten: %v", err)
	}
}

// TestNewResolverCopiesTrustAnchorEntityIDs: renaming the Trust Anchor
// of the Config passed to NewResolver changes nothing about which Trust
// Anchor ResolveViaEndpoint accepts.
func TestNewResolverCopiesTrustAnchorEntityIDs(t *testing.T) {
	const renamed = "https://other-ta.example.org"
	anchor := setupSelfSignedAnchor(t)
	r, cfg := anchor.newResolver(t)
	cfg.TrustAnchors[0].EntityID = renamed
	request := federation.ResolveRequest{
		Endpoint: anchor.entityID + "/resolve", Subject: anchor.entityID, ExpectedIssuer: anchor.entityID, TrustAnchor: renamed,
	}
	_, err := r.ResolveViaEndpoint(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "is not one of this Resolver's Config.TrustAnchors") {
		t.Errorf("ResolveViaEndpoint(trust_anchor = the caller's new name) = %v, want it refused as not configured", err)
	}
	// Past the Trust Anchor check, an empty ExpectedIssuer is refused
	// before anything is fetched.
	request.TrustAnchor, request.ExpectedIssuer = anchor.entityID, ""
	_, err = r.ResolveViaEndpoint(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "expected resolver issuer") {
		t.Errorf("ResolveViaEndpoint(trust_anchor = the configured one) = %v, want it past the Trust Anchor check", err)
	}
}

// selfSignedAnchor is a Trust Anchor serving its own Entity
// Configuration over TLS, for the tests that a Resolver keeps its own
// copy of its Trust Anchors.
type selfSignedAnchor struct {
	entityID string
	key      *ecdsa.PrivateKey
	fetcher  *fapihttp.Client
	now      time.Time
}

func setupSelfSignedAnchor(t *testing.T) selfSignedAnchor {
	t.Helper()
	a := selfSignedAnchor{key: generateKey(t), now: time.Now()}
	entityID, ts := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: a.key, Algorithm: fapi.ES256, KeyID: "ta",
			Issuer: id, Subject: id, Now: a.now, Lifetime: time.Hour, JWKS: jwksFor(t, "ta", a.key),
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)
	a.entityID, a.fetcher = entityID, fetcherFor(t, ts)
	return a
}

// newResolver returns a Resolver trusting a, and the Config it was built
// from.
func (a selfSignedAnchor) newResolver(t *testing.T) (*federation.Resolver, federation.Config) {
	t.Helper()
	cfg := federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: a.entityID, JWKS: jwksFor(t, "ta", a.key)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}
	r, err := federation.NewResolver(cfg, federation.Dependencies{HTTP: a.fetcher, Clock: fixedClock{now: a.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r, cfg
}

// TestNewSelfIssuerCopiesItsConfig: editing the caller's AuthorityHints,
// TrustMarkIssuers (the map or a list in it) or JWKS in place after
// NewSelfIssuer changes no Entity Configuration it signs.
func TestNewSelfIssuerCopiesItsConfig(t *testing.T) {
	const certified = "https://ta.example.org/marks/certified"
	key := generateKey(t)
	now := time.Now()
	cfg := federation.SelfIssueConfig{
		EntityID: "https://ta.example.org", Lifetime: time.Hour,
		AuthorityHints:   []string{"https://superior.example.org"},
		TrustMarkIssuers: map[string][]string{certified: {"https://issuer.example.org"}},
	}
	deps := federation.SelfIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "ta", JWKS: jwksFor(t, "ta", key), Clock: fixedClock{now: now},
	}
	s, err := federation.NewSelfIssuer(cfg, deps)
	if err != nil {
		t.Fatalf("NewSelfIssuer: %v", err)
	}
	cfg.AuthorityHints[0] = "https://other-superior.example.org"
	cfg.TrustMarkIssuers[certified][0] = "https://other-issuer.example.org"
	cfg.TrustMarkIssuers["https://ta.example.org/marks/open"] = nil
	copy(deps.JWKS, jwksFor(t, "ta", generateKey(t)))

	token, err := s.EntityConfiguration(nil)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}
	stmt, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	// Verified against its own claimed jwks, as Resolver.verifySelfSigned
	// does: overwritten, it would name another key.
	candidates, err := jose.ParseJWKSet(stmt.ClaimedJWKS())
	if err != nil || len(candidates) != 1 {
		t.Fatalf("jose.ParseJWKSet(ClaimedJWKS) = %d keys, %v; want 1", len(candidates), err)
	}
	claims, err := stmt.Verify(candidates[0].PublicKey, intfed.VerifyPolicy{
		ExpectedIssuer: "https://ta.example.org", ExpectedSubject: "https://ta.example.org",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify against the claimed jwks: %v", err)
	}
	if got, want := stmt.ClaimedAuthorityHints(), []string{"https://superior.example.org"}; !slices.Equal(got, want) {
		t.Errorf("authority_hints = %q, want %q", got, want)
	}
	if got, want := claims.TrustMarkIssuers, map[string][]string{certified: {"https://issuer.example.org"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("trust_mark_issuers = %q, want %q", got, want)
	}
}
