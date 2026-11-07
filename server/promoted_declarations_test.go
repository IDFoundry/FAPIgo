package server_test

// Wrappers embedding one of this package's types: what the embedded type
// declares about its own behaviour is never taken as the wrapper's
// declaration where the wrapper can change that behaviour.

import (
	"context"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// publishingIssuer embeds JWTAccessTokens and names the keys it signs
// with: signing, or the embedded ones when signing is nil.
type publishingIssuer struct {
	server.JWTAccessTokens
	signing keys.KeyManager
}

func (p publishingIssuer) AccessTokenSigningKeys() (keys.KeyManager, fapi.SignatureAlgorithm) {
	if p.signing != nil {
		return p.signing, p.Algorithm
	}
	return p.Keys, p.Algorithm
}

// IssueAccessToken signs with the keys AccessTokenSigningKeys names.
func (p publishingIssuer) IssueAccessToken(ctx context.Context, params server.AccessTokenParams) (string, string, error) {
	manager, algorithm := p.AccessTokenSigningKeys()
	return server.JWTAccessTokens{Keys: manager, Algorithm: algorithm}.IssueAccessToken(ctx, params)
}

// assuredPublishingIssuer adds AccessTokenIssuerAssurance, declaring the
// keys it publishes.
type assuredPublishingIssuer struct{ publishingIssuer }

func (a assuredPublishingIssuer) AccessTokenAssurance() server.AccessTokenAssurance {
	manager, _ := a.AccessTokenSigningKeys()
	return server.AccessTokenAssurance{SigningKeys: manager}
}

// opaqueOverJWTIssuer embeds JWTAccessTokens but issues only opaque
// tokens, kept in opaque.Store.
type opaqueOverJWTIssuer struct {
	server.JWTAccessTokens
	opaque server.OpaqueAccessTokens
}

func (o opaqueOverJWTIssuer) IssueAccessToken(ctx context.Context, p server.AccessTokenParams) (string, string, error) {
	return o.opaque.IssueAccessToken(ctx, p)
}

// declaringOpaqueOverJWTIssuer is opaqueOverJWTIssuer declaring what it
// signs with (nothing) and relies on (its opaque store).
type declaringOpaqueOverJWTIssuer struct{ opaqueOverJWTIssuer }

func (declaringOpaqueOverJWTIssuer) AccessTokenSigningKeys() (keys.KeyManager, fapi.SignatureAlgorithm) {
	return nil, 0
}

func (d declaringOpaqueOverJWTIssuer) AccessTokenAssurance() server.AccessTokenAssurance {
	return server.AccessTokenAssurance{Store: d.opaque.Store}
}

// TestEmbeddedJWTAccessTokensMustPublishKeys: an issuer embedding
// JWTAccessTokens, by value or pointer, that doesn't implement
// AccessTokenKeyPublisher is refused at every assurance level, since the
// server would otherwise publish (and RevokeToken trust) keys its
// overriding IssueAccessToken may not use.
func TestEmbeddedJWTAccessTokensMustPublishKeys(t *testing.T) {
	jwt := server.JWTAccessTokens{Keys: newTestKeyManager(), Algorithm: fapi.ES256}
	for name, issuer := range map[string]server.AccessTokenIssuer{
		"value":           embeddingIssuer{jwt},
		"pointer":         struct{ *server.JWTAccessTokens }{&jwt},
		"opaque override": opaqueOverJWTIssuer{jwt, server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}},
	} {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies()
			deps.AccessTokens = issuer
			if _, err := server.New(validConfig(t), deps); err == nil || !strings.Contains(err.Error(), "server.AccessTokenKeyPublisher") {
				t.Fatalf("New = %v, want an AccessTokenKeyPublisher refusal", err)
			}
		})
	}
	for name, issuer := range map[string]server.AccessTokenIssuer{
		"publishes the embedded keys": publishingIssuer{JWTAccessTokens: jwt},
		"publishes none":              declaringOpaqueOverJWTIssuer{opaqueOverJWTIssuer{jwt, server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}}},
	} {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies()
			deps.AccessTokens = issuer
			if _, err := server.New(validConfig(t), deps); err != nil {
				t.Fatalf("New: %v", err)
			}
		})
	}
}

// TestProductionChecksWhatAnEmbeddingIssuerDeclares: under
// AssuranceProduction an issuer embedding JWTAccessTokens is checked
// against its own AccessTokenIssuerAssurance, never the embedded keys.
// One that keeps opaque tokens in a memstore is refused, as
// OpaqueAccessTokens over that memstore is.
func TestProductionChecksWhatAnEmbeddingIssuerDeclares(t *testing.T) {
	jwt := server.JWTAccessTokens{Keys: newTestKeyManager(), Algorithm: fapi.ES256}
	mem := server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
	for name, tc := range map[string]struct {
		issuer server.AccessTokenIssuer
		want   string
	}{
		"opaque over memstore":                  {mem, "access_tokens"},
		"publishes keys, declares nothing":      {publishingIssuer{JWTAccessTokens: jwt}, "AccessTokenIssuerAssurance"},
		"declares the memstore it keeps tokens": {declaringOpaqueOverJWTIssuer{opaqueOverJWTIssuer{jwt, mem}}, "access_tokens"},
		"declares keys without custody":         {assuredPublishingIssuer{publishingIssuer{jwt, undeclaredKeyManager{inner: newTestKeyManager()}}}, "access_tokens keys"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := productionNew(t, func(d *server.Dependencies) { d.AccessTokens = tc.issuer }); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(production) = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	if err := productionNew(t, func(d *server.Dependencies) {
		d.AccessTokens = assuredPublishingIssuer{publishingIssuer{JWTAccessTokens: jwt}}
	}); err != nil {
		t.Fatalf("New(production, embedding issuer declaring keys with custody): %v", err)
	}
}

// TestPublicJWKSPublishesWhatAnEmbeddingIssuerNames: PublicJWKS
// publishes the access token key an AccessTokenKeyPublisher names, not
// the one it embeds, and none when it names none.
func TestPublicJWKSPublishesWhatAnEmbeddingIssuerNames(t *testing.T) {
	embedded := server.JWTAccessTokens{Keys: &fakeKeyManager{key: generateKey(t), keyID: "embedded-at"}, Algorithm: fapi.ES256}
	for name, tc := range map[string]struct {
		issuer        server.AccessTokenIssuer
		want, notWant string
	}{
		"other keys":     {publishingIssuer{embedded, &fakeKeyManager{key: generateKey(t), keyID: "wrapper-at"}}, "wrapper-at", "embedded-at"},
		"embedded keys":  {publishingIssuer{JWTAccessTokens: embedded}, "embedded-at", ""},
		"no keys at all": {declaringOpaqueOverJWTIssuer{opaqueOverJWTIssuer{embedded, server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}}}, "", "embedded-at"},
	} {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies()
			deps.AccessTokens = tc.issuer
			srv, err := server.New(validConfig(t), deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			set, err := srv.PublicJWKS(context.Background())
			if err != nil {
				t.Fatalf("PublicJWKS: %v", err)
			}
			kids := map[string]bool{}
			for _, key := range set.Keys {
				kids[key.KeyID()] = true
			}
			if tc.want != "" && !kids[tc.want] {
				t.Errorf("PublicJWKS kids = %v, want %q", kids, tc.want)
			}
			if tc.notWant != "" && kids[tc.notWant] {
				t.Errorf("PublicJWKS kids = %v, want no %q", kids, tc.notWant)
			}
		})
	}
}

// TestRevokeTokenRecognisesAPublishingIssuersAccessToken: RevokeToken
// answers unsupported_token_type (RFC 7009 §2.2.1) for a live access
// token an AccessTokenKeyPublisher signed, as for JWTAccessTokens'.
func TestRevokeTokenRecognisesAPublishingIssuersAccessToken(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	jwt, ok := h.deps.AccessTokens.(server.JWTAccessTokens)
	if !ok {
		t.Fatalf("harness access tokens = %T, want JWTAccessTokens", h.deps.AccessTokens)
	}
	h.deps.AccessTokens = publishingIssuer{jwt, &fakeKeyManager{key: generateKey(t), keyID: "wrapper-at"}}
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv
	owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	tokens, err := owner.refresh(owner.issueRefreshToken())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if code := serverErrorCode(t, owner.revoke(formParam("token", tokens.AccessToken.Reveal()))); code != server.ErrorUnsupportedTokenType {
		t.Fatalf("RevokeToken(own access token) code = %q, want %q", code, server.ErrorUnsupportedTokenType)
	}
}

// Wrappers embedding ClientCertificateTrust implementations.
type (
	embeddedNoChainTrust struct {
		server.NoClientCertificateChainTrust
	}
	embeddedNoChainTrustPointer struct {
		*server.NoClientCertificateChainTrust
	}
	embeddedVerifiedUpstream struct {
		server.ClientCertificateChainVerifiedUpstream
	}
)

// TestProductionRefusesEmbeddedNoClientCertificateChainTrust: a struct
// embedding NoClientCertificateChainTrust, by value or pointer, has its
// behaviour (no chain check anywhere), so AssuranceProduction refuses it
// as it refuses NoClientCertificateChainTrust itself.
func TestProductionRefusesEmbeddedNoClientCertificateChainTrust(t *testing.T) {
	for name, trust := range map[string]server.ClientCertificateTrust{
		"embedded":         embeddedNoChainTrust{},
		"embedded pointer": embeddedNoChainTrustPointer{&server.NoClientCertificateChainTrust{}},
	} {
		err := productionNew(t, func(d *server.Dependencies) { d.ClientCertificateTrust = trust })
		if err == nil || !strings.Contains(err.Error(), "client_certificate_trust") {
			t.Errorf("%s: New(production) = %v, want a client_certificate_trust refusal", name, err)
		}
	}
	if err := productionNew(t, func(d *server.Dependencies) {
		d.ClientCertificateTrust = embeddedVerifiedUpstream{}
	}); err != nil {
		t.Errorf("New(production, embedded ClientCertificateChainVerifiedUpstream): %v", err)
	}
}
