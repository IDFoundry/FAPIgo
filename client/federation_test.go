package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

func federationConfiguredConfig(t *testing.T) client.Config {
	t.Helper()
	cfg := validConfig(t)
	cfg.Federation = client.FederationConfig{
		EntityID:  "https://rp.example.org",
		Lifetime:  time.Hour,
		Algorithm: fapi.ES256,
	}
	return cfg
}

func federationConfiguredDependencies(t *testing.T) client.Dependencies {
	t.Helper()
	deps := validDependencies(t)
	deps.Keys = newFakeKeyManager(t,
		keys.ClientAuthentication, keys.RequestObjectSigning, keys.DPoPProofSigning, keys.FederationEntitySigning)
	return deps
}

func TestNewAcceptsZeroValueFederationConfig(t *testing.T) {
	cfg := validConfig(t)
	if cfg.Federation.EntityID != "" {
		t.Fatalf("validConfig's zero-value Federation.EntityID = %q, want empty", cfg.Federation.EntityID)
	}
	c, err := client.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(federation not configured) = nil error, want error")
	}
}

func TestNewRejectsInvalidFederationConfig(t *testing.T) {
	validCfg := federationConfiguredConfig(t)

	cases := map[string]func(*client.Config){
		"non-https entity ID": func(c *client.Config) { c.Federation.EntityID = "http://rp.example.org" },
		"zero lifetime":       func(c *client.Config) { c.Federation.Lifetime = 0 },
		"zero algorithm":      func(c *client.Config) { c.Federation.Algorithm = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validCfg
			mutate(&cfg)
			if _, err := client.New(cfg, federationConfiguredDependencies(t)); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestClientEntityConfigurationRejectsMissingSigningKey(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	deps := validDependencies(t)
	// Deliberately omit keys.FederationEntitySigning: this client's own
	// Keys never registered a federation signing key, mirroring a
	// deployment that enables Config.Federation without actually
	// provisioning one.
	deps.Keys = newFakeKeyManager(t, keys.ClientAuthentication, keys.RequestObjectSigning, keys.DPoPProofSigning)
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(no federation signing key registered) = nil error, want error")
	}
}

// emptyKidKeyManager wraps a real key manager but reports an empty
// "kid" for every purpose — reachable in practice through a
// misconfigured KeyManager backend, so keys.PublicJWKS's own explicit
// empty-kid guard can be exercised directly.
type emptyKidKeyManager struct{ *fakeKeyManager }

func (m emptyKidKeyManager) PublicKey(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	info, err := m.fakeKeyManager.PublicKey(ctx, purpose, algorithm)
	if err != nil {
		return keys.PublicKeyInfo{}, err
	}
	info.KeyID = ""
	return info, nil
}

func TestClientEntityConfigurationRejectsEmptyKeyID(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	deps := validDependencies(t)
	deps.Keys = emptyKidKeyManager{newFakeKeyManager(t, keys.FederationEntitySigning)}
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(key manager returns empty kid) = nil error, want error")
	}
}

func TestClientEntityConfiguration(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	cfg.Federation.AuthorityHints = []string{"https://ta.example.org"}
	c, err := client.New(cfg, federationConfiguredDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	metadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{"redirect_uris":["https://rp.example.org/cb"]}`),
	}
	token, err := c.EntityConfiguration(context.Background(), metadata)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}

	stmt, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	if stmt.ClaimedIssuer() != "https://rp.example.org" || stmt.ClaimedSubject() != "https://rp.example.org" {
		t.Errorf("iss/sub = %q/%q, want both equal to the configured entity ID", stmt.ClaimedIssuer(), stmt.ClaimedSubject())
	}
	if got := stmt.ClaimedAuthorityHints(); len(got) != 1 || got[0] != "https://ta.example.org" {
		t.Errorf("ClaimedAuthorityHints = %v, want [https://ta.example.org]", got)
	}

	// Full round trip: verify the statement's signature against its own
	// claimed jwks, exactly as federation.Resolver.verifySelfSigned
	// does for any self-signed Entity Configuration it encounters.
	candidates, err := jose.ParseJWKSet(stmt.ClaimedJWKS())
	if err != nil {
		t.Fatalf("jose.ParseJWKSet(ClaimedJWKS): %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("ParseJWKSet returned %d keys, want 1", len(candidates))
	}
	claims, err := stmt.Verify(candidates[0].PublicKey, intfed.VerifyPolicy{
		ExpectedIssuer: "https://rp.example.org", ExpectedSubject: "https://rp.example.org",
		Algorithm: fapi.ES256, Now: time.Now(), MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify(self-issued statement against its own claimed key): %v", err)
	}
	rp, ok := claims.Metadata["openid_relying_party"]
	if !ok {
		t.Fatalf("Metadata missing openid_relying_party: %v", claims.Metadata)
	}
	var rpMeta struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.Unmarshal(rp, &rpMeta); err != nil || len(rpMeta.RedirectURIs) != 1 {
		t.Errorf("openid_relying_party = %s, want the redirect_uris passed through", rp)
	}
}

// selfAnchoredOpenIDProvider starts an httptest.TLSServer that is its
// own OpenID Federation Trust Anchor (a degenerate, zero-hop chain —
// federation.Resolver.Resolve's own "subject may itself be a configured
// Trust Anchor" case) and serves a self-issued Entity Configuration
// carrying buildMetadata's own return value as its own "metadata"
// claim. buildMetadata is called with the entity ID (== the server's
// own URL, known only once the server has started) so a caller can
// embed it as the "issuer" field of an "openid_provider" object — see
// metadata.ParseAndValidate's anti-spoofing check, which requires
// exactly that. buildMetadata may be nil (an Entity Configuration with
// no metadata claim at all). Returns the entity ID and a
// *federation.Resolver already configured to trust it.
func selfAnchoredOpenIDProvider(t *testing.T, buildMetadata func(entityID string) map[string]json.RawMessage) (entityID string, resolver *federation.Resolver) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID("as-federation-key").MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	jwks, err := json.Marshal(map[string][]json.RawMessage{"keys": {jwkJSON}})
	if err != nil {
		t.Fatalf("marshal jwk set: %v", err)
	}

	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	entityID = ts.URL

	issuer, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID: entityID, Lifetime: time.Hour,
	}, federation.SelfIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "as-federation-key",
		JWKS: jwks, Clock: federation.SystemClock{},
	})
	if err != nil {
		t.Fatalf("NewSelfIssuer: %v", err)
	}
	var metadata map[string]json.RawMessage
	if buildMetadata != nil {
		metadata = buildMetadata(entityID)
	}
	token, err := issuer.EntityConfiguration(metadata)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}
	mux.HandleFunc(federation.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", federation.EntityStatementContentType)
		w.Write([]byte(token))
	})

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	resolver, err = federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: entityID, JWKS: jwks}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return entityID, resolver
}

func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestDiscoverViaFederationRejectsNilResolver(t *testing.T) {
	if _, err := client.DiscoverViaFederation(context.Background(), nil, "https://as.example.org"); err == nil {
		t.Fatalf("DiscoverViaFederation(nil resolver) = nil error, want error")
	}
}

func TestDiscoverViaFederationRejectsEmptyIssuer(t *testing.T) {
	_, resolver := selfAnchoredOpenIDProvider(t, nil)
	if _, err := client.DiscoverViaFederation(context.Background(), resolver, ""); err == nil {
		t.Fatalf("DiscoverViaFederation(empty issuer) = nil error, want error")
	}
}

func TestDiscoverViaFederationRejectsMissingOpenIDProviderMetadata(t *testing.T) {
	entityID, resolver := selfAnchoredOpenIDProvider(t, nil)
	if _, err := client.DiscoverViaFederation(context.Background(), resolver, entityID); err == nil {
		t.Fatalf("DiscoverViaFederation(no openid_provider metadata) = nil error, want error")
	}
}

// TestDiscoverViaFederation confirms DiscoverViaFederation produces the
// identical DiscoveredMetadata shape client.Discover does, sourced from
// a Trust-Chain-verified "openid_provider" object instead of a live
// ".well-known/openid-configuration" fetch.
func TestDiscoverViaFederation(t *testing.T) {
	entityID, resolver := selfAnchoredOpenIDProvider(t, func(entityID string) map[string]json.RawMessage {
		openIDProvider := map[string]json.RawMessage{
			"issuer":                                mustMarshal(t, entityID),
			"token_endpoint":                        mustMarshal(t, entityID+"/token"),
			"jwks_uri":                              mustMarshal(t, entityID+"/jwks"),
			"id_token_signing_alg_values_supported": mustMarshal(t, []string{"ES256"}),
			"authorization_response_iss_parameter_supported": mustMarshal(t, true),
			"client_registration_types_supported":            mustMarshal(t, []string{"automatic"}),
		}
		return map[string]json.RawMessage{"openid_provider": mustMarshal(t, openIDProvider)}
	})

	md, err := client.DiscoverViaFederation(context.Background(), resolver, entityID)
	if err != nil {
		t.Fatalf("DiscoverViaFederation: %v", err)
	}
	if got, want := md.Endpoints.Token.String(), entityID+"/token"; got != want {
		t.Errorf("Endpoints.Token = %q, want %q", got, want)
	}
	if got, want := md.JWKSURI.String(), entityID+"/jwks"; got != want {
		t.Errorf("JWKSURI = %q, want %q", got, want)
	}
	if len(md.IDTokenAlgorithms) != 1 || md.IDTokenAlgorithms[0] != fapi.ES256 {
		t.Errorf("IDTokenAlgorithms = %v, want [ES256]", md.IDTokenAlgorithms)
	}
	if !md.AuthorizationResponseIssSupported {
		t.Errorf("AuthorizationResponseIssSupported = false, want true")
	}
}

// TestDiscoverViaFederationRejectsIssuerMismatch confirms the same
// anti-spoofing check client.Discover itself enforces (OIDC Discovery
// 1.0 §4.3) still applies here: an "openid_provider" object whose own
// "issuer" field doesn't match the resolved entity ID is rejected, even
// though the object arrived inside an already Trust-Chain-verified
// Entity Configuration.
func TestDiscoverViaFederationRejectsIssuerMismatch(t *testing.T) {
	entityID, resolver := selfAnchoredOpenIDProvider(t, func(entityID string) map[string]json.RawMessage {
		openIDProvider := map[string]json.RawMessage{
			"issuer":         mustMarshal(t, "https://wrong-issuer.example.org"),
			"token_endpoint": mustMarshal(t, entityID+"/token"),
			"jwks_uri":       mustMarshal(t, entityID+"/jwks"),
		}
		return map[string]json.RawMessage{"openid_provider": mustMarshal(t, openIDProvider)}
	})
	if _, err := client.DiscoverViaFederation(context.Background(), resolver, entityID); err == nil {
		t.Fatalf("DiscoverViaFederation(issuer mismatch) = nil error, want error")
	}
}

// TestDiscoverViaFederationClientRegistrationTypes covers OpenID
// Federation 1.0 §12.1: an OP supporting Automatic Registration MUST
// list "automatic" in client_registration_types_supported, and this
// package only does Automatic Registration — so an OP that omits it
// (or lists only "explicit") must be refused before any authorization
// request is attempted. Unrecognized extra values are tolerated.
func TestDiscoverViaFederationClientRegistrationTypes(t *testing.T) {
	cases := map[string]struct {
		types   any
		wantErr bool
	}{
		"missing":                {types: nil, wantErr: true},
		"empty":                  {types: []string{}, wantErr: true},
		"explicit only":          {types: []string{"explicit"}, wantErr: true},
		"automatic":              {types: []string{"automatic"}},
		"automatic plus unknown": {types: []string{"automatic", "some-future-type"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			entityID, resolver := selfAnchoredOpenIDProvider(t, func(entityID string) map[string]json.RawMessage {
				openIDProvider := map[string]json.RawMessage{
					"issuer":                                mustMarshal(t, entityID),
					"token_endpoint":                        mustMarshal(t, entityID+"/token"),
					"jwks_uri":                              mustMarshal(t, entityID+"/jwks"),
					"id_token_signing_alg_values_supported": mustMarshal(t, []string{"ES256"}),
				}
				if tc.types != nil {
					openIDProvider["client_registration_types_supported"] = mustMarshal(t, tc.types)
				}
				return map[string]json.RawMessage{"openid_provider": mustMarshal(t, openIDProvider)}
			})
			_, err := client.DiscoverViaFederation(context.Background(), resolver, entityID)
			if tc.wantErr && err == nil {
				t.Fatalf("DiscoverViaFederation(%s) = nil error, want error", name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("DiscoverViaFederation(%s): %v", name, err)
			}
		})
	}
}
