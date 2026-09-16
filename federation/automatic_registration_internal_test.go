package federation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/storage"
)

const testRPJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"rp-1","alg":"ES256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl4P0Sr2SFmvDMTFwbjKz8XkNhP4EQhQGE-tfWFdI"}]}`

func validRPMetadataJSON() string {
	return `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"jwks": ` + testRPJWKS + `
	}`
}

// newTestAutomaticClientRepository builds an AutomaticClientRepository
// with just enough wired up to exercise registeredClientConfigFromMetadata
// directly — underlying/resolver/clock are never touched by that method,
// only cfg and (when a test's own metadata declares jwks_uri) fetcher.
func newTestAutomaticClientRepository(automaticCfg AutomaticRegistrationConfig) *AutomaticClientRepository {
	return &AutomaticClientRepository{cfg: automaticCfg}
}

func newTestAutomaticClientRepositoryWithFetcher(t *testing.T, automaticCfg AutomaticRegistrationConfig, fetcher *fapihttp.Client) *AutomaticClientRepository {
	t.Helper()
	return &AutomaticClientRepository{cfg: automaticCfg, fetcher: fetcher}
}

func call(t *testing.T, repo *AutomaticClientRepository, raw string) (storage.RegisteredClientConfig, json.RawMessage, error) {
	t.Helper()
	return repo.registeredClientConfigFromMetadata(context.Background(), "https://rp.example.org", json.RawMessage(raw))
}

// testSelfSignedCert generates a fresh, real self-signed X.509
// certificate for key — genuinely valid DER, not stand-in bytes, since
// certificateThumbprintFromJWKS actually parses each x5c entry with
// x509.ParseCertificate before computing its thumbprint.
func testSelfSignedCert(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return cert
}

// jwksWithCertificate builds a one-entry JWK Set embedding cert's own
// DER as that entry's "x5c" member (RFC 7517 §4.7's own standard
// base64, not base64url).
func jwksWithCertificate(t *testing.T, key *ecdsa.PrivateKey, cert *x509.Certificate) string {
	t.Helper()
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256", "kid": "rp-cert",
		"x":   base64URLEncode(key.X.Bytes()),
		"y":   base64URLEncode(key.Y.Bytes()),
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}
	body, err := json.Marshal(map[string]any{"keys": []map[string]any{jwk}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return string(body)
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestRegisteredClientConfigFromMetadata(t *testing.T) {
	cfg, jwks, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), validRPMetadataJSON())
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.ID != "https://rp.example.org" {
		t.Errorf("ID = %q", cfg.ID)
	}
	if len(cfg.RedirectURIs) != 1 || cfg.RedirectURIs[0] != "https://rp.example.org/cb" {
		t.Errorf("RedirectURIs = %v", cfg.RedirectURIs)
	}
	if cfg.ClientAssertionAlgorithm != fapi.ES256 {
		t.Errorf("ClientAssertionAlgorithm = %v, want ES256", cfg.ClientAssertionAlgorithm)
	}
	if len(jwks) == 0 {
		t.Errorf("jwks is empty")
	}
	if !cfg.AutomaticFederationRegistration {
		t.Errorf("AutomaticFederationRegistration = false, want true")
	}
}

// TestRegisteredClientConfigFromMetadataFetchesJWKSURI confirms jwks_uri
// is now resolved eagerly, inside registeredClientConfigFromMetadata
// itself — not deferred to the caller — and that the returned jwks
// bytes are what the endpoint actually served.
func TestRegisteredClientConfigFromMetadataFetchesJWKSURI(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(testRPJWKS))
	}))
	t.Cleanup(ts.Close)
	fetcher := testFetcher(t, ts)

	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks_uri":"` + ts.URL + `/jwks.json"}`
	cfg, jwks, err := call(t, newTestAutomaticClientRepositoryWithFetcher(t, AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}, fetcher), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.ID != "https://rp.example.org" {
		t.Errorf("ID = %q", cfg.ID)
	}
	var got, want map[string]any
	if err := json.Unmarshal(jwks, &got); err != nil {
		t.Fatalf("unmarshal returned jwks: %v", err)
	}
	if err := json.Unmarshal([]byte(testRPJWKS), &want); err != nil {
		t.Fatalf("unmarshal testRPJWKS: %v", err)
	}
	gotKeys, wantKeys := got["keys"].([]any), want["keys"].([]any)
	if len(gotKeys) != len(wantKeys) {
		t.Errorf("jwks = %s, want the endpoint's own served body", jwks)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsUnreachableJWKSURI(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks_uri":"https://does-not-resolve.invalid/jwks.json"}`
	if _, _, err := call(t, newTestAutomaticClientRepositoryWithFetcher(t, AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}, testFetcher(t)), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(unreachable jwks_uri) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsBothJWKSAndJWKSURI(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks_uri":"https://rp.example.org/jwks.json","jwks":` + testRPJWKS + `}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(both jwks and jwks_uri) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsMissingRedirectURIs(t *testing.T) {
	raw := `{"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks":` + testRPJWKS + `}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(no redirect_uris) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsMissingJWKS(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256"}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(no jwks) = nil error, want error")
	}
}

// TestRegisteredClientConfigFromMetadataRejectsSelfSignedWithoutX5C
// confirms self_signed_tls_client_auth is now a recognized method — it
// fails here not because the method itself is unsupported, but because
// testRPJWKS carries no "x5c" member for certificateThumbprintFromJWKS
// to compute a thumbprint from.
func TestRegisteredClientConfigFromMetadataRejectsSelfSignedWithoutX5C(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"self_signed_tls_client_auth","jwks":` + testRPJWKS + `}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(self_signed_tls_client_auth, no x5c) = nil error, want error")
	}
}

// TestRegisteredClientConfigFromMetadataRejectsSelfSignedWithMalformedJWKS
// exercises certificateThumbprintFromJWKS's own jose.ParseJWKSet error
// branch — jwks present but not a well-formed JWK Set object at all.
func TestRegisteredClientConfigFromMetadataRejectsSelfSignedWithMalformedJWKS(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"self_signed_tls_client_auth","jwks":"not an object"}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(self_signed_tls_client_auth, malformed jwks) = nil error, want error")
	}
}

// TestRegisteredClientConfigFromMetadataRejectsSelfSignedWithUnparseableX5C
// exercises certificateThumbprintFromJWKS's own "x509.ParseCertificate
// fails, skip this entry" branch specifically — valid base64 (so
// decodeX5C itself succeeds), but not valid DER underneath.
func TestRegisteredClientConfigFromMetadataRejectsSelfSignedWithUnparseableX5C(t *testing.T) {
	jwks := `{"keys":[{"kty":"EC","crv":"P-256","kid":"rp-1","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl4P0Sr2SFmvDMTFwbjKz8XkNhP4EQhQGE-tfWFdI","x5c":["` +
		base64.StdEncoding.EncodeToString([]byte("not a real DER certificate")) + `"]}]}`
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"self_signed_tls_client_auth","jwks":` + jwks + `}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(self_signed_tls_client_auth, unparseable x5c) = nil error, want error")
	}
}

// TestRegisteredClientConfigFromMetadataAcceptsSelfSignedTLSClientAuth
// confirms the full path: a jwks entry carrying a real x5c certificate
// yields a client registered for self_signed_tls_client_auth, with
// ExpectedCertificateThumbprint computed from that same certificate.
func TestRegisteredClientConfigFromMetadataAcceptsSelfSignedTLSClientAuth(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := testSelfSignedCert(t, key)
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"self_signed_tls_client_auth","jwks":` + jwksWithCertificate(t, key, cert) + `}`

	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.ClientAuthMethod != storage.ClientAuthMethodSelfSignedTLSClientAuth {
		t.Errorf("ClientAuthMethod = %v, want self_signed_tls_client_auth", cfg.ClientAuthMethod)
	}
	if want := mtls.Thumbprint(cert); cfg.ExpectedCertificateThumbprint != want {
		t.Errorf("ExpectedCertificateThumbprint = %q, want %q", cfg.ExpectedCertificateThumbprint, want)
	}
}

func TestRegisteredClientConfigFromMetadataAcceptsTLSClientAuthSubjectDN(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"tls_client_auth","tls_client_auth_subject_dn":"CN=rp.example.org","jwks":` + testRPJWKS + `}`
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.ClientAuthMethod != storage.ClientAuthMethodTLSClientAuth {
		t.Errorf("ClientAuthMethod = %v, want tls_client_auth", cfg.ClientAuthMethod)
	}
	if cfg.ExpectedSubjectDN != "CN=rp.example.org" {
		t.Errorf("ExpectedSubjectDN = %q", cfg.ExpectedSubjectDN)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsTLSClientAuthWithoutSubjectDN(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"tls_client_auth","jwks":` + testRPJWKS + `}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(tls_client_auth, no subject_dn) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataAcceptsSANMethods(t *testing.T) {
	cases := map[string]struct {
		method, field, value string
		check                func(storage.RegisteredClientConfig) string
	}{
		"san_dns":   {"tls_client_auth_san_dns", "tls_client_auth_san_dns", "rp.example.org", func(c storage.RegisteredClientConfig) string { return c.ExpectedSANDNS }},
		"san_uri":   {"tls_client_auth_san_uri", "tls_client_auth_san_uri", "https://rp.example.org/id", func(c storage.RegisteredClientConfig) string { return c.ExpectedSANURI }},
		"san_ip":    {"tls_client_auth_san_ip", "tls_client_auth_san_ip", "203.0.113.1", func(c storage.RegisteredClientConfig) string { return c.ExpectedSANIP }},
		"san_email": {"tls_client_auth_san_email", "tls_client_auth_san_email", "rp@example.org", func(c storage.RegisteredClientConfig) string { return c.ExpectedSANEmail }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"` + tc.method + `","` + tc.field + `":"` + tc.value + `","jwks":` + testRPJWKS + `}`
			cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw)
			if err != nil {
				t.Fatalf("registeredClientConfigFromMetadata: %v", err)
			}
			if got := tc.check(cfg); got != tc.value {
				t.Errorf("expected field = %q, want %q", got, tc.value)
			}
		})
	}
}

func TestRegisteredClientConfigFromMetadataRejectsSANMethodsWithoutTheirField(t *testing.T) {
	for _, method := range []string{
		"tls_client_auth_san_dns", "tls_client_auth_san_uri", "tls_client_auth_san_ip", "tls_client_auth_san_email",
	} {
		t.Run(method, func(t *testing.T) {
			raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"` + method + `","jwks":` + testRPJWKS + `}`
			if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
				t.Fatalf("registeredClientConfigFromMetadata(%s, own field absent) = nil error, want error", method)
			}
		})
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidAuthMethod(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"client_secret_basic","jwks":` + testRPJWKS + `}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(client_secret_basic) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidAssertionAlgorithm(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"none","jwks":` + testRPJWKS + `}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(alg=none) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsMalformedJSON(t *testing.T) {
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), `not json`); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(malformed json) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataAcceptsRequestObjectSigningAlg(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"request_object_signing_alg": "ES256",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if alg, permitted := cfg.RequestObjectAlgorithm, cfg.RequestObjectAlgorithm != 0; !permitted || alg != fapi.ES256 {
		t.Errorf("RequestObjectAlgorithm = %v, permitted = %v, want ES256/true", alg, permitted)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidRequestObjectSigningAlg(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"request_object_signing_alg": "bogus",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bad request_object_signing_alg) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataMapsMTLSSenderConstrain(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"tls_client_certificate_bound_access_tokens": true,
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.SenderConstrain != storage.SenderConstrainMTLS {
		t.Errorf("SenderConstrain = %v, want mtls", cfg.SenderConstrain)
	}
}

func TestRegisteredClientConfigFromMetadataDoesNotGrantClientCredentialsByDefault(t *testing.T) {
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), validRPMetadataJSON())
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.AllowsClientCredentialsGrant {
		t.Errorf("AllowsClientCredentialsGrant = true, want false (AutomaticRegistrationConfig.AllowsClientCredentialsGrant not set)")
	}
}

func TestRegisteredClientConfigFromMetadataGrantsClientCredentialsWhenConfigured(t *testing.T) {
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsClientCredentialsGrant: true,
	}), validRPMetadataJSON())
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if !cfg.AllowsClientCredentialsGrant {
		t.Errorf("AllowsClientCredentialsGrant = false, want true (AutomaticRegistrationConfig.AllowsClientCredentialsGrant is set)")
	}
}

// An RP publishing backchannel_authentication_request_signing_alg in its
// own metadata must NOT grant it CIBA when AllowsCIBA is not set — the
// whole point of AllowsCIBA being a config-level switch (mirroring
// AllowedScopes) is that self-published metadata alone can never grant
// this capability.
func TestRegisteredClientConfigFromMetadataIgnoresCIBAMetadataWhenNotAllowed(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.BackchannelAuthenticationRequestAlgorithm != 0 {
		t.Errorf("BackchannelAuthenticationRequestAlgorithm = %v, want unset (AllowsCIBA not set)", cfg.BackchannelAuthenticationRequestAlgorithm)
	}
}

func TestRegisteredClientConfigFromMetadataMapsCIBAMetadataWhenAllowed(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode": "ping",
		"backchannel_client_notification_endpoint": "https://rp.example.org/notify",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.BackchannelAuthenticationRequestAlgorithm != fapi.ES256 {
		t.Errorf("BackchannelAuthenticationRequestAlgorithm = %v, want ES256", cfg.BackchannelAuthenticationRequestAlgorithm)
	}
	if cfg.BackchannelTokenDeliveryMode != storage.BackchannelTokenDeliveryModePing {
		t.Errorf("BackchannelTokenDeliveryMode = %v, want ping", cfg.BackchannelTokenDeliveryMode)
	}
	if cfg.BackchannelClientNotificationEndpoint.String() != "https://rp.example.org/notify" {
		t.Errorf("BackchannelClientNotificationEndpoint = %q, want https://rp.example.org/notify", cfg.BackchannelClientNotificationEndpoint.String())
	}
}

func TestRegisteredClientConfigFromMetadataDefaultsCIBADeliveryModeToPoll(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.BackchannelTokenDeliveryMode != storage.BackchannelTokenDeliveryModePoll {
		t.Errorf("BackchannelTokenDeliveryMode = %v, want poll (default)", cfg.BackchannelTokenDeliveryMode)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidCIBASigningAlg(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "bogus",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus backchannel_authentication_request_signing_alg) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidCIBADeliveryMode(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode": "push",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(backchannel_token_delivery_mode=push) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidCIBANotificationEndpoint(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode": "ping",
		"backchannel_client_notification_endpoint": "not a url",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(malformed backchannel_client_notification_endpoint) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataMapsIDTokenEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"id_token_encrypted_response_alg": "ECDH-ES+A256KW",
		"id_token_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	km, ce, enabled := cfg.IDTokenEncryptionKeyManagement, cfg.IDTokenEncryptionContentEncryption, cfg.IDTokenEncryptionKeyManagement != 0
	if !enabled || km == 0 || ce == 0 {
		t.Errorf("IDTokenEncryption = %v/%v/%v, want a non-zero pair", km, ce, enabled)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsUnpairedIDTokenEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"id_token_encrypted_response_alg": "ECDH-ES+A256KW",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(id_token enc alg without enc) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidIDTokenEncryptionKeyManagement(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"id_token_encrypted_response_alg": "bogus",
		"id_token_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus id_token_encrypted_response_alg) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidIDTokenEncryptionContentEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"id_token_encrypted_response_alg": "ECDH-ES+A256KW",
		"id_token_encrypted_response_enc": "bogus",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus id_token_encrypted_response_enc) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataMapsUserInfoEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"userinfo_encrypted_response_alg": "ECDH-ES+A256KW",
		"userinfo_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw)
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	km, ce, enabled := cfg.UserInfoEncryptionKeyManagement, cfg.UserInfoEncryptionContentEncryption, cfg.UserInfoEncryptionKeyManagement != 0
	if !enabled || km == 0 || ce == 0 {
		t.Errorf("UserInfoEncryption = %v/%v/%v, want a non-zero pair", km, ce, enabled)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidUserInfoEncryptionKeyManagement(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"userinfo_encrypted_response_alg": "bogus",
		"userinfo_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus userinfo_encrypted_response_alg) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidUserInfoEncryptionContentEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"userinfo_encrypted_response_alg": "ECDH-ES+A256KW",
		"userinfo_encrypted_response_enc": "bogus",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus userinfo_encrypted_response_enc) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsUnpairedUserInfoEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"userinfo_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := call(t, newTestAutomaticClientRepository(AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}), raw); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(userinfo enc without alg) = nil error, want error")
	}
}

// testFetcher builds a *fapihttp.Client trusting servers' own TLS
// certificates — for the one test that needs registeredClientConfigFromMetadata
// to actually fetch a jwks_uri. Passing zero servers still yields a
// working fetcher (just one that trusts nothing extra), for a test that
// only needs a well-formed, never-actually-reachable target.
func testFetcher(t *testing.T, servers ...*httptest.Server) *fapihttp.Client {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	return fetcher
}
