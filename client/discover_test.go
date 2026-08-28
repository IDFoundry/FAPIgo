package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/metadata"
)

func newDiscoveryFetcher(t *testing.T, ts *httptest.Server) *fapihttp.Client {
	t.Helper()
	c, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16,
		RequestTimeout:   5 * time.Second,
		MaxRedirects:     1,
		// ts is a local httptest server on loopback; opt in to
		// fapihttp's SSRF pre-check allowing it, same as a real
		// deployment pointing at a loopback issuer would.
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	return c
}

type discoveryDoc struct {
	Issuer                              string   `json:"issuer"`
	AuthorizationEndpoint               string   `json:"authorization_endpoint"`
	TokenEndpoint                       string   `json:"token_endpoint"`
	PushedAuthorizationRequestEndpoint  string   `json:"pushed_authorization_request_endpoint"`
	JWKSURI                             string   `json:"jwks_uri"`
	UserinfoEndpoint                    string   `json:"userinfo_endpoint,omitempty"`
	IDTokenSigningAlgValuesSupported    []string `json:"id_token_signing_alg_values_supported,omitempty"`
	RequestObjectSigningAlgValues       []string `json:"request_object_signing_alg_values_supported,omitempty"`
	AuthorizationSigningAlgValues       []string `json:"authorization_signing_alg_values_supported,omitempty"`
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	RequireSignedRequestObject          bool     `json:"require_signed_request_object,omitempty"`

	UserinfoSigningAlgValuesSupported    []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	BackchannelAuthenticationEndpoint                         string   `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported                    []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`

	MTLSEndpointAliases *discoveryMTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`
}

type discoveryMTLSEndpointAliases struct {
	TokenEndpoint                      string `json:"token_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	BackchannelAuthenticationEndpoint  string `json:"backchannel_authentication_endpoint,omitempty"`
}

func TestDiscoverAcceptsValidDocumentAtRoot(t *testing.T) {
	var gotPath string
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		doc := discoveryDoc{
			Issuer:                              ts.URL,
			AuthorizationEndpoint:               ts.URL + "/authorize",
			TokenEndpoint:                       ts.URL + "/token",
			PushedAuthorizationRequestEndpoint:  ts.URL + "/par",
			JWKSURI:                             ts.URL + "/jwks",
			UserinfoEndpoint:                    ts.URL + "/userinfo",
			IDTokenSigningAlgValuesSupported:    []string{"ES256", "RS256"},
			RequestObjectSigningAlgValues:       []string{"ES256"},
			AuthorizationSigningAlgValues:       []string{"ES256"},
			IDTokenEncryptionAlgValuesSupported: []string{"RSA-OAEP-256", "RSA-OAEP"},
			IDTokenEncryptionEncValuesSupported: []string{"A256GCM", "A128GCM"},
			RequireSignedRequestObject:          true,

			UserinfoSigningAlgValuesSupported:    []string{"ES256", "RS256"},
			UserinfoEncryptionAlgValuesSupported: []string{"RSA-OAEP-256", "RSA-OAEP"},
			UserinfoEncryptionEncValuesSupported: []string{"A256GCM", "A128GCM"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	tsIssuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL(ts.URL): %v", err)
	}

	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), tsIssuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if gotPath != "/.well-known/openid-configuration" {
		t.Errorf("fetched path = %q, want /.well-known/openid-configuration", gotPath)
	}
	if md.Endpoints.Authorization.String() != ts.URL+"/authorize" {
		t.Errorf("Authorization = %q", md.Endpoints.Authorization.String())
	}
	if md.Endpoints.Token.String() != ts.URL+"/token" {
		t.Errorf("Token = %q", md.Endpoints.Token.String())
	}
	if md.Endpoints.PushedAuthorizationRequest.String() != ts.URL+"/par" {
		t.Errorf("PushedAuthorizationRequest = %q", md.Endpoints.PushedAuthorizationRequest.String())
	}
	if md.JWKSURI.String() != ts.URL+"/jwks" {
		t.Errorf("JWKSURI = %q", md.JWKSURI.String())
	}
	if md.Endpoints.UserInfo.String() != ts.URL+"/userinfo" {
		t.Errorf("Endpoints.UserInfo = %q", md.Endpoints.UserInfo.String())
	}
	if len(md.IDTokenAlgorithms) != 1 || md.IDTokenAlgorithms[0] != fapi.ES256 {
		t.Errorf("IDTokenAlgorithms = %v, want [ES256] (RS256 is unsupported and must be filtered)", md.IDTokenAlgorithms)
	}
	if len(md.RequestObjectAlgorithms) != 1 || md.RequestObjectAlgorithms[0] != fapi.ES256 {
		t.Errorf("RequestObjectAlgorithms = %v, want [ES256]", md.RequestObjectAlgorithms)
	}
	if len(md.JARMAlgorithms) != 1 || md.JARMAlgorithms[0] != fapi.ES256 {
		t.Errorf("JARMAlgorithms = %v, want [ES256]", md.JARMAlgorithms)
	}
	if len(md.IDTokenEncryptionAlgorithms) != 1 || md.IDTokenEncryptionAlgorithms[0] != fapi.RSAOAEP256 {
		t.Errorf("IDTokenEncryptionAlgorithms = %v, want [RSAOAEP256] (RSA-OAEP is unsupported and must be filtered)", md.IDTokenEncryptionAlgorithms)
	}
	if len(md.IDTokenEncryptionEncValues) != 1 || md.IDTokenEncryptionEncValues[0] != fapi.A256GCM {
		t.Errorf("IDTokenEncryptionEncValues = %v, want [A256GCM] (A128GCM is unsupported and must be filtered)", md.IDTokenEncryptionEncValues)
	}
	if !md.RequireSignedRequestObject {
		t.Errorf("RequireSignedRequestObject = false, want true")
	}
	if len(md.UserInfoAlgorithms) != 1 || md.UserInfoAlgorithms[0] != fapi.ES256 {
		t.Errorf("UserInfoAlgorithms = %v, want [ES256] (RS256 is unsupported and must be filtered)", md.UserInfoAlgorithms)
	}
	if len(md.UserInfoEncryptionAlgorithms) != 1 || md.UserInfoEncryptionAlgorithms[0] != fapi.RSAOAEP256 {
		t.Errorf("UserInfoEncryptionAlgorithms = %v, want [RSAOAEP256] (RSA-OAEP is unsupported and must be filtered)", md.UserInfoEncryptionAlgorithms)
	}
	if len(md.UserInfoEncryptionEncValues) != 1 || md.UserInfoEncryptionEncValues[0] != fapi.A256GCM {
		t.Errorf("UserInfoEncryptionEncValues = %v, want [A256GCM] (A128GCM is unsupported and must be filtered)", md.UserInfoEncryptionEncValues)
	}
}

func TestDiscoverAppendsWellKnownPathAfterIssuerPath(t *testing.T) {
	var gotPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		// The issuer this test uses has a path component ("/tenant1"),
		// so the well-known suffix must be appended after it per OIDC
		// Discovery 1.0 §4.1's own worked example — not inserted between
		// host and path the way RFC 8414 §3.1 builds its own, differently
		// named "oauth-authorization-server" suffix (see Discover's doc
		// comment). Respond using whatever issuer the request implies
		// isn't necessary here, only that the path was constructed
		// correctly; return 404 so Discover fails cleanly either way and
		// this test only asserts on gotPath.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL+"/tenant1", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	_, _ = client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP())

	if gotPath != "/tenant1/.well-known/openid-configuration" {
		t.Fatalf("fetched path = %q, want /tenant1/.well-known/openid-configuration", gotPath)
	}
}

// TestDiscoverOmitsUserinfoEndpointWhenAbsent covers the common case —
// a server with no UserInfo Endpoint, or one that just doesn't
// advertise it — Discover must succeed with a zero
// Endpoints.UserInfo, not fail; it's OPTIONAL per OpenID Connect
// Discovery 1.0 §3.
func TestDiscoverOmitsUserinfoEndpointWhenAbsent(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:                             ts.URL,
			AuthorizationEndpoint:              ts.URL + "/authorize",
			TokenEndpoint:                      ts.URL + "/token",
			PushedAuthorizationRequestEndpoint: ts.URL + "/par",
			JWKSURI:                            ts.URL + "/jwks",
			// UserinfoEndpoint intentionally omitted.
		})
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !md.Endpoints.UserInfo.IsZero() {
		t.Fatalf("Endpoints.UserInfo = %q, want zero", md.Endpoints.UserInfo.String())
	}
}

// TestDiscoverRejectsMalformedUserinfoEndpoint covers the other side:
// present but unparsable must still fail Discover, the same as any
// other advertised endpoint — silently dropping a malformed URL would
// leave a caller who does read Endpoints.UserInfo none the wiser that
// the server's own metadata was broken.
func TestDiscoverRejectsMalformedUserinfoEndpoint(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:                             ts.URL,
			AuthorizationEndpoint:              ts.URL + "/authorize",
			TokenEndpoint:                      ts.URL + "/token",
			PushedAuthorizationRequestEndpoint: ts.URL + "/par",
			JWKSURI:                            ts.URL + "/jwks",
			UserinfoEndpoint:                   "not-a-url://%zz",
		})
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	if _, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP()); err == nil {
		t.Fatalf("Discover(malformed userinfo_endpoint) = nil error, want error")
	}
}

func TestDiscoverRejectsIssuerMismatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:                             "https://attacker.example.com",
			AuthorizationEndpoint:              "https://as.example.com/authorize",
			TokenEndpoint:                      "https://as.example.com/token",
			PushedAuthorizationRequestEndpoint: "https://as.example.com/par",
			JWKSURI:                            "https://as.example.com/jwks",
		})
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	_, err = client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP())
	if !errors.Is(err, metadata.ErrIssuerMismatch) {
		t.Fatalf("Discover(issuer mismatch) error = %v, want metadata.ErrIssuerMismatch", err)
	}
}

// TestDiscoverAcceptsMissingAuthorizationAndPAREndpoints covers a
// CIBA-only authorization server's own discovery document: no browser
// flow at all, so neither authorization_endpoint nor
// pushed_authorization_request_endpoint is advertised. Discover itself
// must succeed with both left zero — it's client.New's own
// "Authorization/PushedAuthorizationRequest must both be set, or both
// left zero, and at least one flow must be configured" pairing rule
// that enforces consistency for a caller intending the browser flow,
// not Discover.
func TestDiscoverAcceptsMissingAuthorizationAndPAREndpoints(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:        ts.URL,
			TokenEndpoint: ts.URL + "/token",
			JWKSURI:       ts.URL + "/jwks",
			// AuthorizationEndpoint/PushedAuthorizationRequestEndpoint
			// intentionally omitted.
		})
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !md.Endpoints.Authorization.IsZero() {
		t.Fatalf("Endpoints.Authorization = %q, want zero", md.Endpoints.Authorization.String())
	}
	if !md.Endpoints.PushedAuthorizationRequest.IsZero() {
		t.Fatalf("Endpoints.PushedAuthorizationRequest = %q, want zero", md.Endpoints.PushedAuthorizationRequest.String())
	}
}

// TestDiscoverPopulatesBackchannelAuthenticationFields covers the CIBA
// discovery triple, mirroring TestDiscoverAcceptsValidDocumentAtRoot's
// own checks for the UserInfo triple.
func TestDiscoverPopulatesBackchannelAuthenticationFields(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:                                 ts.URL,
			AuthorizationEndpoint:                  ts.URL + "/authorize",
			TokenEndpoint:                          ts.URL + "/token",
			PushedAuthorizationRequestEndpoint:     ts.URL + "/par",
			JWKSURI:                                ts.URL + "/jwks",
			BackchannelAuthenticationEndpoint:      ts.URL + "/backchannel-authenticate",
			BackchannelTokenDeliveryModesSupported: []string{"poll"},
			BackchannelAuthenticationRequestSigningAlgValuesSupported: []string{"ES256", "RS256"},
		})
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if md.Endpoints.BackchannelAuthentication.String() != ts.URL+"/backchannel-authenticate" {
		t.Errorf("Endpoints.BackchannelAuthentication = %q", md.Endpoints.BackchannelAuthentication.String())
	}
	if len(md.BackchannelAuthenticationRequestAlgorithms) != 1 || md.BackchannelAuthenticationRequestAlgorithms[0] != fapi.ES256 {
		t.Errorf("BackchannelAuthenticationRequestAlgorithms = %v, want [ES256] (RS256 is unsupported and must be filtered)", md.BackchannelAuthenticationRequestAlgorithms)
	}
}

// TestDiscoverOmitsBackchannelAuthenticationEndpointWhenAbsent covers
// the common case — a server with no CIBA support at all — mirroring
// TestDiscoverOmitsUserinfoEndpointWhenAbsent.
func TestDiscoverOmitsBackchannelAuthenticationEndpointWhenAbsent(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:                             ts.URL,
			AuthorizationEndpoint:              ts.URL + "/authorize",
			TokenEndpoint:                      ts.URL + "/token",
			PushedAuthorizationRequestEndpoint: ts.URL + "/par",
			JWKSURI:                            ts.URL + "/jwks",
			// BackchannelAuthenticationEndpoint intentionally omitted.
		})
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !md.Endpoints.BackchannelAuthentication.IsZero() {
		t.Fatalf("Endpoints.BackchannelAuthentication = %q, want zero", md.Endpoints.BackchannelAuthentication.String())
	}
	if len(md.BackchannelAuthenticationRequestAlgorithms) != 0 {
		t.Fatalf("BackchannelAuthenticationRequestAlgorithms = %v, want empty", md.BackchannelAuthenticationRequestAlgorithms)
	}
}

// TestDiscoverPopulatesMTLSEndpointAliases covers the RFC 8705 §5
// discovery shape a SenderConstrainMTLS caller needs to prefer over
// the plain Endpoints URLs.
func TestDiscoverPopulatesMTLSEndpointAliases(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:                             ts.URL,
			AuthorizationEndpoint:              ts.URL + "/authorize",
			TokenEndpoint:                      ts.URL + "/token",
			PushedAuthorizationRequestEndpoint: ts.URL + "/par",
			JWKSURI:                            ts.URL + "/jwks",
			MTLSEndpointAliases: &discoveryMTLSEndpointAliases{
				TokenEndpoint:                      ts.URL + "/mtls/token",
				PushedAuthorizationRequestEndpoint: ts.URL + "/mtls/par",
				BackchannelAuthenticationEndpoint:  ts.URL + "/mtls/backchannel-authenticate",
			},
		})
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if md.MTLSEndpointAliases == nil {
		t.Fatalf("MTLSEndpointAliases = nil, want non-nil")
	}
	if md.MTLSEndpointAliases.Token.String() != ts.URL+"/mtls/token" {
		t.Errorf("MTLSEndpointAliases.Token = %q", md.MTLSEndpointAliases.Token.String())
	}
	if md.MTLSEndpointAliases.PushedAuthorizationRequest.String() != ts.URL+"/mtls/par" {
		t.Errorf("MTLSEndpointAliases.PushedAuthorizationRequest = %q", md.MTLSEndpointAliases.PushedAuthorizationRequest.String())
	}
	if md.MTLSEndpointAliases.BackchannelAuthentication.String() != ts.URL+"/mtls/backchannel-authenticate" {
		t.Errorf("MTLSEndpointAliases.BackchannelAuthentication = %q", md.MTLSEndpointAliases.BackchannelAuthentication.String())
	}
}

// TestDiscoverOmitsMTLSEndpointAliasesWhenAbsent covers the common
// case — a server that never advertises mtls_endpoint_aliases at all.
func TestDiscoverOmitsMTLSEndpointAliasesWhenAbsent(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:                             ts.URL,
			AuthorizationEndpoint:              ts.URL + "/authorize",
			TokenEndpoint:                      ts.URL + "/token",
			PushedAuthorizationRequestEndpoint: ts.URL + "/par",
			JWKSURI:                            ts.URL + "/jwks",
			// MTLSEndpointAliases intentionally omitted.
		})
	}))
	defer ts.Close()

	issuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), issuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if md.MTLSEndpointAliases != nil {
		t.Fatalf("MTLSEndpointAliases = %+v, want nil", md.MTLSEndpointAliases)
	}
}

func TestDiscoverRejectsNilFetcher(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	if _, err := client.Discover(context.Background(), nil, issuer); err == nil {
		t.Fatalf("Discover(nil fetcher) = nil error, want error")
	}
}
