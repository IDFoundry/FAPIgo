package keys_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

var (
	_ keys.IssuerBound = (*keys.JWKSIssuerKeySource)(nil)
	_ keys.IssuerBound = (*keys.LocalIssuerKeys)(nil)
)

// TestJWKSIssuerKeySourceBoundIssuer: a JWKSIssuerKeySource reports the
// issuer WithIssuer bound it to, and "" when built without it.
func TestJWKSIssuerKeySourceBoundIssuer(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	unbound, err := keys.NewJWKSIssuerKeySource(newTestFetcherTLS(t, ts), jwksURI, time.Minute)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}
	if got := unbound.BoundIssuer(); got != "" {
		t.Errorf("unbound BoundIssuer() = %q, want \"\"", got)
	}
	bound, err := keys.NewJWKSIssuerKeySource(newTestFetcherTLS(t, ts), jwksURI, time.Minute, keys.WithIssuer(issuer))
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}
	if got := bound.BoundIssuer(); got != issuer.String() {
		t.Errorf("bound BoundIssuer() = %q, want %q", got, issuer.String())
	}
}

// TestLocalIssuerKeysBoundIssuer: a LocalIssuerKeys is always bound to
// the issuer it was built for.
func TestLocalIssuerKeysBoundIssuer(t *testing.T) {
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	l, err := keys.NewLocalIssuerKeys(mustIssuer(t), km)
	if err != nil {
		t.Fatalf("NewLocalIssuerKeys: %v", err)
	}
	if got := l.BoundIssuer(); got != localIssuer {
		t.Errorf("BoundIssuer() = %q, want %q", got, localIssuer)
	}
}
