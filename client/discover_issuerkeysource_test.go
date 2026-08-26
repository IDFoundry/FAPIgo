package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
)

// TestDiscoveredMetadataIssuerKeySourceResolvesRealKey is the real
// end-to-end proof: IssuerKeySource, built directly from what Discover
// returned, actually resolves the issuer's own published verification
// key — not just a construction-only check.
func TestDiscoveredMetadataIssuerKeySourceResolvesRealKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}

	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			doc := discoveryDoc{
				Issuer:                             ts.URL,
				AuthorizationEndpoint:              ts.URL + "/authorize",
				TokenEndpoint:                      ts.URL + "/token",
				PushedAuthorizationRequestEndpoint: ts.URL + "/par",
				JWKSURI:                            ts.URL + "/jwks",
				IDTokenSigningAlgValuesSupported:   []string{"ES256"},
			}
			json.NewEncoder(w).Encode(doc) //nolint:errcheck
		case "/jwks":
			size := 32
			x := base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, size)))
			y := base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, size)))
			fmt.Fprintf(w, `{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":"as-kid","alg":"ES256"}]}`, x, y)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tsIssuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL(ts.URL): %v", err)
	}
	fetcher := newDiscoveryFetcher(t, ts)
	md, err := client.Discover(context.Background(), fetcher, tsIssuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	src, err := md.IssuerKeySource(fetcher, time.Minute)
	if err != nil {
		t.Fatalf("IssuerKeySource: %v", err)
	}

	set, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: ts.URL, Purpose: keys.IDTokenVerification, Algorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ResolveIssuerKeys: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "as-kid" {
		t.Fatalf("Keys = %+v, want one key with kid \"as-kid\"", set.Keys)
	}
	pub, ok := set.Keys[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&priv.PublicKey) {
		t.Fatalf("resolved public key does not match the issuer's own key")
	}
}

func TestDiscoveredMetadataIssuerKeySourceRejectsNilFetcher(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	if _, err := md.IssuerKeySource(nil, time.Minute); err == nil {
		t.Fatal("IssuerKeySource(nil fetcher) = nil error, want error")
	}
}
