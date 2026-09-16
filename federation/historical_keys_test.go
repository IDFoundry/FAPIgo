package federation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// selfAnchoredHistoricalKeysEndpoint starts an httptest.TLSServer that
// is its own Trust Anchor (a degenerate, zero-hop chain, mirroring this
// file's sibling tests' own pattern) and additionally serves a
// Federation Historical Keys endpoint at /historical-keys, signed with
// its own current key and reporting historicalKey (already retired) as
// its sole entry. Returns the entity ID, the historical keys endpoint
// URL, a *federation.Resolver already configured to trust it, and the
// underlying *httptest.Server.
func selfAnchoredHistoricalKeysEndpoint(t *testing.T) (entityID, endpoint string, resolver *federation.Resolver, server *httptest.Server) {
	t.Helper()
	currentKey := generateKey(t)
	historicalKey := generateKey(t)
	jwks := jwksFor(t, "current-key", currentKey)

	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	entityID = ts.URL
	endpoint = entityID + "/historical-keys"

	ecToken, err := intfed.Create(intfed.CreateParams{
		Signer: currentKey, Algorithm: fapi.ES256, KeyID: "current-key",
		Issuer: entityID, Subject: entityID,
		Now: time.Now(), Lifetime: time.Hour, JWKS: jwks,
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(ecToken))

	now := time.Now()
	responseToken, err := intfed.CreateHistoricalKeysResponse(intfed.CreateHistoricalKeysResponseParams{
		Signer: currentKey, Algorithm: fapi.ES256, KeyID: "current-key",
		Issuer: entityID, Now: now,
		Keys: []intfed.HistoricalKeyParams{
			{
				KeyID: "old-key", Algorithm: fapi.ES256, PublicKey: &historicalKey.PublicKey,
				ExpiresAt: now.Add(-time.Hour),
				Revoked:   &intfed.KeyRevocation{RevokedAt: now.Add(-2 * time.Hour), Reason: intfed.KeyRevocationReasonSuperseded},
			},
		},
	})
	if err != nil {
		t.Fatalf("intfed.CreateHistoricalKeysResponse: %v", err)
	}
	mux.HandleFunc("/historical-keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", federation.HistoricalKeysContentType)
		w.Write([]byte(responseToken))
	})

	fetcher := fetcherFor(t, ts)
	resolver, err = federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: entityID, JWKS: jwks}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return entityID, endpoint, resolver, ts
}

func TestFetchHistoricalKeys(t *testing.T) {
	entityID, endpoint, resolver, _ := selfAnchoredHistoricalKeysEndpoint(t)

	claims, err := resolver.FetchHistoricalKeys(context.Background(), endpoint, entityID)
	if err != nil {
		t.Fatalf("FetchHistoricalKeys: %v", err)
	}
	if claims.Issuer != entityID {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, entityID)
	}
	if len(claims.Keys) != 1 || claims.Keys[0].KeyID != "old-key" {
		t.Fatalf("Keys = %+v, want one entry keyed old-key", claims.Keys)
	}
	if claims.Keys[0].Revoked == nil || claims.Keys[0].Revoked.Reason != intfed.KeyRevocationReasonSuperseded {
		t.Errorf("Keys[0].Revoked = %+v, want superseded", claims.Keys[0].Revoked)
	}
}

func TestFetchHistoricalKeysRejectsUnresolvableIssuer(t *testing.T) {
	_, endpoint, _, server := selfAnchoredHistoricalKeysEndpoint(t)

	otherAnchorKey := generateKey(t)
	otherResolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://unrelated.example.org", JWKS: jwksFor(t, "other", otherAnchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, server), Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := otherResolver.FetchHistoricalKeys(context.Background(), endpoint, "https://unrelated.example.org"); err == nil {
		t.Fatalf("FetchHistoricalKeys(untrusted issuer) = nil error, want error")
	}
}

func TestFetchHistoricalKeysRejectsNonHTTPSEndpoint(t *testing.T) {
	entityID, _, resolver, _ := selfAnchoredHistoricalKeysEndpoint(t)
	if _, err := resolver.FetchHistoricalKeys(context.Background(), "http://not-https.example.org/historical-keys", entityID); err == nil {
		t.Fatalf("FetchHistoricalKeys(non-https endpoint) = nil error, want error")
	}
}

func TestFetchHistoricalKeysRejectsFetchFailure(t *testing.T) {
	entityID, endpoint, resolver, _ := selfAnchoredHistoricalKeysEndpoint(t)
	if _, err := resolver.FetchHistoricalKeys(context.Background(), endpoint+"-missing", entityID); err == nil {
		t.Fatalf("FetchHistoricalKeys(fetch failure) = nil error, want error")
	}
}

func TestFetchHistoricalKeysRejectsMalformedResponseBody(t *testing.T) {
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	entityID := ts.URL
	key := generateKey(t)
	jwks := jwksFor(t, "k", key)
	ecToken, err := intfed.Create(intfed.CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "k",
		Issuer: entityID, Subject: entityID,
		Now: time.Now(), Lifetime: time.Hour, JWKS: jwks,
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(ecToken))
	mux.HandleFunc("/historical-keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", federation.HistoricalKeysContentType)
		w.Write([]byte("not-a-valid-jwt"))
	})

	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: entityID, JWKS: jwks}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := resolver.FetchHistoricalKeys(context.Background(), entityID+"/historical-keys", entityID); err == nil {
		t.Fatalf("FetchHistoricalKeys(malformed response body) = nil error, want error")
	}
}

func TestFetchHistoricalKeysRejectsSignatureMismatch(t *testing.T) {
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	entityID := ts.URL
	key := generateKey(t)
	otherKey := generateKey(t)
	historicalKey := generateKey(t)
	jwks := jwksFor(t, "k", key)
	ecToken, err := intfed.Create(intfed.CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "k",
		Issuer: entityID, Subject: entityID,
		Now: time.Now(), Lifetime: time.Hour, JWKS: jwks,
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(ecToken))

	now := time.Now()
	responseToken, err := intfed.CreateHistoricalKeysResponse(intfed.CreateHistoricalKeysResponseParams{
		Signer: otherKey, Algorithm: fapi.ES256, KeyID: "k",
		Issuer: entityID, Now: now,
		Keys: []intfed.HistoricalKeyParams{
			{KeyID: "old-key", Algorithm: fapi.ES256, PublicKey: &historicalKey.PublicKey, ExpiresAt: now.Add(-time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("intfed.CreateHistoricalKeysResponse: %v", err)
	}
	mux.HandleFunc("/historical-keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", federation.HistoricalKeysContentType)
		w.Write([]byte(responseToken))
	})

	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: entityID, JWKS: jwks}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := resolver.FetchHistoricalKeys(context.Background(), entityID+"/historical-keys", entityID); err == nil {
		t.Fatalf("FetchHistoricalKeys(signature mismatch) = nil error, want error")
	}
}

func TestFetchHistoricalKeysRequiresFields(t *testing.T) {
	entityID, endpoint, resolver, _ := selfAnchoredHistoricalKeysEndpoint(t)
	if _, err := resolver.FetchHistoricalKeys(context.Background(), "", entityID); err == nil {
		t.Fatalf("FetchHistoricalKeys(no endpoint) = nil error, want error")
	}
	if _, err := resolver.FetchHistoricalKeys(context.Background(), endpoint, ""); err == nil {
		t.Fatalf("FetchHistoricalKeys(no entity ID) = nil error, want error")
	}
}
