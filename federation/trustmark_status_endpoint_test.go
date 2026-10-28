package federation_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// statusIssuerUnderSuperior is a Trust Mark Issuer below a Trust Anchor
// whose Subordinate Statement about it sets a different status endpoint
// in its metadata, and the number of queries each endpoint received.
type statusIssuerUnderSuperior struct {
	issuerID        string
	resolver        *federation.Resolver
	trustMark       string
	issuerQueries   *atomic.Int32
	superiorQueries *atomic.Int32
}

func setupStatusIssuerUnderSuperior(t *testing.T, statusIssuedAt func(now time.Time) time.Time, maxStatusAge time.Duration) statusIssuerUnderSuperior {
	t.Helper()
	now := time.Now()
	taKey, issuerKey := generateKey(t), generateKey(t)
	taMux, issuerMux := http.NewServeMux(), http.NewServeMux()
	taServer, issuerServer := httptest.NewTLSServer(taMux), httptest.NewTLSServer(issuerMux)
	t.Cleanup(taServer.Close)
	t.Cleanup(issuerServer.Close)
	taID, issuerID := taServer.URL, issuerServer.URL
	create := func(p intfed.CreateParams) string {
		t.Helper()
		p.Algorithm, p.Now, p.Lifetime = fapi.ES256, now, time.Hour
		token, err := intfed.Create(p)
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}
	entityMetadata := func(members map[string]string) map[string]json.RawMessage {
		return map[string]json.RawMessage{"federation_entity": mustJSON(t, members)}
	}
	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(create(intfed.CreateParams{
		Signer: taKey, KeyID: "ta", Issuer: taID, Subject: taID, JWKS: jwksFor(t, "ta", taKey),
		Metadata: entityMetadata(map[string]string{"federation_fetch_endpoint": taID + "/fetch"}),
	})))
	taMux.HandleFunc("/fetch", serveStatement(create(intfed.CreateParams{
		Signer: taKey, KeyID: "ta", Issuer: taID, Subject: issuerID, JWKS: jwksFor(t, "issuer", issuerKey),
		Metadata: entityMetadata(map[string]string{"federation_trust_mark_status_endpoint": taID + "/status"}),
	})))
	issuerMux.HandleFunc("/.well-known/openid-federation", serveStatement(create(intfed.CreateParams{
		Signer: issuerKey, KeyID: "issuer", Issuer: issuerID, Subject: issuerID, JWKS: jwksFor(t, "issuer", issuerKey),
		AuthorityHints: []string{taID},
		Metadata:       entityMetadata(map[string]string{"federation_trust_mark_status_endpoint": issuerID + "/status"}),
	})))

	f := statusIssuerUnderSuperior{issuerID: issuerID, issuerQueries: new(atomic.Int32), superiorQueries: new(atomic.Int32)}
	f.trustMark = signTrustMark(t, issuerKey, "issuer", map[string]any{
		"iss": issuerID, "sub": "https://rp.example.org", "trust_mark_type": testTrustMarkType,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	answer := func(queries *atomic.Int32) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			queries.Add(1)
			response, err := intfed.CreateTrustMarkStatusResponse(intfed.CreateTrustMarkStatusResponseParams{
				Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "issuer",
				Issuer: issuerID, TrustMark: f.trustMark, Status: intfed.TrustMarkStatusActive, Now: statusIssuedAt(now),
			})
			if err != nil {
				t.Errorf("CreateTrustMarkStatusResponse: %v", err)
			}
			w.Header().Set("Content-Type", "application/trust-mark-status-response+jwt")
			w.Write([]byte(response))
		}
	}
	issuerMux.HandleFunc("/status", answer(f.issuerQueries))
	taMux.HandleFunc("/status", answer(f.superiorQueries))

	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: taID, JWKS: jwksFor(t, "ta", taKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second, MaxTrustMarkStatusAge: maxStatusAge},
	}, federation.Dependencies{HTTP: fetcherFor(t, taServer, issuerServer), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	f.resolver = r
	return f
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestCheckTrustMarkStatusUsesTheIssuersOwnEndpoint covers OpenID
// Federation 1.0 §8.4: the status endpoint "MUST be published directly
// in Entity Configuration metadata and not in Subordinate Statements".
// A superior's Subordinate Statement setting another endpoint in the
// issuer's metadata doesn't redirect the query.
func TestCheckTrustMarkStatusUsesTheIssuersOwnEndpoint(t *testing.T) {
	f := setupStatusIssuerUnderSuperior(t, func(now time.Time) time.Time { return now }, 0)
	if _, err := f.resolver.CheckTrustMarkStatus(context.Background(), f.trustMark); err != nil {
		t.Fatalf("CheckTrustMarkStatus: %v", err)
	}
	if f.issuerQueries.Load() != 1 || f.superiorQueries.Load() != 0 {
		t.Errorf("queries: issuer %d, superior's endpoint %d; want only the issuer's own", f.issuerQueries.Load(), f.superiorQueries.Load())
	}
}

// TestCheckTrustMarkStatusRefusesAnOldResponse: a status response has
// no exp, so one issued long ago (a replayed "active" answer, say) is
// refused once older than Limits.MaxTrustMarkStatusAge's default.
func TestCheckTrustMarkStatusRefusesAnOldResponse(t *testing.T) {
	issuedAt := func(now time.Time) time.Time { return now.Add(-federation.DefaultMaxTrustMarkStatusAge - time.Minute) }
	f := setupStatusIssuerUnderSuperior(t, issuedAt, 0)
	if _, err := f.resolver.CheckTrustMarkStatus(context.Background(), f.trustMark); !errors.Is(err, intfed.ErrTrustMarkStatusResponseTooOld) {
		t.Fatalf("CheckTrustMarkStatus(old response) = %v, want ErrTrustMarkStatusResponseTooOld", err)
	}
	// A federation whose issuers cache their answers raises the bound.
	f = setupStatusIssuerUnderSuperior(t, issuedAt, time.Hour)
	if _, err := f.resolver.CheckTrustMarkStatus(context.Background(), f.trustMark); err != nil {
		t.Fatalf("CheckTrustMarkStatus(old response, MaxTrustMarkStatusAge 1h) = %v", err)
	}
}
