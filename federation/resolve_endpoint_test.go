package federation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// selfAnchoredResolveEndpoint starts an httptest.TLSServer that is its
// own Trust Anchor (a degenerate, zero-hop chain, mirroring this file's
// sibling tests' own setupThreeLevelFederation/singleEntityServer
// pattern) and additionally serves a Resolve Endpoint at /resolve,
// answering exactly one configured (subject, metadata) pair with a
// freshly signed Resolve Response. Returns the entity ID, its own
// resolve endpoint URL, and a *federation.Resolver already configured
// to trust it.
func selfAnchoredResolveEndpoint(t *testing.T, subject string, metadata map[string]json.RawMessage) (entityID, resolveEndpoint string, resolver *federation.Resolver, server *httptest.Server) {
	t.Helper()
	key := generateKey(t)
	jwks := jwksFor(t, "resolver-key", key)

	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	entityID = ts.URL
	resolveEndpoint = entityID + "/resolve"

	ecToken, err := intfed.Create(intfed.CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "resolver-key",
		Issuer: entityID, Subject: entityID,
		Now: time.Now(), Lifetime: time.Hour, JWKS: jwks,
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(ecToken))

	responseToken, err := intfed.CreateResolveResponse(intfed.CreateResolveResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "resolver-key",
		Issuer: entityID, Subject: subject,
		Now: time.Now(), Lifetime: time.Hour,
		Metadata: metadata, TrustChain: []string{"placeholder-chain-entry"},
	})
	if err != nil {
		t.Fatalf("intfed.CreateResolveResponse: %v", err)
	}
	mux.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sub") != subject {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", federation.ResolveResponseContentType)
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
	return entityID, resolveEndpoint, resolver, ts
}

func TestResolveViaEndpoint(t *testing.T) {
	metadata := map[string]json.RawMessage{
		"openid_provider": json.RawMessage(`{"issuer":"https://op.example.org","token_endpoint":"https://op.example.org/token"}`),
	}
	entityID, resolveEndpoint, resolver, _ := selfAnchoredResolveEndpoint(t, "https://op.example.org", metadata)

	claims, err := resolver.ResolveViaEndpoint(context.Background(), federation.ResolveRequest{
		Endpoint: resolveEndpoint, Subject: "https://op.example.org", TrustAnchor: entityID,
	})
	if err != nil {
		t.Fatalf("ResolveViaEndpoint: %v", err)
	}
	if claims.Subject != "https://op.example.org" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if _, ok := claims.Metadata["openid_provider"]; !ok {
		t.Errorf("Metadata missing openid_provider: %v", claims.Metadata)
	}
}

func TestResolveViaEndpointRejectsUnresolvableIssuer(t *testing.T) {
	metadata := map[string]json.RawMessage{"openid_provider": json.RawMessage(`{}`)}
	_, resolveEndpoint, _, server := selfAnchoredResolveEndpoint(t, "https://op.example.org", metadata)

	// A different Resolver, trusting a different (unrelated) Trust
	// Anchor, can still reach the resolve endpoint over TLS (it trusts
	// the same test server certificate) but has no way to establish
	// trust in the response's own issuer identity.
	otherAnchorKey := generateKey(t)
	otherResolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://unrelated.example.org", JWKS: jwksFor(t, "other", otherAnchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, server), Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := otherResolver.ResolveViaEndpoint(context.Background(), federation.ResolveRequest{
		Endpoint: resolveEndpoint, Subject: "https://op.example.org", TrustAnchor: "https://unrelated.example.org",
	}); err == nil {
		t.Fatalf("ResolveViaEndpoint(untrusted resolver) = nil error, want error")
	}
}

func TestResolveViaEndpointRequiresFields(t *testing.T) {
	metadata := map[string]json.RawMessage{"openid_provider": json.RawMessage(`{}`)}
	entityID, resolveEndpoint, resolver, _ := selfAnchoredResolveEndpoint(t, "https://op.example.org", metadata)

	cases := map[string]federation.ResolveRequest{
		"no endpoint":     {Subject: "https://op.example.org", TrustAnchor: entityID},
		"no subject":      {Endpoint: resolveEndpoint, TrustAnchor: entityID},
		"no trust anchor": {Endpoint: resolveEndpoint, Subject: "https://op.example.org"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := resolver.ResolveViaEndpoint(context.Background(), req); err == nil {
				t.Fatalf("ResolveViaEndpoint(%s) = nil error, want error", name)
			}
		})
	}
}
