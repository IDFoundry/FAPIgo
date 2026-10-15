package serverresource_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestNewVerifierResource: with Options.Resource, the verifier accepts
// only tokens issued for that resource server — a token another
// resource server received can't be replayed here — and, under
// AcceptIssuerAudience, tokens issued with no resource indicator too.
// Without it, only tokens issued with no resource indicator.
func TestNewVerifierResource(t *testing.T) {
	const (
		rsA = "https://issuer-a.example.com"
		rsB = "https://issuer-b.example.com"
	)
	now := time.Now()
	type token struct {
		audience  string
		audiences []string
	}
	forA := token{audience: rsA, audiences: []string{rsA}}
	forBoth := token{audience: rsA, audiences: []string{rsA, rsB}}
	forIssuer := token{audience: "https://as.example.com"}
	for name, tc := range map[string]struct {
		opts   serverresource.Options
		accept []token
		refuse []token
	}{
		"issuer":           {accept: []token{forIssuer}, refuse: []token{forA, forBoth}},
		"resource":         {opts: serverresource.Options{Resource: rsB}, accept: []token{forBoth}, refuse: []token{forA, forIssuer}},
		"resource, moving": {opts: serverresource.Options{Resource: rsB, AcceptIssuerAudience: true}, accept: []token{forBoth, forIssuer}, refuse: []token{forA}},
	} {
		for format, accessTokens := range map[string]server.AccessTokenIssuer{
			"jwt":    jwtAccessTokens(t),
			"opaque": server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()},
		} {
			t.Run(name+"/"+format, func(t *testing.T) {
				cfg := serverConfig(t)
				deps := serverDependencies(t, accessTokens, now)
				verifier, err := serverresource.NewVerifier(cfg, deps, tc.opts)
				if err != nil {
					t.Fatalf("NewVerifier: %v", err)
				}
				verify := func(tok token) error {
					cert := clientCertificate(t)
					thumbprint := sha256.Sum256(cert.Raw)
					raw, _, err := accessTokens.IssueAccessToken(context.Background(), server.AccessTokenParams{
						ClientID: "client", Subject: "alice", Scope: []string{"openid"},
						Thumbprint:      base64.RawURLEncoding.EncodeToString(thumbprint[:]),
						SenderConstrain: storage.SenderConstrainMTLS,
						Issuer:          cfg.Issuer.String(), Audience: tok.audience, Audiences: tok.audiences,
						Now: now, Lifetime: cfg.Limits.AccessTokenLifetime, Random: rand.Reader,
					})
					if err != nil {
						t.Fatalf("IssueAccessToken: %v", err)
					}
					_, err = verifier.Verify(context.Background(), resource.VerifyRequest{
						Method: "POST", URL: &url.URL{Scheme: "https", Host: "issuer-b.example.com", Path: "/credential"},
						Authorization: "Bearer " + raw, PeerCertificate: cert,
					})
					return err
				}
				for _, tok := range tc.accept {
					if err := verify(tok); err != nil {
						t.Errorf("Verify(%v) = %v, want accepted", tok, err)
					}
				}
				for _, tok := range tc.refuse {
					if err := verify(tok); err == nil {
						t.Errorf("Verify(%v) accepted, want refused", tok)
					}
				}
			})
		}
	}
}

func TestNewVerifierRefusesInvalidResourceOptions(t *testing.T) {
	cfg := serverConfig(t)
	deps := serverDependencies(t, jwtAccessTokens(t), time.Now())
	for name, opts := range map[string]serverresource.Options{
		"relative":                  {Resource: "/credential"},
		"fragment":                  {Resource: "https://issuer.example.com#x"},
		"issuer audience, resource": {AcceptIssuerAudience: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := serverresource.NewVerifier(cfg, deps, opts); err == nil {
				t.Fatal("NewVerifier accepted invalid Options")
			}
		})
	}
	// The issuer itself as Resource, with AcceptIssuerAudience, is just
	// the issuer.
	if _, err := serverresource.NewVerifier(cfg, deps, serverresource.Options{Resource: cfg.Issuer.String(), AcceptIssuerAudience: true}); err != nil {
		t.Fatalf("NewVerifier(issuer as resource): %v", err)
	}
}
