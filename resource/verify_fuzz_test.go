package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// FuzzVerifyResourceRequest exercises Verifier.Verify against an
// arbitrary Authorization header value and DPoP proof — the resource
// server's actual request-verification entry point, not just one of
// the JWT parsers it eventually calls. Method/URL/PeerCertificate are
// fixed to a realistic request so the fuzzer's mutations land on the
// two fields that are genuinely attacker-controlled per request: the
// raw Authorization header (this package's own strings.Cut(..., " ")
// scheme/token split, ahead of internal/token.ParseAccessToken) and
// the DPoP proof (internal/dpop.Verify, already fuzzed standalone, but
// not previously exercised through this package's own scheme-routing
// and sender-constraint cross-check logic). Backed by a real
// JWTAccessTokens resolver and a real memstore.ReplayStore, not mocks,
// so this reaches actual signature verification, not just claim
// parsing. Only checks for panics/hangs.
func FuzzVerifyResourceRequest(f *testing.F) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate issuer key: %v", err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate dpop key: %v", err)
	}
	dpopJWK, err := jose.NewJWK(dpopKey.Public(), fapi.ES256)
	if err != nil {
		f.Fatalf("dpop jwk: %v", err)
	}
	thumbprint, err := dpopJWK.Thumbprint()
	if err != nil {
		f.Fatalf("dpop thumbprint: %v", err)
	}

	const issuer = "https://as.example"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	target, err := url.Parse("https://rs.example/accounts")
	if err != nil {
		f.Fatalf("parse target url: %v", err)
	}
	issuerURL, err := fapi.ParseIssuerURL(issuer)
	if err != nil {
		f.Fatalf("ParseIssuerURL: %v", err)
	}

	jwtAccessTokens, err := resource.NewJWTAccessTokens(
		&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
			{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
		}}},
		issuerURL, issuer, fapi.ES256, 5*time.Minute, 8,
	)
	if err != nil {
		f.Fatalf("NewJWTAccessTokens: %v", err)
	}
	v, err := resource.NewVerifier(
		resource.Config{Limits: resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second}},
		resource.Dependencies{
			AccessTokens: jwtAccessTokens,
			Replay:       memstore.NewReplayStore(),
			Revocation:   resource.NoRevocation{},
			Clock:        fixedClock{now: now},
		},
	)
	if err != nil {
		f.Fatalf("NewVerifier: %v", err)
	}

	dpopBoundToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: issuer, Subject: "user-1", Audience: issuer, ClientID: "client-1",
		Confirmation: &token.Confirmation{JKT: thumbprint.String()},
		Now:          now, Lifetime: 5 * time.Minute, Random: rand.Reader,
	})
	if err != nil {
		f.Fatalf("IssueAccessToken(dpop-bound): %v", err)
	}
	dpopProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "GET", URL: target,
		AccessToken: dpopBoundToken, Now: now, Random: rand.Reader,
	})
	if err != nil {
		f.Fatalf("CreateProof: %v", err)
	}

	bearerToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: issuer, Subject: "user-1", Audience: issuer, ClientID: "client-1",
		Now: now, Lifetime: 5 * time.Minute, Random: rand.Reader,
	})
	if err != nil {
		f.Fatalf("IssueAccessToken(bearer): %v", err)
	}

	f.Add("DPoP "+dpopBoundToken, dpopProof)
	f.Add("Bearer "+bearerToken, "")
	f.Add("", "")
	f.Add("Bearer ", "")
	f.Add("DPoP ", "")
	f.Add("Basic dXNlcjpwYXNz", "")

	f.Fuzz(func(t *testing.T, authorization, proof string) {
		var proofs []string
		if proof != "" {
			proofs = []string{proof}
		}
		_, _ = v.Verify(context.Background(), resource.VerifyRequest{
			Method: "GET", URL: target, Authorization: authorization, DPoPProofs: proofs,
		})
	})
}
