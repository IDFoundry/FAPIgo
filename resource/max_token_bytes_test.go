package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
)

// resolveTokenOfSize issues a JWT access token padded to about size
// bytes and resolves it with a JWTAccessTokens whose MaxTokenBytes is
// maxTokenBytes.
func resolveTokenOfSize(t *testing.T, size, maxTokenBytes int) (int, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pad, _ := json.Marshal(strings.Repeat("x", size*3/4))
	accessToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: testIssuer, Subject: "user-1", Audience: testIssuer,
		ClientID: "client-1", Scope: "read",
		Now: now, Lifetime: time.Minute, Random: rand.Reader,
		Parameters: map[string]json.RawMessage{"pad": pad},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	issuerURL, _ := fapi.ParseIssuerURL(testIssuer)
	resolver, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: key.Public()},
	}}}, issuerURL, testIssuer, fapi.ES256, time.Minute, 8)
	if err != nil {
		t.Fatal(err)
	}
	resolver.MaxTokenBytes = maxTokenBytes
	_, err = resolver.ResolveAccessToken(context.Background(), resource.ResolveAccessTokenRequest{Raw: accessToken, Now: now})
	return len(accessToken), err
}

// TestJWTAccessTokensMaxTokenBytes: a token over 16 KiB is refused by
// default and accepted once MaxTokenBytes allows it, so a resource
// server can accept what an authorization server with a raised
// Limits.MaxAccessTokenClaimsBytes issues.
func TestJWTAccessTokensMaxTokenBytes(t *testing.T) {
	size, err := resolveTokenOfSize(t, 20<<10, 0)
	if size <= resource.DefaultMaxAccessTokenBytes {
		t.Fatalf("token is %d bytes, want over %d", size, resource.DefaultMaxAccessTokenBytes)
	}
	if err == nil {
		t.Fatalf("a %d-byte token resolved with the default MaxTokenBytes", size)
	}
	if _, err := resolveTokenOfSize(t, 20<<10, 32<<10); err != nil {
		t.Fatalf("a %d-byte token with MaxTokenBytes 32 KiB: %v", size, err)
	}
	if _, err := resolveTokenOfSize(t, 1<<10, 0); err != nil {
		t.Fatalf("a small token with the default MaxTokenBytes: %v", err)
	}
}

func TestNewJWTAccessTokensRefusesNegativeMaxTokenBytes(t *testing.T) {
	issuerURL, _ := fapi.ParseIssuerURL(testIssuer)
	j := resource.JWTAccessTokens{
		IssuerKeys: &fakeIssuerKeySource{}, Issuer: issuerURL, Audience: testIssuer,
		Algorithm: fapi.ES256, MaxTokenLifetime: time.Minute, MaxKeyCandidates: 8, MaxTokenBytes: -1,
	}
	if _, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: j, Replay: &fakeReplayStore{}, Revocation: &fakeRevocationChecker{}, Clock: fixedClock{now: time.Now()},
	}); err == nil || !strings.Contains(err.Error(), "max token bytes") {
		t.Fatalf("NewVerifier with MaxTokenBytes -1 = %v, want refusal", err)
	}
}
