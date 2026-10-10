package token

import (
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

func hintPolicy() IDTokenHintPolicy {
	return IDTokenHintPolicy{ExpectedIssuer: "https://as.example", Client: "client-123", Algorithm: fapi.ES256}
}

// TestIDTokenVerifyHint: an expired ID token from the expected issuer to
// the client names its subject; another issuer, audience, authorized
// party or key doesn't.
func TestIDTokenVerifyHint(t *testing.T) {
	key := generateKey(t)
	past := time.Now().Add(-time.Hour)
	base := func() map[string]any {
		return map[string]any{"iss": "https://as.example", "sub": "user-1", "aud": "client-123", "exp": past.Add(time.Minute).Unix(), "iat": past.Unix()}
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		key    bool
		want   error
	}{
		{name: "expired, accepted"},
		{name: "other audiences with azp", change: func(c map[string]any) { c["aud"] = []string{"client-123", "rs"}; c["azp"] = "client-123" }},
		{name: "other issuer", change: func(c map[string]any) { c["iss"] = "https://other.example" }, want: ErrIssuerMismatch},
		{name: "other client", change: func(c map[string]any) { c["aud"] = "client-456" }, want: ErrAudienceMismatch},
		{name: "other azp", change: func(c map[string]any) { c["aud"] = []string{"client-123", "client-456"}; c["azp"] = "client-456" }, want: ErrAuthorizedPartyMismatch},
		{name: "other key", key: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := base()
			if tc.change != nil {
				tc.change(claims)
			}
			parsed, err := ParseIDToken(buildRawIDTokenWithClaims(t, key, claims))
			if err != nil {
				t.Fatalf("ParseIDToken: %v", err)
			}
			verifyKey := &key.PublicKey
			if tc.key {
				verifyKey = &generateKey(t).PublicKey
			}
			sub, err := parsed.VerifyHint(verifyKey, hintPolicy())
			switch {
			case tc.key:
				if err == nil {
					t.Fatal("VerifyHint accepted a signature from another key")
				}
			case tc.want != nil:
				if !errors.Is(err, tc.want) {
					t.Fatalf("VerifyHint error = %v, want %v", err, tc.want)
				}
			case err != nil || sub != "user-1":
				t.Fatalf("VerifyHint = %q, %v; want user-1", sub, err)
			}
		})
	}
}

// TestIDTokenVerifyHintRequiresPolicy: an empty issuer or client is a
// caller error, never a match.
func TestIDTokenVerifyHintRequiresPolicy(t *testing.T) {
	key := generateKey(t)
	parsed, err := ParseIDToken(buildRawIDTokenWithClaims(t, key, map[string]any{"iss": "https://as.example", "sub": "user-1", "aud": "client-123", "exp": time.Now().Unix(), "iat": time.Now().Unix()}))
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	for _, policy := range []IDTokenHintPolicy{{Client: "client-123", Algorithm: fapi.ES256}, {ExpectedIssuer: "https://as.example", Algorithm: fapi.ES256}} {
		if _, err := parsed.VerifyHint(&key.PublicKey, policy); err == nil {
			t.Errorf("VerifyHint(%+v) accepted an incomplete policy", policy)
		}
	}
}
