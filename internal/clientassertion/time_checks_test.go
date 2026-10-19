package clientassertion

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// verifyAt signs claims as a client assertion, filling in the iss,
// sub, aud and jti basePolicy expects, and verifies it under policy.
func verifyAt(t *testing.T, claims map[string]any, policy VerifyPolicy) error {
	t.Helper()
	key := generateKey(t)
	full := map[string]any{"iss": "client-123", "sub": "client-123", "aud": "https://as.example/token", "jti": "j1"}
	for k, v := range claims {
		full[k] = v
	}
	payload, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256}, payload)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(compact)
	if err != nil {
		return err
	}
	_, err = a.Verify(context.Background(), &key.PublicKey, policy)
	return err
}

// FAPI 2.0 Security Profile §5.3.2.1 item 13: "shall reject JWTs with an
// iat or nbf timestamp greater than 60 seconds in the future", while
// accepting up to 10 seconds (MaxClockSkew).
func TestVerifyBoundsFutureIssuedAtAndNotBefore(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := basePolicy(now)
	policy.MaxClockSkew = 10 * time.Second
	exp := now.Add(time.Minute).Unix()
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   error
	}{
		{"iat within the skew", map[string]any{"exp": exp, "iat": now.Add(10 * time.Second).Unix()}, nil},
		{"iat past the skew", map[string]any{"exp": exp, "iat": now.Add(11 * time.Second).Unix()}, ErrIssuedInFuture},
		{"iat an hour ahead", map[string]any{"exp": exp, "iat": now.Add(time.Hour).Unix()}, ErrIssuedInFuture},
		{"nbf within the skew", map[string]any{"exp": exp, "nbf": now.Add(10 * time.Second).Unix()}, nil},
		{"nbf past the skew", map[string]any{"exp": exp, "nbf": now.Add(11 * time.Second).Unix()}, ErrNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyAt(t, tc.claims, policy); !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// The exp bound allows the client's clock to run MaxClockSkew ahead: an
// assertion made with the longest lifetime the server accepts still
// verifies when the client is 5s fast, and one a second past
// MaxLifetime+MaxClockSkew doesn't.
func TestVerifyLifetimeAllowsClockSkew(t *testing.T) {
	serverNow := time.Unix(1_800_000_000, 0)
	key := generateKey(t)
	compact := createTestAssertion(t, key, serverNow.Add(5*time.Second), 60*time.Second)
	a, err := Parse(compact)
	if err != nil {
		t.Fatal(err)
	}
	policy := basePolicy(serverNow)
	policy.MaxLifetime, policy.MaxClockSkew = 60*time.Second, 10*time.Second
	if _, err := a.Verify(context.Background(), &key.PublicKey, policy); err != nil {
		t.Errorf("Verify of an assertion from a client 5s fast = %v, want success", err)
	}

	tooLong := map[string]any{"exp": serverNow.Add(71 * time.Second).Unix()}
	if err := verifyAt(t, tooLong, policy); !errors.Is(err, ErrLifetimeExceeded) {
		t.Errorf("Verify with exp past MaxLifetime+MaxClockSkew = %v, want ErrLifetimeExceeded", err)
	}
}

// RFC 7519 §2: a NumericDate may be a non-integer; it's floored.
func TestParseAcceptsFractionalNumericDates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := basePolicy(now)
	policy.MaxClockSkew = 10 * time.Second
	claims := map[string]any{"exp": json.Number("1800000030.75"), "iat": json.Number("1800000000.5")}
	if err := verifyAt(t, claims, policy); err != nil {
		t.Errorf("Verify with fractional exp/iat = %v, want success", err)
	}
	if err := verifyAt(t, map[string]any{"exp": "1800000030"}, policy); !errors.Is(err, ErrMalformedClaims) {
		t.Errorf("Verify with a string exp = %v, want ErrMalformedClaims", err)
	}
}
