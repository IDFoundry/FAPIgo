package requestobject

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// verifyClaimsAt signs claims as a request object, filling in the iss,
// client_id, aud and response_type basePolicy expects, and verifies it
// under policy.
func verifyClaimsAt(t *testing.T, claims map[string]any, policy VerifyPolicy) error {
	t.Helper()
	key := generateKey(t)
	full := map[string]any{"iss": "client-123", "client_id": "client-123", "aud": "https://as.example", "response_type": "code"}
	for k, v := range claims {
		full[k] = v
	}
	payload, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "oauth-authz-req+jwt"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Parse(compact)
	if err != nil {
		return err
	}
	_, err = o.Verify(context.Background(), &key.PublicKey, policy)
	return err
}

// FAPI 2.0 Security Profile §5.3.2.1 item 13: "shall reject JWTs with an
// iat or nbf timestamp greater than 60 seconds in the future", while
// accepting up to 10 seconds (MaxClockSkew).
func TestVerifyBoundsFutureIssuedAt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := basePolicy(now)
	policy.MaxClockSkew = 10 * time.Second
	exp, nbf := now.Add(time.Minute).Unix(), now.Unix()
	for _, tc := range []struct {
		name string
		iat  time.Time
		want error
	}{
		{"iat now", now, nil},
		{"iat within the skew", now.Add(10 * time.Second), nil},
		{"iat past the skew", now.Add(11 * time.Second), ErrIssuedInFuture},
		{"iat an hour ahead", now.Add(time.Hour), ErrIssuedInFuture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyClaimsAt(t, map[string]any{"exp": exp, "nbf": nbf, "iat": tc.iat.Unix()}, policy)
			if !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// The exp bound allows the client's clock to run MaxClockSkew ahead: a
// request object made with the longest lifetime the server accepts
// still verifies when the client is 5s fast.
func TestVerifyLifetimeAllowsClockSkew(t *testing.T) {
	serverNow := time.Unix(1_800_000_000, 0)
	key := generateKey(t)
	compact := createTestObject(t, key, serverNow.Add(5*time.Second), 60*time.Second)
	o, err := Parse(compact)
	if err != nil {
		t.Fatal(err)
	}
	policy := basePolicy(serverNow)
	policy.MaxLifetime, policy.MaxClockSkew = 60*time.Second, 10*time.Second
	if _, err := o.Verify(context.Background(), &key.PublicKey, policy); err != nil {
		t.Errorf("Verify of an object from a client 5s fast = %v, want success", err)
	}

	tooLong := map[string]any{"exp": serverNow.Add(71 * time.Second).Unix()}
	if err := verifyClaimsAt(t, tooLong, policy); !errors.Is(err, ErrLifetimeExceeded) {
		t.Errorf("Verify with exp past MaxLifetime+MaxClockSkew = %v, want ErrLifetimeExceeded", err)
	}
}

// RFC 7519 §2: a NumericDate may be a non-integer; it's floored.
func TestParseAcceptsFractionalNumericDates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	policy := basePolicy(now)
	policy.MaxClockSkew = 10 * time.Second
	claims := map[string]any{"exp": json.Number("1800000030.75"), "nbf": json.Number("1799999999.5"), "iat": json.Number("1800000000.25")}
	if err := verifyClaimsAt(t, claims, policy); err != nil {
		t.Errorf("Verify with fractional exp/nbf/iat = %v, want success", err)
	}
	if err := verifyClaimsAt(t, map[string]any{"exp": "1800000030"}, policy); !errors.Is(err, ErrMalformedClaims) {
		t.Errorf("Verify with a string exp = %v, want ErrMalformedClaims", err)
	}
}
