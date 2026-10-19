package token

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// validateAccessTokenClaimsAt signs claims as an access token, filling in
// the iss, sub, aud, client_id and jti baseAccessTokenPolicy expects,
// and validates it at now with a 2 minute maximum lifetime and 10s skew.
func validateAccessTokenClaimsAt(t *testing.T, now time.Time, claims map[string]any) (ValidatedAccessToken, error) {
	t.Helper()
	key := generateKey(t)
	full := map[string]any{
		"iss": "https://as.example", "sub": "user-1", "aud": "https://rs.example",
		"client_id": "client-123", "jti": "j1",
	}
	for k, v := range claims {
		full[k] = v
	}
	parsed, err := ParseAccessToken(buildRawAccessTokenWithClaims(t, key, full))
	if err != nil {
		return ValidatedAccessToken{}, err
	}
	policy := baseAccessTokenPolicy(now)
	policy.MaxClockSkew = 10 * time.Second
	return parsed.Validate(&key.PublicKey, policy)
}

// FAPI 2.0 Security Profile §5.3.2.1 item 13 and RFC 7519 §4.1.5: an
// access token whose iat or nbf is further in the future than the
// allowed skew is refused. RFC 9068 doesn't define nbf, but a
// third-party issuer may set it.
func TestAccessTokenValidateBoundsFutureIssuedAtAndNotBefore(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	exp, iat := now.Add(time.Minute).Unix(), now.Unix()
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   error
	}{
		{"iat within the skew", map[string]any{"exp": exp, "iat": now.Add(10 * time.Second).Unix()}, nil},
		{"iat past the skew", map[string]any{"exp": exp, "iat": now.Add(11 * time.Second).Unix()}, ErrIssuedInFuture},
		{"nbf within the skew", map[string]any{"exp": exp, "iat": iat, "nbf": now.Add(10 * time.Second).Unix()}, nil},
		{"nbf past the skew", map[string]any{"exp": exp, "iat": iat, "nbf": now.Add(11 * time.Second).Unix()}, ErrNotYetValid},
		{"nbf an hour ahead", map[string]any{"exp": now.Add(90 * time.Second).Unix(), "iat": iat, "nbf": now.Add(time.Hour).Unix()}, ErrNotYetValid},
		{"exp at MaxLifetime plus the skew", map[string]any{"exp": now.Add(130 * time.Second).Unix(), "iat": iat}, nil},
		{"exp past MaxLifetime plus the skew", map[string]any{"exp": now.Add(131 * time.Second).Unix(), "iat": iat}, ErrLifetimeExceeded},
		{"fractional dates", map[string]any{"exp": json.Number("1800000060.5"), "iat": json.Number("1800000000.5"), "nbf": json.Number("1800000000.9")}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateAccessTokenClaimsAt(t, now, tc.claims)
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

// nbf is checked without being taken out of Parameters, where an
// embedder has always been able to read it; one that isn't a NumericDate
// is malformed.
func TestAccessTokenNotBeforeStaysInParameters(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	got, err := validateAccessTokenClaimsAt(t, now, map[string]any{"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix()})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if string(got.Parameters["nbf"]) != "1800000000" {
		t.Errorf("Parameters[nbf] = %s, want 1800000000", got.Parameters["nbf"])
	}
	_, err = validateAccessTokenClaimsAt(t, now, map[string]any{"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nbf": "1800000000"})
	if !errors.Is(err, ErrMalformedClaims) {
		t.Errorf("Validate with a string nbf = %v, want ErrMalformedClaims", err)
	}
}

// An ID token's exp may sit up to MaxLifetime plus MaxClockSkew away, so
// one from a server whose clock runs ahead within the skew still
// validates.
func TestIDTokenValidateLifetimeAllowsClockSkew(t *testing.T) {
	clientNow := time.Unix(1_800_000_000, 0)
	key := generateKey(t)
	policy := baseIDTokenPolicy(clientNow)
	policy.MaxClockSkew = 10 * time.Second
	for _, tc := range []struct {
		name string
		exp  time.Duration
		want error
	}{
		{"at MaxLifetime plus the skew", policy.MaxLifetime + policy.MaxClockSkew, nil},
		{"past it", policy.MaxLifetime + policy.MaxClockSkew + time.Second, ErrLifetimeExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildRawIDTokenWithClaims(t, key, map[string]any{
				"iss": policy.ExpectedIssuer, "sub": "user-1", "aud": policy.ExpectedAudience,
				"exp": clientNow.Add(tc.exp).Unix(), "iat": clientNow.Unix(),
			})
			parsed, err := ParseIDToken(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parsed.Validate(&key.PublicKey, policy); !errors.Is(err, tc.want) {
				t.Errorf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}
