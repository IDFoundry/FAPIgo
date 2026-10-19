package dpop

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// verifyProofClaimsAt signs claims as a DPoP proof for POST
// https://as.example/token, filling in htm, htu and jti, and verifies it
// at now with a 60s maximum age and 10s clock skew.
func verifyProofClaimsAt(t *testing.T, now time.Time, claims map[string]any) error {
	t.Helper()
	key := generateKey(t)
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	full := map[string]any{"htm": "POST", "htu": "https://as.example/token", "jti": "j1"}
	for k, v := range claims {
		full[k] = v
	}
	payload, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType, JWK: &jwk}, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: mustURL(t, "https://as.example/token"),
		Now: now, MaxProofAge: time.Minute, MaxClockSkew: 10 * time.Second,
	})
	return err
}

// FAPI 2.0 Security Profile §5.3.2.1 item 13: "shall reject JWTs with an
// iat or nbf timestamp greater than 60 seconds in the future". RFC 9449
// doesn't define nbf or exp for a proof, but RFC 7519 §4.1.4-§4.1.5
// holds every JWT to them.
func TestVerifyHoldsProofToNotBeforeAndExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	iat := now.Unix()
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   error
	}{
		{"nbf within the skew", map[string]any{"iat": iat, "nbf": now.Add(10 * time.Second).Unix()}, nil},
		{"nbf past the skew", map[string]any{"iat": iat, "nbf": now.Add(11 * time.Second).Unix()}, ErrNotYetValid},
		{"nbf an hour ahead", map[string]any{"iat": iat, "nbf": now.Add(time.Hour).Unix()}, ErrNotYetValid},
		{"exp within the skew", map[string]any{"iat": iat, "exp": now.Add(-10 * time.Second).Unix()}, nil},
		{"exp past", map[string]any{"iat": iat, "exp": now.Add(-11 * time.Second).Unix()}, ErrExpired},
		{"iat past the skew", map[string]any{"iat": now.Add(11 * time.Second).Unix()}, ErrIssuedInFuture},
		{"fractional iat", map[string]any{"iat": json.Number("1800000000.9")}, nil},
		{"fractional nbf past the skew", map[string]any{"iat": iat, "nbf": json.Number("1800000011.1")}, ErrNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyProofClaimsAt(t, now, tc.claims)
			if !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyRefusesNonNumericProofTimes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, claims := range []map[string]any{
		{"iat": "1800000000"},
		{"iat": now.Unix(), "nbf": "soon"},
		{"iat": now.Unix(), "exp": true},
	} {
		if err := verifyProofClaimsAt(t, now, claims); !errors.Is(err, ErrMalformedClaims) {
			t.Errorf("Verify(%v) = %v, want ErrMalformedClaims", claims, err)
		}
	}
}
