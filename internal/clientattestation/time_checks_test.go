package clientattestation

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// An attestation's exp may sit up to MaxLifetime plus MaxClockSkew away:
// the attester's clock may run that far ahead, and an attestation it
// issued with the longest lifetime the server accepts still fits.
func TestAttestationVerifyLifetimeAllowsClockSkew(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1_800_000_000, 0)
	policy := basePolicy(now)
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
			attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
				Issuer: "https://attester.example.com", Subject: "https://client.example.com",
				IssuedAt: now.Unix(), ExpiresAt: now.Add(tc.exp).Unix(),
				CNFJWK: confirmationJWK(t, &clientKey.PublicKey),
			})
			parsed, err := Parse(attestation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parsed.Verify(&attesterKey.PublicKey, policy); !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// RFC 7519 §2: a NumericDate may be a non-integer; it's floored.
func TestAttestationAcceptsFractionalNumericDates(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1_800_000_000, 0)
	var jwk json.RawMessage = confirmationJWK(t, &clientKey.PublicKey)
	payload, err := json.Marshal(map[string]any{
		"iss": "https://attester.example.com", "sub": "https://client.example.com",
		"iat": json.Number("1800000000.5"), "exp": json.Number("1800000300.5"),
		"cnf": map[string]any{"jwk": jwk},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(attesterKey, jose.Header{Algorithm: fapi.ES256, Type: TypHeader}, payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := parsed.Verify(&attesterKey.PublicKey, basePolicy(now))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verified.ExpiresAt.Equal(time.Unix(1_800_000_300, 0)) {
		t.Errorf("ExpiresAt = %v, want the floored exp", verified.ExpiresAt)
	}
}
