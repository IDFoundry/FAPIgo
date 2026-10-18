package clientattestation

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// signTestPoPPayload signs claims as a PoP, for shapes popClaimsInput
// can't express.
func signTestPoPPayload(t *testing.T, signer *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	compact, err := jose.Sign(signer, jose.Header{Algorithm: fapi.ES256, Type: PoPTypHeader}, raw)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

// TestAttestation_VerifyWithoutIss: draft-08 removed iss from the
// Client Attestation (draft-12 §4), so an attestation without one
// verifies; one with an iss naming another attester still doesn't.
func TestAttestation_VerifyWithoutIss(t *testing.T) {
	attesterKey, clientKey := generateKey(t), generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	for name, tc := range map[string]struct {
		issuer string
		want   error
	}{
		"without iss (draft-12)":           {"", nil},
		"with the expected iss (draft-07)": {"https://attester.example.com", nil},
		"with another attester's iss":      {"https://wrong-attester.example.com", ErrIssuerMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
				Issuer: tc.issuer, Subject: "https://client.example.com",
				IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), CNFJWK: jwk,
			})
			parsed, err := Parse(attestation)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			verified, err := parsed.Verify(&attesterKey.PublicKey, basePolicy(now))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify error = %v, want %v", err, tc.want)
			}
			if tc.want == nil && verified.ClientID != "https://client.example.com" {
				t.Errorf("ClientID = %q", verified.ClientID)
			}
		})
	}
}

// TestAttestation_VerifyRejectsFutureIat: an attestation issued further
// in the future than the clock-skew allowance is refused, as a future
// nbf is; one within it is accepted.
func TestAttestation_VerifyRejectsFutureIat(t *testing.T) {
	attesterKey, clientKey := generateKey(t), generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	policy := basePolicy(now)
	policy.MaxClockSkew = 10 * time.Second
	for name, tc := range map[string]struct {
		iat  time.Time
		want error
	}{
		"within the skew":  {now.Add(10 * time.Second), nil},
		"beyond the skew":  {now.Add(11 * time.Second), ErrNotYetValid},
		"an hour from now": {now.Add(time.Hour), ErrNotYetValid},
	} {
		t.Run(name, func(t *testing.T) {
			attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
				Subject: "https://client.example.com", IssuedAt: tc.iat.Unix(),
				ExpiresAt: now.Add(5 * time.Minute).Unix(), CNFJWK: jwk,
			})
			parsed, err := Parse(attestation)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if _, err := parsed.Verify(&attesterKey.PublicKey, policy); !errors.Is(err, tc.want) {
				t.Fatalf("Verify error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestPoP_VerifyWithoutIss: draft-08 removed iss from the PoP (draft-12
// §5.1); a PoP without one verifies, and one naming another client
// doesn't. ClientID comes from the policy either way.
func TestPoP_VerifyWithoutIss(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	for name, tc := range map[string]struct {
		issuer string
		want   error
	}{
		"without iss (draft-12)":     {"", nil},
		"with the client as iss":     {"https://client.example.com", nil},
		"with another client as iss": {"https://someone-else.example.com", ErrIssuerMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			pop := createTestPoP(t, clientKey, popClaimsInput{
				Issuer: tc.issuer, Audience: "https://as.example.com", JTI: "jti-1", IssuedAt: now.Unix(),
			})
			parsed, err := ParsePoP(pop)
			if err != nil {
				t.Fatalf("ParsePoP: %v", err)
			}
			verified, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify error = %v, want %v", err, tc.want)
			}
			if tc.want == nil && verified.ClientID != "https://client.example.com" {
				t.Errorf("ClientID = %q", verified.ClientID)
			}
		})
	}
}

// TestPoP_VerifyHonoursExp: a PoP carrying exp is held to it, with the
// clock-skew allowance (RFC 7519 §4.1.4; draft-12 §5.1 rule 4).
func TestPoP_VerifyHonoursExp(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	policy := basePoPPolicy(now)
	policy.MaxClockSkew = 5 * time.Second
	for name, tc := range map[string]struct {
		exp  time.Time
		want error
	}{
		"exp ahead":                {now.Add(time.Minute), nil},
		"exp just within the skew": {now.Add(-5 * time.Second), nil},
		"exp past the skew":        {now.Add(-6 * time.Second), ErrExpired},
	} {
		t.Run(name, func(t *testing.T) {
			pop := createTestPoP(t, clientKey, popClaimsInput{
				Audience: "https://as.example.com", JTI: "jti-1",
				IssuedAt: now.Add(-30 * time.Second).Unix(), ExpiresAt: tc.exp.Unix(),
			})
			parsed, err := ParsePoP(pop)
			if err != nil {
				t.Fatalf("ParsePoP: %v", err)
			}
			if _, err := parsed.Verify(context.Background(), jwk, policy); !errors.Is(err, tc.want) {
				t.Fatalf("Verify error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestPoP_VerifyAudienceArray: aud may be an array holding just this
// server's issuer.
func TestPoP_VerifyAudienceArray(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	for name, tc := range map[string]struct {
		aud  any
		want error
	}{
		"this server, as a string":    {"https://as.example.com", nil},
		"this server, as an array":    {[]string{"https://as.example.com"}, nil},
		"another server, as an array": {[]string{"https://other.example.com"}, ErrAudienceMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			pop := signTestPoPPayload(t, clientKey, map[string]any{"aud": tc.aud, "jti": "jti-1", "iat": now.Unix()})
			parsed, err := ParsePoP(pop)
			if err != nil {
				t.Fatalf("ParsePoP: %v", err)
			}
			if _, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now)); !errors.Is(err, tc.want) {
				t.Fatalf("Verify error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestPoP_VerifyReplayScopedToInstance: the replay record is scoped to
// the Client Instance Key, so two installations sending the same jti
// don't collide, while the same installation repeating one does.
func TestPoP_VerifyReplayScopedToInstance(t *testing.T) {
	now := time.Unix(1300816000, 0)
	policy := basePoPPolicy(now)
	policy.Replay = newMemoryReplayChecker()
	first, second := generateKey(t), generateKey(t)
	use := func(instanceKey *ecdsa.PrivateKey) error {
		t.Helper()
		pop := createTestPoP(t, instanceKey, popClaimsInput{Audience: "https://as.example.com", JTI: "shared-jti", IssuedAt: now.Unix()})
		parsed, err := ParsePoP(pop)
		if err != nil {
			t.Fatalf("ParsePoP: %v", err)
		}
		_, err = parsed.Verify(context.Background(), confirmationJWK(t, &instanceKey.PublicKey), policy)
		return err
	}
	if err := use(first); err != nil {
		t.Fatalf("first instance: %v", err)
	}
	if err := use(second); err != nil {
		t.Fatalf("second instance, same jti: %v", err)
	}
	if err := use(first); err == nil {
		t.Fatal("first instance repeating its jti was accepted")
	}
}
