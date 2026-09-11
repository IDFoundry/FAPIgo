package federation

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// createTrustMarkToken signs a Trust Mark JWT with the given claims,
// typ (pass trustMarkJWTType for a well-formed one) and kid — there is
// no exported Create for Trust Marks (this package only ever verifies
// one someone else issued; see doc.go), so tests sign one directly via
// jose.Sign rather than through a package API.
func createTrustMarkToken(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: typ, KeyID: kid}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return token
}

func validTrustMarkClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":             "https://issuer.example.org",
		"sub":             "https://rp.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
	}
}

func trustMarkVerifyPolicy(now time.Time) TrustMarkVerifyPolicy {
	return TrustMarkVerifyPolicy{
		ExpectedSubject:       "https://rp.example.org",
		ExpectedTrustMarkType: "https://federation.example.org/marks/certified",
		Algorithm:             fapi.ES256,
		Now:                   now,
	}
}

func TestParseTrustMarkAndVerifyRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, validTrustMarkClaims(now))

	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	if tm.ClaimedIssuer() != "https://issuer.example.org" {
		t.Errorf("ClaimedIssuer() = %q", tm.ClaimedIssuer())
	}
	if tm.ClaimedSubject() != "https://rp.example.org" {
		t.Errorf("ClaimedSubject() = %q", tm.ClaimedSubject())
	}
	if tm.ClaimedTrustMarkType() != "https://federation.example.org/marks/certified" {
		t.Errorf("ClaimedTrustMarkType() = %q", tm.ClaimedTrustMarkType())
	}
	if tm.KeyID() != "issuer-kid" {
		t.Errorf("KeyID() = %q", tm.KeyID())
	}

	claims, err := tm.Verify(&key.PublicKey, trustMarkVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Issuer != "https://issuer.example.org" {
		t.Errorf("claims.Issuer = %q", claims.Issuer)
	}
	if claims.ExpiresAt.IsZero() {
		t.Errorf("claims.ExpiresAt is zero, want the declared exp")
	}
}

func TestVerifyTrustMarkAcceptsNoExpiry(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	claims := validTrustMarkClaims(now)
	delete(claims, "exp")
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, claims)

	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	verified, err := tm.Verify(&key.PublicKey, trustMarkVerifyPolicy(now.Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("Verify(no exp, far in the future): %v, want nil error", err)
	}
	if !verified.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero (no exp claim)", verified.ExpiresAt)
	}
}

func TestParseTrustMarkRejectsWrongType(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", "some-other+jwt", validTrustMarkClaims(now))
	if _, err := ParseTrustMark(token); !errors.Is(err, ErrTrustMarkWrongType) {
		t.Fatalf("ParseTrustMark(wrong typ) = %v, want ErrTrustMarkWrongType", err)
	}
}

func TestParseTrustMarkRejectsMissingType(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", "", validTrustMarkClaims(now))
	if _, err := ParseTrustMark(token); !errors.Is(err, ErrTrustMarkWrongType) {
		t.Fatalf("ParseTrustMark(missing typ) = %v, want ErrTrustMarkWrongType", err)
	}
}

func TestParseTrustMarkRejectsMissingRequiredClaims(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	for _, field := range []string{"iss", "sub", "trust_mark_type", "iat"} {
		t.Run(field, func(t *testing.T) {
			claims := validTrustMarkClaims(now)
			delete(claims, field)
			token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, claims)
			if _, err := ParseTrustMark(token); !errors.Is(err, ErrMalformedClaims) {
				t.Fatalf("ParseTrustMark(missing %s) = %v, want ErrMalformedClaims", field, err)
			}
		})
	}
}

func TestParseTrustMarkRejectsNonJSONPayload(t *testing.T) {
	key := generateKey(t)
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: trustMarkJWTType}, []byte("not json"))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := ParseTrustMark(token); !errors.Is(err, ErrMalformedClaims) {
		t.Fatalf("ParseTrustMark(non-JSON payload) = %v, want ErrMalformedClaims", err)
	}
}

func TestVerifyTrustMarkRejectsSubjectMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, validTrustMarkClaims(now))
	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	policy := trustMarkVerifyPolicy(now)
	policy.ExpectedSubject = "https://someone-else.example.org"
	if _, err := tm.Verify(&key.PublicKey, policy); !errors.Is(err, ErrSubjectMismatch) {
		t.Fatalf("Verify(wrong subject) = %v, want ErrSubjectMismatch", err)
	}
}

func TestVerifyTrustMarkRejectsTypeMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, validTrustMarkClaims(now))
	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	policy := trustMarkVerifyPolicy(now)
	policy.ExpectedTrustMarkType = "https://federation.example.org/marks/different"
	if _, err := tm.Verify(&key.PublicKey, policy); !errors.Is(err, ErrTrustMarkTypeMismatch) {
		t.Fatalf("Verify(wrong trust_mark_type) = %v, want ErrTrustMarkTypeMismatch", err)
	}
}

func TestVerifyTrustMarkRejectsExpired(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, validTrustMarkClaims(now))
	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	if _, err := tm.Verify(&key.PublicKey, trustMarkVerifyPolicy(now.Add(2*time.Hour))); !errors.Is(err, ErrTrustMarkExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrTrustMarkExpired", err)
	}
}

func TestVerifyTrustMarkRejectsNotYetValid(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, validTrustMarkClaims(now))
	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	if _, err := tm.Verify(&key.PublicKey, trustMarkVerifyPolicy(now.Add(-time.Hour))); !errors.Is(err, ErrTrustMarkNotYetValid) {
		t.Fatalf("Verify(not yet valid) = %v, want ErrTrustMarkNotYetValid", err)
	}
}

func TestVerifyTrustMarkRejectsWrongKey(t *testing.T) {
	key := generateKey(t)
	otherKey := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, validTrustMarkClaims(now))
	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	if _, err := tm.Verify(&otherKey.PublicKey, trustMarkVerifyPolicy(now)); err == nil {
		t.Fatalf("Verify(wrong key) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsMissingSubject(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, validTrustMarkClaims(now))
	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	policy := trustMarkVerifyPolicy(now)
	policy.ExpectedSubject = ""
	if _, err := tm.Verify(&key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(empty ExpectedSubject) = nil error, want error")
	}
	policy = trustMarkVerifyPolicy(now)
	policy.ExpectedTrustMarkType = ""
	if _, err := tm.Verify(&key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(empty ExpectedTrustMarkType) = nil error, want error")
	}
	policy = trustMarkVerifyPolicy(now)
	policy.Now = time.Time{}
	if _, err := tm.Verify(&key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(zero Now) = nil error, want error")
	}
}

func TestParseTrustMarkRejectsMalformedCompact(t *testing.T) {
	if _, err := ParseTrustMark("not-a-jws-at-all"); err == nil {
		t.Fatalf("ParseTrustMark(garbage) = nil error, want error")
	}
}

func TestParseTrustMarkRejectsMalformedExp(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	claims := validTrustMarkClaims(now)
	claims["exp"] = "not-a-number"
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, claims)
	if _, err := ParseTrustMark(token); !errors.Is(err, ErrMalformedClaims) {
		t.Fatalf("ParseTrustMark(malformed exp) = %v, want ErrMalformedClaims", err)
	}
}

func TestTrustMarkAlgorithm(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkToken(t, key, "issuer-kid", trustMarkJWTType, validTrustMarkClaims(now))
	tm, err := ParseTrustMark(token)
	if err != nil {
		t.Fatalf("ParseTrustMark: %v", err)
	}
	if tm.Algorithm() != fapi.ES256 {
		t.Errorf("Algorithm() = %v, want ES256", tm.Algorithm())
	}
}
