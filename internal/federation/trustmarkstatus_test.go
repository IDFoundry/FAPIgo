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

// createTrustMarkStatusResponseToken mirrors createTrustMarkToken —
// used only for cases CreateTrustMarkStatusResponse itself can't
// produce (a wrong typ header, a malformed claim).
func createTrustMarkStatusResponseToken(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
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

func validTrustMarkStatusResponseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":        "https://issuer.example.org",
		"iat":        now.Unix(),
		"trust_mark": "a.b.c",
		"status":     "active",
	}
}

func trustMarkStatusResponseVerifyPolicy(now time.Time) TrustMarkStatusResponseVerifyPolicy {
	return TrustMarkStatusResponseVerifyPolicy{
		ExpectedIssuer: "https://issuer.example.org", ExpectedTrustMark: "a.b.c",
		Algorithm: fapi.ES256, Now: now,
	}
}

func TestParseTrustMarkStatusResponseAndVerifyRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", trustMarkStatusResponseJWTType, validTrustMarkStatusResponseClaims(now))

	r, err := ParseTrustMarkStatusResponse(token)
	if err != nil {
		t.Fatalf("ParseTrustMarkStatusResponse: %v", err)
	}
	if r.ClaimedIssuer() != "https://issuer.example.org" {
		t.Errorf("ClaimedIssuer() = %q", r.ClaimedIssuer())
	}
	if r.ClaimedTrustMark() != "a.b.c" {
		t.Errorf("ClaimedTrustMark() = %q", r.ClaimedTrustMark())
	}
	if r.KeyID() != "issuer-kid" {
		t.Errorf("KeyID() = %q", r.KeyID())
	}

	claims, err := r.Verify(&key.PublicKey, trustMarkStatusResponseVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Status != TrustMarkStatusActive {
		t.Errorf("claims.Status = %q, want active", claims.Status)
	}
}

func TestParseTrustMarkStatusResponseRejectsWrongType(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", "some-other+jwt", validTrustMarkStatusResponseClaims(now))
	if _, err := ParseTrustMarkStatusResponse(token); !errors.Is(err, ErrTrustMarkStatusResponseWrongType) {
		t.Fatalf("ParseTrustMarkStatusResponse(wrong typ) = %v, want ErrTrustMarkStatusResponseWrongType", err)
	}
}

func TestParseTrustMarkStatusResponseRejectsMissingRequiredClaims(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	for _, field := range []string{"iss", "trust_mark", "status", "iat"} {
		t.Run(field, func(t *testing.T) {
			claims := validTrustMarkStatusResponseClaims(now)
			delete(claims, field)
			token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", trustMarkStatusResponseJWTType, claims)
			if _, err := ParseTrustMarkStatusResponse(token); !errors.Is(err, ErrMalformedClaims) {
				t.Fatalf("ParseTrustMarkStatusResponse(missing %s) = %v, want ErrMalformedClaims", field, err)
			}
		})
	}
}

func TestParseTrustMarkStatusResponseRejectsMalformedCompact(t *testing.T) {
	if _, err := ParseTrustMarkStatusResponse("not-a-jws-at-all"); err == nil {
		t.Fatalf("ParseTrustMarkStatusResponse(garbage) = nil error, want error")
	}
}

func TestParseTrustMarkStatusResponseRejectsNonJSONPayload(t *testing.T) {
	key := generateKey(t)
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: trustMarkStatusResponseJWTType}, []byte("not json"))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := ParseTrustMarkStatusResponse(token); !errors.Is(err, ErrMalformedClaims) {
		t.Fatalf("ParseTrustMarkStatusResponse(non-JSON payload) = %v, want ErrMalformedClaims", err)
	}
}

func TestTrustMarkStatusResponseAlgorithm(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", trustMarkStatusResponseJWTType, validTrustMarkStatusResponseClaims(now))
	r, err := ParseTrustMarkStatusResponse(token)
	if err != nil {
		t.Fatalf("ParseTrustMarkStatusResponse: %v", err)
	}
	if r.Algorithm() != fapi.ES256 {
		t.Errorf("Algorithm() = %v, want ES256", r.Algorithm())
	}
}

func TestVerifyTrustMarkStatusResponseRejectsIssuerMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", trustMarkStatusResponseJWTType, validTrustMarkStatusResponseClaims(now))
	r, err := ParseTrustMarkStatusResponse(token)
	if err != nil {
		t.Fatalf("ParseTrustMarkStatusResponse: %v", err)
	}
	policy := trustMarkStatusResponseVerifyPolicy(now)
	policy.ExpectedIssuer = "https://someone-else.example.org"
	if _, err := r.Verify(&key.PublicKey, policy); !errors.Is(err, ErrTrustMarkStatusResponseIssuerMismatch) {
		t.Fatalf("Verify(wrong issuer) = %v, want ErrTrustMarkStatusResponseIssuerMismatch", err)
	}
}

func TestVerifyTrustMarkStatusResponseRejectsTrustMarkMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", trustMarkStatusResponseJWTType, validTrustMarkStatusResponseClaims(now))
	r, err := ParseTrustMarkStatusResponse(token)
	if err != nil {
		t.Fatalf("ParseTrustMarkStatusResponse: %v", err)
	}
	policy := trustMarkStatusResponseVerifyPolicy(now)
	policy.ExpectedTrustMark = "x.y.z"
	if _, err := r.Verify(&key.PublicKey, policy); !errors.Is(err, ErrTrustMarkStatusResponseTrustMarkMismatch) {
		t.Fatalf("Verify(wrong trust mark) = %v, want ErrTrustMarkStatusResponseTrustMarkMismatch", err)
	}
}

func TestVerifyTrustMarkStatusResponseRejectsNotYetValid(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", trustMarkStatusResponseJWTType, validTrustMarkStatusResponseClaims(now))
	r, err := ParseTrustMarkStatusResponse(token)
	if err != nil {
		t.Fatalf("ParseTrustMarkStatusResponse: %v", err)
	}
	if _, err := r.Verify(&key.PublicKey, trustMarkStatusResponseVerifyPolicy(now.Add(-time.Hour))); !errors.Is(err, ErrTrustMarkStatusResponseNotYetValid) {
		t.Fatalf("Verify(not yet valid) = %v, want ErrTrustMarkStatusResponseNotYetValid", err)
	}
}

func TestVerifyTrustMarkStatusResponseRejectsWrongKey(t *testing.T) {
	key := generateKey(t)
	otherKey := generateKey(t)
	now := time.Now()
	token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", trustMarkStatusResponseJWTType, validTrustMarkStatusResponseClaims(now))
	r, err := ParseTrustMarkStatusResponse(token)
	if err != nil {
		t.Fatalf("ParseTrustMarkStatusResponse: %v", err)
	}
	if _, err := r.Verify(&otherKey.PublicKey, trustMarkStatusResponseVerifyPolicy(now)); err == nil {
		t.Fatal("Verify(wrong key) = nil error, want error")
	}
}

func TestVerifyTrustMarkStatusResponseRejectsMissingPolicyFields(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTrustMarkStatusResponseToken(t, key, "issuer-kid", trustMarkStatusResponseJWTType, validTrustMarkStatusResponseClaims(now))
	r, err := ParseTrustMarkStatusResponse(token)
	if err != nil {
		t.Fatalf("ParseTrustMarkStatusResponse: %v", err)
	}
	policy := trustMarkStatusResponseVerifyPolicy(now)
	policy.ExpectedIssuer = ""
	if _, err := r.Verify(&key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(empty ExpectedIssuer) = nil error, want error")
	}
	policy = trustMarkStatusResponseVerifyPolicy(now)
	policy.ExpectedTrustMark = ""
	if _, err := r.Verify(&key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(empty ExpectedTrustMark) = nil error, want error")
	}
	policy = trustMarkStatusResponseVerifyPolicy(now)
	policy.Now = time.Time{}
	if _, err := r.Verify(&key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(zero Now) = nil error, want error")
	}
}

func TestCreateTrustMarkStatusResponseRoundTripsThroughParseAndVerify(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	token, err := CreateTrustMarkStatusResponse(CreateTrustMarkStatusResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "issuer-kid",
		Issuer: "https://issuer.example.org", TrustMark: "a.b.c",
		Status: TrustMarkStatusRevoked, Now: now,
	})
	if err != nil {
		t.Fatalf("CreateTrustMarkStatusResponse: %v", err)
	}

	r, err := ParseTrustMarkStatusResponse(token)
	if err != nil {
		t.Fatalf("ParseTrustMarkStatusResponse: %v", err)
	}
	if r.KeyID() != "issuer-kid" {
		t.Errorf("KeyID() = %q, want \"issuer-kid\"", r.KeyID())
	}
	claims, err := r.Verify(&key.PublicKey, TrustMarkStatusResponseVerifyPolicy{
		ExpectedIssuer: "https://issuer.example.org", ExpectedTrustMark: "a.b.c",
		Algorithm: fapi.ES256, Now: now,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Status != TrustMarkStatusRevoked {
		t.Errorf("claims.Status = %q, want revoked", claims.Status)
	}
}

func TestCreateTrustMarkStatusResponseRejectsInvalidParams(t *testing.T) {
	valid := func() CreateTrustMarkStatusResponseParams {
		return CreateTrustMarkStatusResponseParams{
			Signer: generateKey(t), Algorithm: fapi.ES256, KeyID: "k",
			Issuer: "https://issuer.example.org", TrustMark: "a.b.c",
			Status: TrustMarkStatusActive, Now: time.Now(),
		}
	}
	cases := map[string]func(*CreateTrustMarkStatusResponseParams){
		"nil signer":        func(p *CreateTrustMarkStatusResponseParams) { p.Signer = nil },
		"invalid algorithm": func(p *CreateTrustMarkStatusResponseParams) { p.Algorithm = fapi.SignatureAlgorithm(255) },
		"empty key id":      func(p *CreateTrustMarkStatusResponseParams) { p.KeyID = "" },
		"empty issuer":      func(p *CreateTrustMarkStatusResponseParams) { p.Issuer = "" },
		"empty trust mark":  func(p *CreateTrustMarkStatusResponseParams) { p.TrustMark = "" },
		"empty status":      func(p *CreateTrustMarkStatusResponseParams) { p.Status = "" },
		"zero now":          func(p *CreateTrustMarkStatusResponseParams) { p.Now = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := valid()
			mutate(&p)
			if _, err := CreateTrustMarkStatusResponse(p); err == nil {
				t.Fatalf("CreateTrustMarkStatusResponse(%s) = nil error, want error", name)
			}
		})
	}
}
