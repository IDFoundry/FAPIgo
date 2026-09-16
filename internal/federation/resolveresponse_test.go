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

func createResolveResponseToken(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
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

func validResolveResponseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://resolver.example.org",
		"sub": "https://op.example.org",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"metadata": map[string]any{
			"openid_provider": map[string]any{"issuer": "https://op.example.org"},
		},
		"trust_chain": []string{"a.b.c", "d.e.f"},
	}
}

func resolveResponseVerifyPolicy(now time.Time) ResolveResponseVerifyPolicy {
	return ResolveResponseVerifyPolicy{
		ExpectedIssuer: "https://resolver.example.org", ExpectedSubject: "https://op.example.org",
		Algorithm: fapi.ES256, Now: now,
	}
}

func TestParseResolveResponseAndVerifyRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	claims := validResolveResponseClaims(now)
	claims["trust_marks"] = []map[string]string{
		{"trust_mark_type": "https://marks.example.org/certified", "trust_mark": "x.y.z"},
	}
	token := createResolveResponseToken(t, key, "resolver-kid", resolveResponseJWTType, claims)

	r, err := ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	if r.ClaimedIssuer() != "https://resolver.example.org" {
		t.Errorf("ClaimedIssuer() = %q", r.ClaimedIssuer())
	}
	if r.KeyID() != "resolver-kid" {
		t.Errorf("KeyID() = %q", r.KeyID())
	}

	got, err := r.Verify(&key.PublicKey, resolveResponseVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "https://op.example.org" {
		t.Errorf("Subject = %q", got.Subject)
	}
	if _, ok := got.Metadata["openid_provider"]; !ok {
		t.Errorf("Metadata missing openid_provider: %v", got.Metadata)
	}
	if len(got.TrustChain) != 2 || got.TrustChain[0] != "a.b.c" || got.TrustChain[1] != "d.e.f" {
		t.Errorf("TrustChain = %v, want [a.b.c d.e.f]", got.TrustChain)
	}
	if len(got.TrustMarks) != 1 || got.TrustMarks[0].TrustMarkType != "https://marks.example.org/certified" {
		t.Errorf("TrustMarks = %+v", got.TrustMarks)
	}
}

func TestParseResolveResponseRejectsWrongType(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createResolveResponseToken(t, key, "resolver-kid", "some-other+jwt", validResolveResponseClaims(now))
	if _, err := ParseResolveResponse(token); !errors.Is(err, ErrResolveResponseWrongType) {
		t.Fatalf("ParseResolveResponse(wrong typ) = %v, want ErrResolveResponseWrongType", err)
	}
}

func TestParseResolveResponseRejectsMissingRequiredClaims(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	for _, field := range []string{"iss", "sub", "iat", "exp", "metadata", "trust_chain"} {
		t.Run(field, func(t *testing.T) {
			claims := validResolveResponseClaims(now)
			delete(claims, field)
			token := createResolveResponseToken(t, key, "resolver-kid", resolveResponseJWTType, claims)
			if _, err := ParseResolveResponse(token); !errors.Is(err, ErrMalformedClaims) {
				t.Fatalf("ParseResolveResponse(missing %s) = %v, want ErrMalformedClaims", field, err)
			}
		})
	}
}

func TestResolveResponseVerifyRejectsIssuerMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createResolveResponseToken(t, key, "resolver-kid", resolveResponseJWTType, validResolveResponseClaims(now))
	r, err := ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	policy := resolveResponseVerifyPolicy(now.Add(time.Second))
	policy.ExpectedIssuer = "https://someone-else.example.org"
	if _, err := r.Verify(&key.PublicKey, policy); !errors.Is(err, ErrResolveResponseIssuerMismatch) {
		t.Fatalf("Verify(issuer mismatch) = %v, want ErrResolveResponseIssuerMismatch", err)
	}
}

func TestResolveResponseVerifyRejectsSubjectMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createResolveResponseToken(t, key, "resolver-kid", resolveResponseJWTType, validResolveResponseClaims(now))
	r, err := ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	policy := resolveResponseVerifyPolicy(now.Add(time.Second))
	policy.ExpectedSubject = "https://someone-else.example.org"
	if _, err := r.Verify(&key.PublicKey, policy); !errors.Is(err, ErrResolveResponseSubjectMismatch) {
		t.Fatalf("Verify(subject mismatch) = %v, want ErrResolveResponseSubjectMismatch", err)
	}
}

func TestResolveResponseVerifyRejectsExpired(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createResolveResponseToken(t, key, "resolver-kid", resolveResponseJWTType, validResolveResponseClaims(now))
	r, err := ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	policy := resolveResponseVerifyPolicy(now.Add(2 * time.Hour))
	if _, err := r.Verify(&key.PublicKey, policy); !errors.Is(err, ErrResolveResponseExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrResolveResponseExpired", err)
	}
}

func TestCreateResolveResponseRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token, err := CreateResolveResponse(CreateResolveResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "resolver-kid",
		Issuer: "https://resolver.example.org", Subject: "https://op.example.org",
		Now: now, Lifetime: time.Hour,
		Metadata:   map[string]json.RawMessage{"openid_provider": json.RawMessage(`{"issuer":"https://op.example.org"}`)},
		TrustChain: []string{"a.b.c", "d.e.f"},
		TrustMarks: []RawTrustMark{{TrustMarkType: "https://marks.example.org/certified", TrustMark: "x.y.z"}},
	})
	if err != nil {
		t.Fatalf("CreateResolveResponse: %v", err)
	}

	r, err := ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	claims, err := r.Verify(&key.PublicKey, resolveResponseVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(claims.TrustChain) != 2 || claims.TrustChain[0] != "a.b.c" {
		t.Errorf("TrustChain = %v", claims.TrustChain)
	}
	if len(claims.TrustMarks) != 1 || claims.TrustMarks[0].TrustMark != "x.y.z" {
		t.Errorf("TrustMarks = %+v", claims.TrustMarks)
	}
}

func TestCreateResolveResponseRejectsMissingFields(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	base := func() CreateResolveResponseParams {
		return CreateResolveResponseParams{
			Signer: key, Algorithm: fapi.ES256, KeyID: "resolver-kid",
			Issuer: "https://resolver.example.org", Subject: "https://op.example.org",
			Now: now, Lifetime: time.Hour,
			Metadata:   map[string]json.RawMessage{"openid_provider": json.RawMessage(`{}`)},
			TrustChain: []string{"a.b.c"},
		}
	}
	cases := map[string]func(*CreateResolveResponseParams){
		"no signer":      func(p *CreateResolveResponseParams) { p.Signer = nil },
		"invalid alg":    func(p *CreateResolveResponseParams) { p.Algorithm = 0 },
		"no key id":      func(p *CreateResolveResponseParams) { p.KeyID = "" },
		"no issuer":      func(p *CreateResolveResponseParams) { p.Issuer = "" },
		"no subject":     func(p *CreateResolveResponseParams) { p.Subject = "" },
		"zero lifetime":  func(p *CreateResolveResponseParams) { p.Lifetime = 0 },
		"no metadata":    func(p *CreateResolveResponseParams) { p.Metadata = nil },
		"no trust chain": func(p *CreateResolveResponseParams) { p.TrustChain = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(&p)
			if _, err := CreateResolveResponse(p); err == nil {
				t.Fatalf("CreateResolveResponse(%s) = nil error, want error", name)
			}
		})
	}
}

func TestResolveResponseVerifyRejectsNotYetValid(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createResolveResponseToken(t, key, "resolver-kid", resolveResponseJWTType, validResolveResponseClaims(now.Add(time.Hour)))
	r, err := ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	policy := resolveResponseVerifyPolicy(now)
	if _, err := r.Verify(&key.PublicKey, policy); !errors.Is(err, ErrResolveResponseNotYetValid) {
		t.Fatalf("Verify(not yet valid) = %v, want ErrResolveResponseNotYetValid", err)
	}
}
