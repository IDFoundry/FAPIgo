package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func testJWKS(t *testing.T, key *ecdsa.PrivateKey) json.RawMessage {
	t.Helper()
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID("test-kid").MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	set, err := json.Marshal(map[string][]json.RawMessage{"keys": {jwkJSON}})
	if err != nil {
		t.Fatalf("marshal jwk set: %v", err)
	}
	return set
}

func entityConfigParams(t *testing.T, key *ecdsa.PrivateKey, entityID string, now time.Time) CreateParams {
	t.Helper()
	return CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "test-kid",
		Issuer: entityID, Subject: entityID,
		Now: now, Lifetime: time.Hour,
		JWKS:           testJWKS(t, key),
		AuthorityHints: []string{"https://superior.example.org"},
	}
}

func subordinateStatementParams(t *testing.T, superiorKey *ecdsa.PrivateKey, superiorID, subjectID string, now time.Time) CreateParams {
	t.Helper()
	return CreateParams{
		Signer: superiorKey, Algorithm: fapi.ES256, KeyID: "superior-kid",
		Issuer: superiorID, Subject: subjectID,
		Now: now, Lifetime: time.Hour,
		JWKS:           testJWKS(t, superiorKey),
		MetadataPolicy: mustPolicy(t, `{"openid_relying_party":{"subject_type":{"value":"pairwise"}}}`),
		SourceEndpoint: "https://superior.example.org/fetch",
	}
}

func TestCreateAndVerifyEntityConfiguration(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	const entityID = "https://rp.example.org"

	token, err := Create(entityConfigParams(t, key, entityID, now))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stmt.ClaimedIssuer() != entityID {
		t.Errorf("ClaimedIssuer = %q, want %q", stmt.ClaimedIssuer(), entityID)
	}
	if stmt.ClaimedSubject() != entityID {
		t.Errorf("ClaimedSubject = %q, want %q", stmt.ClaimedSubject(), entityID)
	}
	if stmt.KeyID() != "test-kid" {
		t.Errorf("KeyID = %q, want test-kid", stmt.KeyID())
	}
	if got := stmt.ClaimedAuthorityHints(); len(got) != 1 || got[0] != "https://superior.example.org" {
		t.Errorf("ClaimedAuthorityHints = %v", got)
	}

	claims, err := stmt.Verify(&key.PublicKey, VerifyPolicy{
		ExpectedIssuer: entityID, ExpectedSubject: entityID,
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Issuer != entityID || claims.Subject != entityID {
		t.Errorf("verified claims iss/sub = %q/%q, want %q/%q", claims.Issuer, claims.Subject, entityID, entityID)
	}
	if len(claims.JWKS) == 0 {
		t.Errorf("verified claims JWKS is empty")
	}
}

func TestCreateAndVerifySubordinateStatement(t *testing.T) {
	superiorKey := generateKey(t)
	now := time.Now()
	const superiorID = "https://superior.example.org"
	const subjectID = "https://rp.example.org"

	token, err := Create(subordinateStatementParams(t, superiorKey, superiorID, subjectID, now))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	claims, err := stmt.Verify(&superiorKey.PublicKey, VerifyPolicy{
		ExpectedIssuer: superiorID, ExpectedSubject: subjectID,
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.SourceEndpoint != "https://superior.example.org/fetch" {
		t.Errorf("SourceEndpoint = %q", claims.SourceEndpoint)
	}
	if claims.MetadataPolicy == nil {
		t.Errorf("MetadataPolicy is nil")
	}
}

func TestCreateRejectsMixedVariantClaims(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	selfSignedWithPolicy := entityConfigParams(t, key, "https://rp.example.org", now)
	selfSignedWithPolicy.MetadataPolicy = mustPolicy(t, `{"openid_relying_party":{}}`)
	if _, err := Create(selfSignedWithPolicy); err == nil {
		t.Errorf("Create(self-signed with metadata_policy) = nil error, want error")
	}

	subordinateWithHints := subordinateStatementParams(t, key, "https://superior.example.org", "https://rp.example.org", now)
	subordinateWithHints.AuthorityHints = []string{"https://someone.example.org"}
	if _, err := Create(subordinateWithHints); err == nil {
		t.Errorf("Create(subordinate statement with authority_hints) = nil error, want error")
	}

	subordinateWithTrustMarks := subordinateStatementParams(t, key, "https://superior.example.org", "https://rp.example.org", now)
	subordinateWithTrustMarks.TrustMarks = []RawTrustMark{{TrustMarkType: "https://federation.example.org/marks/certified", TrustMark: "opaque"}}
	if _, err := Create(subordinateWithTrustMarks); err == nil {
		t.Errorf("Create(subordinate statement with trust_marks) = nil error, want error")
	}
}

func TestCreateAndParseRoundTripsTrustMarksClaim(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	const entityID = "https://rp.example.org"

	p := entityConfigParams(t, key, entityID, now)
	p.TrustMarks = []RawTrustMark{
		{TrustMarkType: "https://federation.example.org/marks/certified", TrustMark: "opaque-trust-mark-jwt"},
	}
	token, err := Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(stmt.claims.TrustMarks) != 1 {
		t.Fatalf("TrustMarks = %v, want 1 entry", stmt.claims.TrustMarks)
	}
	got := stmt.claims.TrustMarks[0]
	if got.TrustMarkType != "https://federation.example.org/marks/certified" || got.TrustMark != "opaque-trust-mark-jwt" {
		t.Errorf("TrustMarks[0] = %+v", got)
	}
}

func TestVerifyRejectsIssuerAndSubjectMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	const entityID = "https://rp.example.org"

	token, err := Create(entityConfigParams(t, key, entityID, now))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	basePolicy := VerifyPolicy{ExpectedIssuer: entityID, ExpectedSubject: entityID, Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour}

	wrongIssuer := basePolicy
	wrongIssuer.ExpectedIssuer = "https://someone-else.example.org"
	if _, err := stmt.Verify(&key.PublicKey, wrongIssuer); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("Verify(wrong issuer) error = %v, want ErrIssuerMismatch", err)
	}

	wrongSubject := basePolicy
	wrongSubject.ExpectedSubject = "https://someone-else.example.org"
	if _, err := stmt.Verify(&key.PublicKey, wrongSubject); !errors.Is(err, ErrSubjectMismatch) {
		t.Errorf("Verify(wrong subject) error = %v, want ErrSubjectMismatch", err)
	}
}

func TestVerifyRejectsExpiredAndOverLifetime(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	const entityID = "https://rp.example.org"

	token, err := Create(entityConfigParams(t, key, entityID, now))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	expired := VerifyPolicy{
		ExpectedIssuer: entityID, ExpectedSubject: entityID, Algorithm: fapi.ES256,
		Now: now.Add(2 * time.Hour), MaxLifetime: 2 * time.Hour,
	}
	if _, err := stmt.Verify(&key.PublicKey, expired); !errors.Is(err, ErrExpired) {
		t.Errorf("Verify(expired) error = %v, want ErrExpired", err)
	}

	tooShortMaxLifetime := VerifyPolicy{
		ExpectedIssuer: entityID, ExpectedSubject: entityID, Algorithm: fapi.ES256,
		Now: now, MaxLifetime: time.Minute,
	}
	if _, err := stmt.Verify(&key.PublicKey, tooShortMaxLifetime); !errors.Is(err, ErrLifetimeExceeded) {
		t.Errorf("Verify(exceeds max lifetime) error = %v, want ErrLifetimeExceeded", err)
	}
}

func TestVerifyRejectsAlgorithmMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	const entityID = "https://rp.example.org"

	token, err := Create(entityConfigParams(t, key, entityID, now))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = stmt.Verify(&key.PublicKey, VerifyPolicy{
		ExpectedIssuer: entityID, ExpectedSubject: entityID,
		Algorithm: fapi.PS256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err == nil {
		t.Fatalf("Verify(wrong expected algorithm) = nil error, want error")
	}
}

func TestParseRejectsWrongOrMissingType(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://rp.example.org", "sub": "https://rp.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": json.RawMessage(testJWKS(t, key)),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	for _, typ := range []string{"", "some-other+jwt"} {
		token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: typ}, payload)
		if err != nil {
			t.Fatalf("jose.Sign: %v", err)
		}
		if _, err := Parse(token); !errors.Is(err, ErrWrongType) {
			t.Errorf("Parse(typ=%q) error = %v, want ErrWrongType", typ, err)
		}
	}
}

func TestParseRejectsMissingRequiredClaims(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	full := map[string]any{
		"iss": "https://rp.example.org", "sub": "https://rp.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": json.RawMessage(testJWKS(t, key)),
	}

	for _, missing := range []string{"iss", "sub", "iat", "exp", "jwks"} {
		claims := map[string]any{}
		for k, v := range full {
			if k != missing {
				claims[k] = v
			}
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("marshal claims: %v", err)
		}
		token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType}, payload)
		if err != nil {
			t.Fatalf("jose.Sign: %v", err)
		}
		if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
			t.Errorf("Parse(missing %q) error = %v, want ErrMalformedClaims", missing, err)
		}
	}
}

func TestParseRejectsNonJSONPayload(t *testing.T) {
	key := generateKey(t)
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType}, []byte("not json"))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
		t.Errorf("Parse(non-JSON payload) error = %v, want ErrMalformedClaims", err)
	}
}

func TestParseRejectsMalformedOptionalClaims(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	base := map[string]any{
		"iss": "https://rp.example.org", "sub": "https://superior.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": json.RawMessage(testJWKS(t, key)),
	}

	cases := map[string]any{
		"metadata":             `"not an object"`,
		"authority_hints":      `"not an array"`,
		"metadata_policy":      `["not an object"]`,
		"metadata_policy_crit": `{"not":"an array"}`,
		"source_endpoint":      `123`,
	}
	for claim, badValue := range cases {
		t.Run(claim, func(t *testing.T) {
			claims := map[string]any{}
			for k, v := range base {
				claims[k] = v
			}
			claims[claim] = json.RawMessage(badValue.(string))
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatalf("marshal claims: %v", err)
			}
			token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType}, payload)
			if err != nil {
				t.Fatalf("jose.Sign: %v", err)
			}
			if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
				t.Errorf("Parse(malformed %q) error = %v, want ErrMalformedClaims", claim, err)
			}
		})
	}
}

func TestParseRejectsMalformedRequiredClaims(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	base := map[string]any{
		"iss": "https://rp.example.org", "sub": "https://rp.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": json.RawMessage(testJWKS(t, key)),
	}

	cases := map[string]string{
		"iss": `123`, // not a string
		"sub": `""`,  // empty string, rejected same as absent
		"iat": `"x"`, // not an integer
		"exp": `"x"`, // not an integer
	}
	for claim, badValue := range cases {
		t.Run(claim, func(t *testing.T) {
			claims := map[string]any{}
			for k, v := range base {
				claims[k] = v
			}
			claims[claim] = json.RawMessage(badValue)
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatalf("marshal claims: %v", err)
			}
			token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType}, payload)
			if err != nil {
				t.Fatalf("jose.Sign: %v", err)
			}
			if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
				t.Errorf("Parse(malformed %q) error = %v, want ErrMalformedClaims", claim, err)
			}
		})
	}
}

func TestParseRejectsInvalidConstraints(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	base := map[string]any{
		"iss": "https://rp.example.org", "sub": "https://rp.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": json.RawMessage(testJWKS(t, key)),
	}

	cases := map[string]string{
		"malformed json":           `"not an object"`,
		"negative max_path_length": `{"max_path_length":-1}`,
	}
	for name, badValue := range cases {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{}
			for k, v := range base {
				claims[k] = v
			}
			claims["constraints"] = json.RawMessage(badValue)
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatalf("marshal claims: %v", err)
			}
			token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType}, payload)
			if err != nil {
				t.Fatalf("jose.Sign: %v", err)
			}
			if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
				t.Errorf("Parse(invalid constraints: %s) error = %v, want ErrMalformedClaims", name, err)
			}
		})
	}
}

func TestParseParsesTrustMarksClaim(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://rp.example.org", "sub": "https://rp.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": json.RawMessage(testJWKS(t, key)),
		"trust_marks": []map[string]string{
			{"trust_mark_type": "https://federation.example.org/marks/certified", "trust_mark": "eyJhbGciOiJFUzI1NiJ9.e30.sig"},
		},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(stmt.claims.TrustMarks) != 1 {
		t.Fatalf("TrustMarks = %v, want 1 entry", stmt.claims.TrustMarks)
	}
	got := stmt.claims.TrustMarks[0]
	if got.TrustMarkType != "https://federation.example.org/marks/certified" || got.TrustMark != "eyJhbGciOiJFUzI1NiJ9.e30.sig" {
		t.Errorf("TrustMarks[0] = %+v", got)
	}
}

func TestParseRejectsInvalidTrustMarksClaim(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	base := map[string]any{
		"iss": "https://rp.example.org", "sub": "https://rp.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": json.RawMessage(testJWKS(t, key)),
	}

	cases := map[string]string{
		"malformed json":          `"not an array"`,
		"missing trust_mark":      `[{"trust_mark_type":"https://federation.example.org/marks/certified"}]`,
		"missing trust_mark_type": `[{"trust_mark":"eyJhbGciOiJFUzI1NiJ9.e30.sig"}]`,
	}
	for name, badValue := range cases {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{}
			for k, v := range base {
				claims[k] = v
			}
			claims["trust_marks"] = json.RawMessage(badValue)
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatalf("marshal claims: %v", err)
			}
			token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType}, payload)
			if err != nil {
				t.Fatalf("jose.Sign: %v", err)
			}
			if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
				t.Errorf("Parse(invalid trust_marks: %s) error = %v, want ErrMalformedClaims", name, err)
			}
		})
	}
}

func TestParseRejectsMalformedCompact(t *testing.T) {
	if _, err := Parse("not-a-jws-at-all"); err == nil {
		t.Fatalf("Parse(garbage) = nil error, want error")
	}
}

func TestStatementAlgorithm(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token, err := Create(entityConfigParams(t, key, "https://rp.example.org", now))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stmt.Algorithm() != fapi.ES256 {
		t.Errorf("Algorithm() = %v, want ES256", stmt.Algorithm())
	}
}

func TestCreateRejectsInvalidParams(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	validParams := func() CreateParams {
		return entityConfigParams(t, key, "https://rp.example.org", now)
	}

	cases := map[string]func(*CreateParams){
		"nil signer":        func(p *CreateParams) { p.Signer = nil },
		"invalid algorithm": func(p *CreateParams) { p.Algorithm = 0 },
		"empty issuer":      func(p *CreateParams) { p.Issuer = "" },
		"empty subject":     func(p *CreateParams) { p.Subject = "" },
		"zero now":          func(p *CreateParams) { p.Now = time.Time{} },
		"zero lifetime":     func(p *CreateParams) { p.Lifetime = 0 },
		"negative lifetime": func(p *CreateParams) { p.Lifetime = -time.Second },
		"empty jwks":        func(p *CreateParams) { p.JWKS = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validParams()
			mutate(&p)
			if _, err := Create(p); err == nil {
				t.Fatalf("Create(%s) = nil error, want error", name)
			}
		})
	}
}

func TestCreateIncludesMetadataAndCriticalOperators(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	p := entityConfigParams(t, key, "https://rp.example.org", now)
	p.Metadata = map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"redirect_uris":["https://rp.example.org/cb"]}`)}
	token, err := Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	claims, err := stmt.Verify(&key.PublicKey, VerifyPolicy{
		ExpectedIssuer: "https://rp.example.org", ExpectedSubject: "https://rp.example.org",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Metadata == nil {
		t.Errorf("Metadata is nil")
	}

	sp := subordinateStatementParams(t, key, "https://superior.example.org", "https://rp.example.org", now)
	sp.MetadataPolicyCritical = []string{"x-custom-op"}
	token2, err := Create(sp)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt2, err := Parse(token2)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	claims2, err := stmt2.Verify(&key.PublicKey, VerifyPolicy{
		ExpectedIssuer: "https://superior.example.org", ExpectedSubject: "https://rp.example.org",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(claims2.MetadataPolicyCritical) != 1 || claims2.MetadataPolicyCritical[0] != "x-custom-op" {
		t.Errorf("MetadataPolicyCritical = %v", claims2.MetadataPolicyCritical)
	}
}

func TestVerifyRejectsInvalidPolicy(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token, err := Create(entityConfigParams(t, key, "https://rp.example.org", now))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	validPolicy := func() VerifyPolicy {
		return VerifyPolicy{
			ExpectedIssuer: "https://rp.example.org", ExpectedSubject: "https://rp.example.org",
			Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
		}
	}

	cases := map[string]func(*VerifyPolicy){
		"empty expected issuer":  func(p *VerifyPolicy) { p.ExpectedIssuer = "" },
		"empty expected subject": func(p *VerifyPolicy) { p.ExpectedSubject = "" },
		"zero now":               func(p *VerifyPolicy) { p.Now = time.Time{} },
		"zero max lifetime":      func(p *VerifyPolicy) { p.MaxLifetime = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := validPolicy()
			mutate(&policy)
			if _, err := stmt.Verify(&key.PublicKey, policy); err == nil {
				t.Fatalf("Verify(%s) = nil error, want error", name)
			}
		})
	}
}

func TestVerifyRejectsNotYetValid(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token, err := Create(entityConfigParams(t, key, "https://rp.example.org", now))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = stmt.Verify(&key.PublicKey, VerifyPolicy{
		ExpectedIssuer: "https://rp.example.org", ExpectedSubject: "https://rp.example.org",
		Algorithm: fapi.ES256, Now: now.Add(-time.Hour), MaxLifetime: 2 * time.Hour,
	})
	if !errors.Is(err, ErrNotYetValid) {
		t.Errorf("Verify(iat in the future) error = %v, want ErrNotYetValid", err)
	}
}

func TestCreateAndVerifyConstraints(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	p := subordinateStatementParams(t, key, "https://superior.example.org", "https://intermediate.example.org", now)
	p.Constraints = &Constraints{
		MaxPathLength:      1,
		HasMaxPathLength:   true,
		NamingConstraints:  &NamingConstraints{Permitted: []string{".example.org"}, Excluded: []string{"east.example.org"}},
		AllowedEntityTypes: []string{"openid_provider", "openid_relying_party"},
	}
	token, err := Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	claims, err := stmt.Verify(&key.PublicKey, VerifyPolicy{
		ExpectedIssuer: "https://superior.example.org", ExpectedSubject: "https://intermediate.example.org",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Constraints == nil {
		t.Fatalf("Constraints is nil")
	}
	if !claims.Constraints.HasMaxPathLength || claims.Constraints.MaxPathLength != 1 {
		t.Errorf("MaxPathLength = %v (has=%v), want 1 (true)", claims.Constraints.MaxPathLength, claims.Constraints.HasMaxPathLength)
	}
	if claims.Constraints.NamingConstraints == nil || len(claims.Constraints.NamingConstraints.Permitted) != 1 {
		t.Errorf("NamingConstraints = %+v", claims.Constraints.NamingConstraints)
	}
	if len(claims.Constraints.AllowedEntityTypes) != 2 {
		t.Errorf("AllowedEntityTypes = %v", claims.Constraints.AllowedEntityTypes)
	}
}

// TestCreateAndVerifyMaxPathLengthZero confirms max_path_length: 0 (a
// meaningful "no intermediates allowed" constraint) round-trips as
// present, distinct from the constraint being entirely absent.
func TestCreateAndVerifyMaxPathLengthZero(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := subordinateStatementParams(t, key, "https://superior.example.org", "https://leaf.example.org", now)
	p.Constraints = &Constraints{MaxPathLength: 0, HasMaxPathLength: true}
	token, err := Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	claims, err := stmt.Verify(&key.PublicKey, VerifyPolicy{
		ExpectedIssuer: "https://superior.example.org", ExpectedSubject: "https://leaf.example.org",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Constraints == nil || !claims.Constraints.HasMaxPathLength || claims.Constraints.MaxPathLength != 0 {
		t.Fatalf("Constraints = %+v, want HasMaxPathLength=true, MaxPathLength=0", claims.Constraints)
	}
}

func TestCreateRejectsConstraintsOnEntityConfiguration(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := entityConfigParams(t, key, "https://rp.example.org", now)
	p.Constraints = &Constraints{MaxPathLength: 1, HasMaxPathLength: true}
	if _, err := Create(p); err == nil {
		t.Errorf("Create(self-signed with constraints) = nil error, want error")
	}
}

func TestStatementClaimedJWKS(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	jwks := testJWKS(t, key)
	p := entityConfigParams(t, key, "https://rp.example.org", now)
	p.JWKS = jwks
	token, err := Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	eq, err := jsonEqual(stmt.ClaimedJWKS(), jwks)
	if err != nil {
		t.Fatalf("jsonEqual: %v", err)
	}
	if !eq {
		t.Errorf("ClaimedJWKS() = %s, want %s", stmt.ClaimedJWKS(), jwks)
	}
}

func TestStatementClaimedMetadataPolicy(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	wantPolicy := mustPolicy(t, `{"openid_relying_party":{"subject_type":{"value":"pairwise"}}}`)

	p := subordinateStatementParams(t, key, "https://superior.example.org", "https://rp.example.org", now)
	p.MetadataPolicy = wantPolicy
	p.MetadataPolicyCritical = []string{"x-custom-op"}
	token, err := Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy, crit := stmt.ClaimedMetadataPolicy()
	assertPolicyEqual(t, policy, wantPolicy)
	if len(crit) != 1 || crit[0] != "x-custom-op" {
		t.Errorf("ClaimedMetadataPolicy() crit = %v, want [x-custom-op]", crit)
	}
}

func TestStatementClaimedConstraints(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	maxPathLength := 2

	p := subordinateStatementParams(t, key, "https://superior.example.org", "https://rp.example.org", now)
	p.Constraints = &Constraints{
		MaxPathLength: maxPathLength, HasMaxPathLength: true,
		NamingConstraints:  &NamingConstraints{Permitted: []string{".example.org"}, Excluded: []string{"bad.example.org"}},
		AllowedEntityTypes: []string{"openid_relying_party"},
	}
	token, err := Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	constraints := stmt.ClaimedConstraints()
	if constraints == nil {
		t.Fatalf("ClaimedConstraints() = nil, want non-nil")
	}
	if !constraints.HasMaxPathLength || constraints.MaxPathLength != maxPathLength {
		t.Errorf("MaxPathLength = (%d, %v), want (%d, true)", constraints.MaxPathLength, constraints.HasMaxPathLength, maxPathLength)
	}
	if constraints.NamingConstraints == nil || len(constraints.NamingConstraints.Permitted) != 1 || len(constraints.NamingConstraints.Excluded) != 1 {
		t.Errorf("NamingConstraints = %+v, want one permitted and one excluded entry", constraints.NamingConstraints)
	}
	if len(constraints.AllowedEntityTypes) != 1 || constraints.AllowedEntityTypes[0] != "openid_relying_party" {
		t.Errorf("AllowedEntityTypes = %v, want [openid_relying_party]", constraints.AllowedEntityTypes)
	}
}

func TestStatementClaimedConstraintsAbsent(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := subordinateStatementParams(t, key, "https://superior.example.org", "https://rp.example.org", now)
	p.Constraints = nil
	token, err := Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stmt, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if constraints := stmt.ClaimedConstraints(); constraints != nil {
		t.Errorf("ClaimedConstraints() = %+v, want nil", constraints)
	}
}
