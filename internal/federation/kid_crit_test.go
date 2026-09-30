package federation

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// signStatement signs claims (merged over a valid Entity Configuration's)
// with the given header kid.
func signStatement(t *testing.T, kid string, overrides map[string]any) string {
	t.Helper()
	key := generateKey(t)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://rp.example.org", "sub": "https://rp.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": json.RawMessage(testJWKS(t, key)),
	}
	for k, v := range overrides {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType, KeyID: kid}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestParseRequiresKeyID(t *testing.T) {
	if _, err := Parse(signStatement(t, "", nil)); !errors.Is(err, ErrMissingKeyID) {
		t.Errorf("Parse(no kid) = %v, want ErrMissingKeyID", err)
	}
	if _, err := Parse(signStatement(t, "test-kid", nil)); err != nil {
		t.Errorf("Parse(kid) = %v, want nil", err)
	}
}

func TestParseRequiresUniqueJWKSKeyIDs(t *testing.T) {
	a := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","kid":"a"}`)
	noKid := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`)
	upperKid := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","KID":"b"}`)
	for name, keys := range map[string][]json.RawMessage{
		"key without kid": {noKid},
		// Member names are case-sensitive: "KID" is not "kid".
		"kid in another case": {upperKid},
		"duplicate kid":       {a, a},
	} {
		token := signStatement(t, "test-kid", map[string]any{"jwks": map[string]any{"keys": keys}})
		if _, err := Parse(token); !errors.Is(err, ErrMalformedJWKS) {
			t.Errorf("Parse(%s) = %v, want ErrMalformedJWKS", name, err)
		}
	}
}

func TestParseRejectsCriticalClaims(t *testing.T) {
	for name, crit := range map[string]any{
		"names an extension claim": []string{"example_extension"},
		"not an array":             "example_extension",
		"empty":                    []string{},
	} {
		token := signStatement(t, "test-kid", map[string]any{"crit": crit, "example_extension": true})
		if _, err := Parse(token); !errors.Is(err, ErrUnsupportedCriticalClaim) {
			t.Errorf("Parse(crit %s) = %v, want ErrUnsupportedCriticalClaim", name, err)
		}
	}
	// An extension claim nobody marked critical is ignored.
	if _, err := Parse(signStatement(t, "test-kid", map[string]any{"example_extension": true})); err != nil {
		t.Errorf("Parse(non-critical extension claim) = %v, want nil", err)
	}
}

func TestCreateRequiresKeyIDs(t *testing.T) {
	key := generateKey(t)
	base := CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "test-kid",
		Issuer: "https://rp.example.org", Subject: "https://rp.example.org",
		Now: time.Now(), Lifetime: time.Hour, JWKS: testJWKS(t, key),
	}
	if _, err := Create(base); err != nil {
		t.Fatalf("Create(valid) = %v", err)
	}
	noKid := base
	noKid.KeyID = ""
	if _, err := Create(noKid); err == nil {
		t.Error("Create(no key ID) = nil error, want error")
	}
	dup := base
	dup.JWKS = json.RawMessage(`{"keys":[{"kty":"EC","kid":"a"},{"kty":"EC","kid":"a"}]}`)
	if _, err := Create(dup); !errors.Is(err, ErrMalformedJWKS) {
		t.Errorf("Create(duplicate jwks kid) = %v, want ErrMalformedJWKS", err)
	}
}
