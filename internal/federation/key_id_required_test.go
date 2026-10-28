package federation

import (
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// TestParsersRequireKeyID covers OpenID Federation 1.0 §7, §7.2.1,
// §8.3.2, §8.4.2 and §8.7.2: Trust Marks, Trust Mark delegations,
// Resolve Responses, Trust Mark Status Responses and historical keys
// JWTs each "MUST include the kid (Key ID) header parameter".
func TestParsersRequireKeyID(t *testing.T) {
	key := generateKey(t)
	for _, tc := range []struct {
		typ   string
		parse func(string) error
	}{
		{trustMarkJWTType, func(s string) error { _, err := ParseTrustMark(s); return err }},
		{trustMarkDelegationJWTType, func(s string) error { _, err := ParseTrustMarkDelegation(s); return err }},
		{resolveResponseJWTType, func(s string) error { _, err := ParseResolveResponse(s); return err }},
		{trustMarkStatusResponseJWTType, func(s string) error { _, err := ParseTrustMarkStatusResponse(s); return err }},
		{historicalKeysJWTType, func(s string) error { _, err := ParseHistoricalKeysResponse(s); return err }},
	} {
		token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: tc.typ}, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := tc.parse(token); !errors.Is(err, ErrMissingKeyID) {
			t.Errorf("parse %s without kid = %v, want ErrMissingKeyID", tc.typ, err)
		}
	}
}

// TestHistoricalKeysSkipEntriesMissingRequiredMembers covers §8.7.2's
// REQUIRED kid of each key and revoked_at of each revocation: an entry
// lacking either isn't a usable historical key.
func TestHistoricalKeysSkipEntriesMissingRequiredMembers(t *testing.T) {
	signingKey, historicalKey := generateKey(t), generateKey(t)
	now := time.Now()
	withoutKid := historicalKeyJWKMap(t, "", &historicalKey.PublicKey, map[string]any{"exp": now.Add(-time.Hour).Unix()})
	delete(withoutKid, "kid")
	for name, entry := range map[string]map[string]any{
		"no kid":        withoutKid,
		"no revoked_at": historicalKeyJWKMap(t, "k", &historicalKey.PublicKey, map[string]any{"exp": now.Add(-time.Hour).Unix(), "revoked": map[string]any{"reason": "compromised"}}),
	} {
		token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, map[string]any{
			"iss": "https://entity.example.org", "iat": now.Unix(), "keys": []map[string]any{entry},
		})
		r, err := ParseHistoricalKeysResponse(token)
		if err != nil {
			t.Fatalf("%s: ParseHistoricalKeysResponse: %v", name, err)
		}
		claims, err := r.Verify(&signingKey.PublicKey, historicalKeysVerifyPolicy(now.Add(time.Second)))
		if err != nil {
			t.Fatalf("%s: Verify: %v", name, err)
		}
		if len(claims.Keys) != 0 {
			t.Errorf("%s: Keys = %+v, want the entry skipped", name, claims.Keys)
		}
	}
}
