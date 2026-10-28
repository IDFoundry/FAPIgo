package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/server"
)

// OIDC Core §5.5.1: "When the Claim value does not match the requested
// value, the Claim is not included in the response." "values" is
// "processed equivalently ... except that a choice of acceptable Claim
// values is provided".
func TestIDTokenIdentityClaimsHonourRequestedValues(t *testing.T) {
	h := newHarnessWithIdentityClaims(t, fakeIdentityClaims{
		subject: "user-1",
		claims: map[string]json.RawMessage{
			"email": json.RawMessage(`"real@example.com"`),
			"name":  json.RawMessage(`"Sam Rivera"`),
		},
	})
	for _, tc := range []struct {
		claims       string
		email, named bool
	}{
		{`{"id_token":{"email":{"value":"other@example.com"},"name":null}}`, false, true},
		{`{"id_token":{"email":{"value":"real@example.com"}}}`, true, false},
		{`{"id_token":{"email":{"values":["other@example.com","real@example.com"]}}}`, true, false},
		{`{"id_token":{"email":{"values":["other@example.com"]},"name":{"essential":true}}}`, false, true},
		{`{"id_token":{"email":{"value":"real@example.com","values":["other@example.com"]}}}`, false, false},
	} {
		t.Run(tc.claims, func(t *testing.T) {
			validated := exchangeForValidatedIDToken(t, h, completeAuthorizationWithClaims(t, h, tc.claims))
			if _, ok := validated.Parameters["email"]; ok != tc.email {
				t.Errorf("ID token email present = %v, want %v (%s)", ok, tc.email, validated.Parameters["email"])
			}
			if _, ok := validated.Parameters["name"]; ok != tc.named {
				t.Errorf("ID token name present = %v, want %v", ok, tc.named)
			}
		})
	}
}

// The access token records the values requested of userinfo claims, for
// a UserInfo endpoint (serverresource.UserInfoClaims) to apply, and
// nothing when none carried one.
func TestAccessTokenRecordsRequestedUserinfoClaimValues(t *testing.T) {
	h := newHarnessWithIdentityClaims(t, fakeIdentityClaims{subject: "user-1"})
	for claims, want := range map[string]string{
		`{"userinfo":{"email":{"value":"a@example.com"},"name":null}}`: `{"email":["a@example.com"]}`,
		`{"userinfo":{"email":{"values":["a","b"]}}}`:                  `{"email":["a","b"]}`,
		`{"userinfo":{"email":null}}`:                                  ``,
	} {
		t.Run(claims, func(t *testing.T) {
			code := completeAuthorizationWithClaims(t, h, claims)
			result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
				HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			raw, ok := accessTokenParameters(t, h, result.AccessToken.Reveal())[server.RequestedUserinfoClaimValuesKey]
			if want == "" {
				if ok {
					t.Fatalf("access token carries %s = %s, want none", server.RequestedUserinfoClaimValuesKey, raw)
				}
				return
			}
			if !ok || string(raw) != want {
				t.Fatalf("access token %s = %s, want %s", server.RequestedUserinfoClaimValuesKey, raw, want)
			}
		})
	}
}

func accessTokenParameters(t *testing.T, h harness, raw string) map[string]json.RawMessage {
	t.Helper()
	parsed, err := token.ParseAccessToken(raw)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer, Algorithm: fapi.ES256,
		Now: h.now, MaxLifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	return validated.Parameters
}
