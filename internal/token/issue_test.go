package token

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// TestIssueAccessTokenRefusesMissingFields: every required field of
// AccessTokenParams is checked before signing, so a zero value never
// yields a token with an empty iss, aud or client_id, or one that is
// already expired.
func TestIssueAccessTokenRefusesMissingFields(t *testing.T) {
	key := generateKey(t)
	cases := []struct {
		name   string
		mutate func(*AccessTokenParams)
	}{
		{"empty issuer", func(p *AccessTokenParams) { p.Issuer = "" }},
		{"empty subject", func(p *AccessTokenParams) { p.Subject = "" }},
		{"no audience", func(p *AccessTokenParams) { p.Audience = "" }},
		{"empty client ID", func(p *AccessTokenParams) { p.ClientID = "" }},
		{"zero now", func(p *AccessTokenParams) { p.Now = time.Time{} }},
		{"zero lifetime", func(p *AccessTokenParams) { p.Lifetime = 0 }},
		{"negative lifetime", func(p *AccessTokenParams) { p.Lifetime = -time.Minute }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := baseAccessTokenParams(key, time.Now(), time.Minute)
			tc.mutate(&p)
			if _, _, err := IssueAccessToken(p); err == nil {
				t.Fatalf("IssueAccessToken(%s) = nil error, want error", tc.name)
			}
		})
	}
}

// TestIssueIDTokenRefusesMissingFields is the ID-token counterpart of
// TestIssueAccessTokenRefusesMissingFields.
func TestIssueIDTokenRefusesMissingFields(t *testing.T) {
	key := generateKey(t)
	cases := []struct {
		name   string
		mutate func(*IDTokenParams)
	}{
		{"empty issuer", func(p *IDTokenParams) { p.Issuer = "" }},
		{"empty subject", func(p *IDTokenParams) { p.Subject = "" }},
		{"empty audience", func(p *IDTokenParams) { p.Audience = "" }},
		{"zero now", func(p *IDTokenParams) { p.Now = time.Time{} }},
		{"zero lifetime", func(p *IDTokenParams) { p.Lifetime = 0 }},
		{"negative lifetime", func(p *IDTokenParams) { p.Lifetime = -time.Minute }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := baseIDTokenParams(key, time.Now(), time.Minute)
			tc.mutate(&p)
			if _, err := IssueIDToken(p); err == nil {
				t.Fatalf("IssueIDToken(%s) = nil error, want error", tc.name)
			}
		})
	}
}

// TestParseTokensRejectWrongTypedOptionalClaims: an optional claim of
// the wrong JSON type is malformed, not silently treated as absent — a
// numeric acr or a string amr must not read as "no acr"/"no amr".
func TestParseTokensRejectWrongTypedOptionalClaims(t *testing.T) {
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	compact := func(header, payload string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
	}
	const idBase = `"iss":"https://as.example","sub":"user-1","aud":"client-123","exp":9999999999,"iat":1`
	for _, extra := range []string{
		`"acr":2`,
		`"acr":""`,
		`"amr":"pwd"`,
		`"amr":[]`,
		`"amr":[1]`,
	} {
		tok := compact(`{"alg":"ES256"}`, `{`+idBase+`,`+extra+`}`)
		if _, err := ParseIDToken(tok); !errors.Is(err, ErrMalformedClaims) {
			t.Errorf("ParseIDToken(%s) = %v, want ErrMalformedClaims", extra, err)
		}
	}
	const atBase = `"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","client_id":"client-123","exp":9999999999,"iat":1,"jti":"x"`
	for _, extra := range []string{`"scope":["openid"]`, `"scope":""`} {
		tok := compact(`{"alg":"ES256","typ":"at+jwt"}`, `{`+atBase+`,`+extra+`}`)
		if _, err := ParseAccessToken(tok); !errors.Is(err, ErrMalformedClaims) {
			t.Errorf("ParseAccessToken(%s) = %v, want ErrMalformedClaims", extra, err)
		}
	}
}
