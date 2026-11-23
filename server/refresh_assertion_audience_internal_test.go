package server

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestCheckRefreshAssertionAudience covers which grants a refresh's
// client assertion may name an endpoint URL for, once
// acceptableClientAssertionAudiences has let one through as a
// candidate: a CIBA grant only. An authorization code grant, a grant
// the embedder served and one whose type was never recorded need the
// issuer, and a client authenticated without an assertion has no aud
// to check.
func TestCheckRefreshAssertionAudience(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{cfg: Config{Issuer: issuer}}
	const tokenURL = "https://as.example/token"
	const preAuthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	iss := issuer.String()
	for _, tc := range []struct {
		name  string
		grant grantRecord
		aud   string
		code  ErrorCode // "" when the aud is accepted
	}{
		{"code grant, issuer", grantRecord{GrantType: "authorization_code"}, iss, ""},
		{"code grant, token endpoint URL", grantRecord{GrantType: "authorization_code"}, tokenURL, ErrorInvalidClient},
		{"CIBA grant, issuer", grantRecord{GrantType: CIBAGrantType}, iss, ""},
		{"CIBA grant, token endpoint URL", grantRecord{GrantType: CIBAGrantType}, tokenURL, ""},
		{"embedder grant, issuer", grantRecord{GrantType: preAuthorized}, iss, ""},
		{"embedder grant, token endpoint URL", grantRecord{GrantType: preAuthorized}, tokenURL, ErrorInvalidClient},
		{"untyped grant, issuer", grantRecord{CodeGrantID: "code-grant"}, iss, ""},
		{"untyped grant, token endpoint URL", grantRecord{CodeGrantID: "code-grant"}, tokenURL, ErrorInvalidClient},
		{"no assertion", grantRecord{GrantType: "authorization_code"}, "", ""},
	} {
		if got := errorCodeOf(srv.checkRefreshAssertionAudience(tc.grant, tc.aud)); got != tc.code {
			t.Errorf("%s: checkRefreshAssertionAudience code %q, want %q", tc.name, got, tc.code)
		}
	}
}
