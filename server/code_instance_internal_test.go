package server

import (
	"crypto/sha256"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// TestAuthorizationCodeHash covers the digest a code is stored under:
// never the plain SHA-256 a refresh token with the same value is stored
// under, and the SHA-256 of the prefix, each part of the binding
// length-prefixed, and the code.
func TestAuthorizationCodeHash(t *testing.T) {
	const code = "code-value"
	bound := codeBinding{codeChallenge: "challenge", redirectURI: "https://rp.example/cb"}
	for _, binding := range []codeBinding{{}, bound, {instanceKey: "instance-a", codeChallenge: "challenge", dpopJKT: "jkt"}} {
		if authorizationCodeHash(code, binding) == sha256.Sum256([]byte(code)) {
			t.Errorf("authorizationCodeHash(%+v) is a refresh token's digest of the same value", binding)
		}
	}
	got := authorizationCodeHash(code, bound)
	if want := sha256.Sum256([]byte(codeHashPrefix + "0:" + "9:challenge" + "21:https://rp.example/cb" + "0:" + code)); got != want {
		t.Error("authorizationCodeHash isn't the SHA-256 of the prefix, the length-prefixed binding and the code")
	}
	if again := authorizationCodeHash(code, bound); again != got {
		t.Error("authorizationCodeHash isn't deterministic")
	}
}

// TestAuthorizationCodeHashSeparatesBindings covers one digest per
// client instance (for a client authenticated by Client Attestation),
// PKCE challenge, redirect URI and DPoP key, so a token request
// presenting another finds no code, and per split of the same text
// between the parts, or between the last part and the code: a
// code_challenge or redirect_uri is the client's to choose.
func TestAuthorizationCodeHashSeparatesBindings(t *testing.T) {
	type presented struct {
		code    string
		binding codeBinding
	}
	const code = "code-value"
	issued := presented{code, codeBinding{instanceKey: "instance-a", codeChallenge: "challenge", redirectURI: "https://rp.example/cb", dpopJKT: "jkt"}}
	for name, other := range map[string]presented{
		"another instance":            {code, codeBinding{instanceKey: "instance-b", codeChallenge: "challenge", redirectURI: "https://rp.example/cb", dpopJKT: "jkt"}},
		"no instance":                 {code, codeBinding{codeChallenge: "challenge", redirectURI: "https://rp.example/cb", dpopJKT: "jkt"}},
		"another challenge":           {code, codeBinding{instanceKey: "instance-a", codeChallenge: "challengf", redirectURI: "https://rp.example/cb", dpopJKT: "jkt"}},
		"another redirect URI":        {code, codeBinding{instanceKey: "instance-a", codeChallenge: "challenge", redirectURI: "https://rp.example/cc", dpopJKT: "jkt"}},
		"another DPoP key":            {code, codeBinding{instanceKey: "instance-a", codeChallenge: "challenge", redirectURI: "https://rp.example/cb", dpopJKT: "jku"}},
		"no DPoP key":                 {code, codeBinding{instanceKey: "instance-a", codeChallenge: "challenge", redirectURI: "https://rp.example/cb"}},
		"instance into challenge":     {code, codeBinding{instanceKey: "instance-", codeChallenge: "achallenge", redirectURI: "https://rp.example/cb", dpopJKT: "jkt"}},
		"challenge into redirect URI": {code, codeBinding{instanceKey: "instance-a", codeChallenge: "challeng", redirectURI: "ehttps://rp.example/cb", dpopJKT: "jkt"}},
		"redirect URI into DPoP key":  {code, codeBinding{instanceKey: "instance-a", codeChallenge: "challenge", redirectURI: "https://rp.example/c", dpopJKT: "bjkt"}},
		"DPoP key into code":          {"t" + code, codeBinding{instanceKey: "instance-a", codeChallenge: "challenge", redirectURI: "https://rp.example/cb", dpopJKT: "jk"}},
	} {
		if authorizationCodeHash(other.code, other.binding) == authorizationCodeHash(issued.code, issued.binding) {
			t.Errorf("authorizationCodeHash doesn't separate %s", name)
		}
	}
}

// TestCheckCodeInstance covers the code grant's own record of the
// instance it was issued to.
func TestCheckCodeInstance(t *testing.T) {
	for _, tc := range []struct {
		recorded, presented string
		ok                  bool
	}{
		{"", "", true},
		{"instance-a", "instance-a", true},
		{"instance-a", "instance-b", false},
		{"instance-a", "", false},
		{"", "instance-a", false},
	} {
		err := checkCodeInstance(grantRecord{ClientInstanceKey: tc.recorded}, tc.presented)
		if (err == nil) != tc.ok || (err != nil && err.Code() != ErrorInvalidGrant) {
			t.Errorf("checkCodeInstance(%q, %q) = %v, want ok=%v", tc.recorded, tc.presented, err, tc.ok)
		}
	}
}

// TestCheckGrantTypeStillAllowed covers the refresh-time check of the
// grant type a refresh token's grant was made under against the client's
// current registration.
func TestCheckGrantTypeStillAllowed(t *testing.T) {
	newClient := func(cfg storage.RegisteredClientConfig) storage.RegisteredClient {
		t.Helper()
		cfg.ID = "client"
		cfg.ClientAssertionAlgorithm = fapi.ES256
		cfg.AllowedScopes = []string{"accounts"}
		client, err := storage.NewRegisteredClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	codeClient := newClient(storage.RegisteredClientConfig{RedirectURIs: []fapi.RegisteredRedirectURI{"https://client.example/cb"}})
	cibaClient := newClient(storage.RegisteredClientConfig{
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		BackchannelTokenDeliveryMode:              storage.BackchannelTokenDeliveryModePoll,
	})
	neither := newClient(storage.RegisteredClientConfig{AllowsClientCredentialsGrant: true})

	const preAuthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	srv := &Server{cfg: Config{AdditionalGrantTypes: []string{preAuthorized}}}
	for _, tc := range []struct {
		name   string
		grant  grantRecord
		code   ErrorCode // "" when the refresh is allowed
		client storage.RegisteredClient
	}{
		{"code grant, code client", grantRecord{GrantType: "authorization_code"}, "", codeClient},
		{"code grant, code removed", grantRecord{GrantType: "authorization_code"}, ErrorUnauthorizedClient, cibaClient},
		{"CIBA grant, CIBA client", grantRecord{GrantType: CIBAGrantType}, "", cibaClient},
		{"CIBA grant, CIBA removed", grantRecord{GrantType: CIBAGrantType}, ErrorUnauthorizedClient, codeClient},
		{"embedder grant, type served", grantRecord{GrantType: preAuthorized}, "", neither},
		{"embedder grant, type removed", grantRecord{GrantType: "urn:example:removed"}, ErrorUnauthorizedClient, neither},
		{"legacy code or CIBA grant", grantRecord{CodeGrantID: "code-grant"}, "", neither},
		{"legacy embedder grant", grantRecord{}, ErrorInvalidGrant, neither},
	} {
		err := srv.checkGrantTypeStillAllowed(tc.client, tc.grant)
		if got := errorCodeOf(err); got != tc.code {
			t.Errorf("%s: checkGrantTypeStillAllowed code %q, want %q", tc.name, got, tc.code)
		}
	}
}

// errorCodeOf is err's code, or "" for no error.
func errorCodeOf(err *Error) ErrorCode {
	if err == nil {
		return ""
	}
	return err.Code()
}
