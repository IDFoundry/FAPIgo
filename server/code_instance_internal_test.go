package server

import (
	"crypto/sha256"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// TestAuthorizationCodeHash covers the digest a code is stored under:
// never the plain SHA-256 a refresh token with the same value is stored
// under, and one per client instance for a client authenticated by
// Client Attestation, so another instance of the same client finds no
// code.
func TestAuthorizationCodeHash(t *testing.T) {
	const code = "code-value"
	if authorizationCodeHash(code, "") == sha256.Sum256([]byte(code)) {
		t.Error("authorizationCodeHash without an instance is a refresh token's digest of the same value")
	}
	if got, want := authorizationCodeHash(code, ""), sha256.Sum256([]byte(codeHashPrefix+code)); got != want {
		t.Error("authorizationCodeHash without an instance isn't the SHA-256 of the prefixed code")
	}
	if authorizationCodeHash(code, "instance-a") == sha256.Sum256([]byte(code)) {
		t.Error("authorizationCodeHash with an instance is a refresh token's digest of the same value")
	}
	a, b := authorizationCodeHash(code, "instance-a"), authorizationCodeHash(code, "instance-b")
	if a == b || a == authorizationCodeHash(code, "") {
		t.Error("authorizationCodeHash doesn't separate instances")
	}
	if a != authorizationCodeHash(code, "instance-a") {
		t.Error("authorizationCodeHash isn't deterministic")
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
