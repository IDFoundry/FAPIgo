package server

import (
	"crypto/sha256"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// TestAuthorizationCodeHash covers the digest a code is stored under: a
// plain SHA-256 for a client not authenticated by Client Attestation,
// and one per client instance otherwise, so another instance of the
// same client finds no code.
func TestAuthorizationCodeHash(t *testing.T) {
	const code = "code-value"
	if got, want := authorizationCodeHash(code, ""), sha256.Sum256([]byte(code)); got != want {
		t.Error("authorizationCodeHash without an instance isn't the code's SHA-256")
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

	for _, tc := range []struct {
		name      string
		client    storage.RegisteredClient
		grantType string
		ok        bool
	}{
		{"code grant, code client", codeClient, "authorization_code", true},
		{"code grant, code removed", cibaClient, "authorization_code", false},
		{"CIBA grant, CIBA client", cibaClient, CIBAGrantType, true},
		{"CIBA grant, CIBA removed", codeClient, CIBAGrantType, false},
		{"embedder grant", neither, "", true},
	} {
		err := checkGrantTypeStillAllowed(tc.client, grantRecord{GrantType: tc.grantType})
		if (err == nil) != tc.ok || (err != nil && err.Code() != ErrorUnauthorizedClient) {
			t.Errorf("%s: checkGrantTypeStillAllowed = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
