package claimnames

import "testing"

type reservedCase struct {
	kind   Kind
	source Source
	name   string
	want   bool
}

func reservedCases() []reservedCase {
	var cases []reservedCase
	add := func(kind Kind, source Source, want bool, names ...string) {
		for _, n := range names {
			cases = append(cases, reservedCase{kind, source, n, want})
		}
	}
	everywhere := []string{"_claim_names", "_claim_sources", "sub_jwk", "events"}
	authority := []string{"roles", "groups", "entitlements", "act", "may_act", "authorization_details"}
	jarmParams := []string{"code", "state", "error"}
	for _, source := range []Source{Embedder, Client} {
		add(IDToken, source, true, everywhere...)
		add(IDToken, source, true, jarmParams...)
		add(IDToken, source, true, "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "cnf", "nonce", "auth_time", "acr", "amr", "azp", "at_hash", "c_hash", "s_hash")
		add(AccessToken, source, true, everywhere...)
		add(AccessToken, source, true, "iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope", "cnf")
		add(UserInfo, source, true, everywhere...)
		add(UserInfo, source, true, jarmParams...)
		add(UserInfo, source, true, "iss", "aud", "azp", "nonce", "at_hash", "c_hash", "s_hash")
		add(UserInfo, source, false, "sub", "exp")
	}
	// The embedder decides authorization attributes and delegation, and
	// supplies the resource owner's identity claims; a client never does.
	for _, kind := range []Kind{IDToken, AccessToken, UserInfo} {
		add(kind, Embedder, false, authority...)
		add(kind, Embedder, false, "email", "name")
		add(kind, Client, true, authority...)
		add(kind, Client, true, "email", "name")
		add(kind, Embedder, false, "x_custom")
		add(kind, Client, false, "x_custom")
	}
	return cases
}

func TestReserved(t *testing.T) {
	for _, tc := range reservedCases() {
		if got := Reserved(tc.kind, tc.source, tc.name); got != tc.want {
			t.Errorf("Reserved(%d, %d, %q) = %v, want %v", tc.kind, tc.source, tc.name, got, tc.want)
		}
	}
}

func TestReservedInTokens(t *testing.T) {
	for name, want := range map[string]bool{"code": true, "client_id": true, "roles": true, "x_custom": false} {
		if got := ReservedInTokens(Client, name); got != want {
			t.Errorf("ReservedInTokens(Client, %q) = %v, want %v", name, got, want)
		}
	}
	if ReservedInTokens(Embedder, "roles") {
		t.Error("ReservedInTokens(Embedder, roles) = true, want false")
	}
}
