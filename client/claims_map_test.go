package client_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
)

func TestIDTokenClaimsAsMapIncludesOptionalFieldsWhenPresent(t *testing.T) {
	exp := time.Unix(1893456000, 0)
	iat := time.Unix(1893452400, 0)
	authTime := time.Unix(1893450000, 0)
	claims := client.IDTokenClaims{
		Subject:   "user-1",
		ExpiresAt: exp,
		IssuedAt:  iat,
		AuthTime:  authTime,
		ACR:       "urn:mace:incommon:iap:silver",
		AMR:       []string{"pwd", "otp"},
		Parameters: map[string]json.RawMessage{
			"name":  json.RawMessage(`"Ada"`),
			"email": json.RawMessage(`"ada@example.com"`),
		},
	}

	got := claims.AsMap()

	want := map[string]any{
		"sub":       "user-1",
		"exp":       exp.Unix(),
		"iat":       iat.Unix(),
		"auth_time": authTime.Unix(),
		"acr":       "urn:mace:incommon:iap:silver",
		"amr":       []string{"pwd", "otp"},
		"name":      "Ada",
		"email":     "ada@example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("AsMap() = %v (len %d), want len %d", got, len(got), len(want))
	}
	for k, v := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("AsMap()[%q] missing", k)
			continue
		}
		gotJSON, _ := json.Marshal(gv)
		wantJSON, _ := json.Marshal(v)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("AsMap()[%q] = %v, want %v", k, gv, v)
		}
	}
}

// TestIDTokenClaimsAsMapOmitsAbsentOptionalFields confirms auth_time,
// acr and amr are left out entirely when the token never carried them
// (AuthTime zero, ACR "", AMR nil) — not included as a zero/empty
// value, which would misrepresent an absent claim as a present one
// (auth_time: 0 in particular would read as "authenticated at the Unix
// epoch", not "no auth_time claim at all").
func TestIDTokenClaimsAsMapOmitsAbsentOptionalFields(t *testing.T) {
	claims := client.IDTokenClaims{
		Subject:    "user-1",
		ExpiresAt:  time.Unix(1893456000, 0),
		IssuedAt:   time.Unix(1893452400, 0),
		Parameters: map[string]json.RawMessage{},
	}

	got := claims.AsMap()

	for _, key := range []string{"auth_time", "acr", "amr"} {
		if _, ok := got[key]; ok {
			t.Errorf("AsMap()[%q] = %v, want absent", key, got[key])
		}
	}
	if got["sub"] != "user-1" {
		t.Errorf("AsMap()[sub] = %v, want user-1", got["sub"])
	}
}

// TestIDTokenClaimsAsMapDoesNotMutateParameters confirms AsMap returns
// a copy — mutating the result must not reach back into c.Parameters.
func TestIDTokenClaimsAsMapDoesNotMutateParameters(t *testing.T) {
	claims := client.IDTokenClaims{
		Subject:    "user-1",
		Parameters: map[string]json.RawMessage{"name": json.RawMessage(`"Ada"`)},
	}

	got := claims.AsMap()
	got["name"] = "mutated"

	if string(claims.Parameters["name"]) != `"Ada"` {
		t.Fatalf("Parameters[name] = %s, want unchanged", claims.Parameters["name"])
	}
}

func TestUserInfoAsMapMergesSubjectAndParameters(t *testing.T) {
	info := client.UserInfo{
		Subject: "user-1",
		Parameters: map[string]json.RawMessage{
			"name":  json.RawMessage(`"Ada"`),
			"email": json.RawMessage(`"ada@example.com"`),
		},
	}

	got := info.AsMap()

	want := map[string]any{"sub": "user-1", "name": "Ada", "email": "ada@example.com"}
	if len(got) != len(want) {
		t.Fatalf("AsMap() = %v (len %d), want len %d", got, len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("AsMap()[%q] = %v, want %v", k, got[k], v)
		}
	}
}
