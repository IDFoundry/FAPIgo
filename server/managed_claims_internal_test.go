package server

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/internal/grantrevocation"
	"github.com/idfoundry/fapigo/internal/token"
)

// storedClaimsUnderManagedNames are extension claims stored under the
// names of claims the server sets itself, as a record no extension
// registry allows could hold them.
func storedClaimsUnderManagedNames() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		grantrevocation.Claim:           json.RawMessage(`"forged-grant"`),
		grantrevocation.CodeClaim:       json.RawMessage(`"forged-code-grant"`),
		token.PairwiseSectorClaim:       json.RawMessage(`"forged.example"`),
		token.GrantTypeClaim:            json.RawMessage(`"client_credentials"`),
		RequestedUserinfoClaimsKey:      json.RawMessage(`["email"]`),
		"Authorization_Details":         json.RawMessage(`[{"type":"forged"}]`),
		"tenant":                        json.RawMessage(`"acme"`),
		token.ClientSubjectClaim:        json.RawMessage(`"forged-sub"`),
		RequestedUserinfoClaimValuesKey: json.RawMessage(`{}`),
	}
}

// TestAccessTokenClaimsManagedTakePrecedence covers a grant whose stored
// extension claims use the names of claims the server manages: the
// grant's own values replace them, and one the grant doesn't have
// leaves the name out, while an ordinary extension claim is kept and the
// record's own map isn't changed.
func TestAccessTokenClaimsManagedTakePrecedence(t *testing.T) {
	stored := storedClaimsUnderManagedNames()
	g := grantRecord{TokenClaims: stored, GrantID: "grant-1", ClientSubject: "pairwise-sub", PairwiseSector: "rp.example"}
	claims, err := g.accessTokenClaims()
	if err != nil {
		t.Fatalf("accessTokenClaims: %v", err)
	}
	want := map[string]string{
		grantrevocation.Claim:     `"grant-1"`,
		token.PairwiseSectorClaim: `"rp.example"`,
		"tenant":                  `"acme"`,
	}
	if len(claims) != len(want) {
		t.Fatalf("claims = %s, want only %v", claims, want)
	}
	for name, value := range want {
		if got := string(claims[name]); got != value {
			t.Errorf("%s = %s, want %s", name, got, value)
		}
	}
	if got := string(stored[grantrevocation.Claim]); got != `"forged-grant"` {
		t.Errorf("stored claims changed: %s = %s", grantrevocation.Claim, got)
	}
}

// TestAccessTokenClaimsWithoutManagedValues covers a grant with no
// value of its own for any managed claim: a stored value under one of
// their names doesn't stand in for it.
func TestAccessTokenClaimsWithoutManagedValues(t *testing.T) {
	claims, err := grantRecord{TokenClaims: storedClaimsUnderManagedNames()}.accessTokenClaims()
	if err != nil {
		t.Fatalf("accessTokenClaims: %v", err)
	}
	if len(claims) != 1 || string(claims["tenant"]) != `"acme"` {
		t.Fatalf("claims = %s, want only tenant", claims)
	}
}
