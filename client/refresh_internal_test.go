package client

import (
	"testing"
	"time"
)

// TestCheckRefreshedIDToken covers OIDC Core §12.2's comparisons with
// the original ID token, which a conforming server never fails.
func TestCheckRefreshedIDToken(t *testing.T) {
	authTime := time.Unix(1_700_000_000, 0)
	original := TokenSet{HasIDToken: true, IDTokenClaims: IDTokenClaims{Subject: "user-1", AuthTime: authTime, AZP: "client-1"}}
	same := original.IDTokenClaims
	withNonce := TokenSet{HasIDToken: true, IDTokenClaims: IDTokenClaims{Subject: "user-1", Nonce: "original-nonce"}}
	withAud := TokenSet{HasIDToken: true, IDTokenClaims: IDTokenClaims{Subject: "user-1", Audience: []string{"client-1", "rs-1"}}}

	for name, tc := range map[string]struct {
		original  TokenSet
		refreshed IDTokenClaims
		wantErr   bool
	}{
		"same":                                {original, same, false},
		"no auth_time":                        {original, IDTokenClaims{Subject: "user-1", AZP: "client-1"}, false},
		"no original ID token":                {TokenSet{}, IDTokenClaims{Subject: "anyone"}, false},
		"another subject":                     {original, IDTokenClaims{Subject: "user-2", AuthTime: authTime, AZP: "client-1"}, true},
		"auth_time of the refresh":            {original, IDTokenClaims{Subject: "user-1", AuthTime: authTime.Add(time.Hour), AZP: "client-1"}, true},
		"another azp":                         {original, IDTokenClaims{Subject: "user-1", AuthTime: authTime, AZP: "client-2"}, true},
		"azp where the original had none":     {TokenSet{HasIDToken: true, IDTokenClaims: IDTokenClaims{Subject: "user-1"}}, IDTokenClaims{Subject: "user-1", AZP: "client-1"}, true},
		"no nonce":                            {withNonce, IDTokenClaims{Subject: "user-1"}, false},
		"the original nonce":                  {withNonce, IDTokenClaims{Subject: "user-1", Nonce: "original-nonce"}, false},
		"another nonce":                       {withNonce, IDTokenClaims{Subject: "user-1", Nonce: "attacker-chosen-nonce"}, true},
		"nonce where the original had none":   {original, IDTokenClaims{Subject: "user-1", AuthTime: authTime, AZP: "client-1", Nonce: "n"}, true},
		"the same aud in another order":       {withAud, IDTokenClaims{Subject: "user-1", Audience: []string{"rs-1", "client-1"}}, false},
		"an aud missing one":                  {withAud, IDTokenClaims{Subject: "user-1", Audience: []string{"client-1"}}, true},
		"an aud with another":                 {withAud, IDTokenClaims{Subject: "user-1", Audience: []string{"client-1", "rs-2"}}, true},
		"aud where the original records none": {original, IDTokenClaims{Subject: "user-1", AuthTime: authTime, AZP: "client-1", Audience: []string{"client-1"}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkRefreshedIDToken(tc.original, tc.refreshed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkRefreshedIDToken = %v, want error %v", err, tc.wantErr)
			}
			if err != nil && err.Code() != ErrorInvalidResponse {
				t.Errorf("code = %q, want %q", err.Code(), ErrorInvalidResponse)
			}
		})
	}
}
