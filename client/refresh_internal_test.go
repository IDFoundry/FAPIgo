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

	for name, tc := range map[string]struct {
		original  TokenSet
		refreshed IDTokenClaims
		wantErr   bool
	}{
		"same":                            {original, same, false},
		"no auth_time":                    {original, IDTokenClaims{Subject: "user-1", AZP: "client-1"}, false},
		"no original ID token":            {TokenSet{}, IDTokenClaims{Subject: "anyone"}, false},
		"another subject":                 {original, IDTokenClaims{Subject: "user-2", AuthTime: authTime, AZP: "client-1"}, true},
		"auth_time of the refresh":        {original, IDTokenClaims{Subject: "user-1", AuthTime: authTime.Add(time.Hour), AZP: "client-1"}, true},
		"another azp":                     {original, IDTokenClaims{Subject: "user-1", AuthTime: authTime, AZP: "client-2"}, true},
		"azp where the original had none": {TokenSet{HasIDToken: true, IDTokenClaims: IDTokenClaims{Subject: "user-1"}}, IDTokenClaims{Subject: "user-1", AZP: "client-1"}, true},
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
