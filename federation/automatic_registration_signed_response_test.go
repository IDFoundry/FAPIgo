package federation

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestRegistrationHoldsSignedResponseAlgorithmsToTheOPs covers OpenID
// Connect Core §10.1: an ID token is signed "using the algorithm
// specified" at registration, and Dynamic Client Registration 1.0 §2's
// userinfo_signed_response_alg makes the UserInfo response a signed JWT.
// The OP signs each with one algorithm, so an RP asking for another —
// or for signed UserInfo from an OP that signs none — isn't registered,
// instead of having its choice dropped.
func TestRegistrationHoldsSignedResponseAlgorithmsToTheOPs(t *testing.T) {
	signsBoth := AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}, IDTokenSigningAlgorithm: fapi.ES256, UserInfoSigningAlgorithm: fapi.PS256}
	signsIDTokensOnly := AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}, IDTokenSigningAlgorithm: fapi.ES256}
	for _, tc := range []struct {
		name    string
		cfg     AutomaticRegistrationConfig
		members string
		wantErr string
	}{
		{"none asked", signsBoth, ``, ""},
		{"matching ID token algorithm", signsBoth, `"id_token_signed_response_alg":"ES256",`, ""},
		{"other ID token algorithm", signsBoth, `"id_token_signed_response_alg":"RS256",`, "id_token_signed_response_alg"},
		{"matching UserInfo algorithm", signsBoth, `"userinfo_signed_response_alg":"PS256",`, ""},
		{"other UserInfo algorithm", signsBoth, `"userinfo_signed_response_alg":"ES256",`, "userinfo_signed_response_alg"},
		{"signed UserInfo from an OP that signs none", signsIDTokensOnly, `"userinfo_signed_response_alg":"ES256",`, "doesn't sign UserInfo"},
		{"ID token algorithm unchecked without ID tokens", AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}, `"id_token_signed_response_alg":"RS256",`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{` + tc.members + `"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks":` + testRPJWKS + `}`
			_, _, err := call(t, newTestAutomaticClientRepository(tc.cfg), raw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("registeredClientConfigFromMetadata: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("registeredClientConfigFromMetadata = %v, want an error naming %s", err, tc.wantErr)
			}
		})
	}
}
