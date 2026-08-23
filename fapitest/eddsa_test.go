package fapitest_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

// jwsAlgorithm decodes the "alg" field from a compact JWS's protected
// header, so a test can confirm which signature algorithm was actually
// used rather than only checking the token parses and verifies —
// verification alone wouldn't distinguish "signed with the configured
// algorithm" from "the harness silently fell back to a different one
// both sides happen to accept."
func jwsAlgorithm(t *testing.T, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("jwsAlgorithm: %d segments, want 3", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("jwsAlgorithm: decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("jwsAlgorithm: unmarshal header: %v", err)
	}
	return header.Alg
}

// TestAuthorizationCodeFlowEdDSA is Phase 4 of adding EdDSA support:
// with fapitest.Config.SignatureAlgorithm set to fapi.EdDSA, a real
// authorization_code flow under ProfileFAPISecurityWithMessageSigning
// exercises every signing purpose this harness has (client assertion,
// request object, DPoP proof, JARM, ID token, access token) with
// EdDSA, over real HTTP — the class of cross-role bug (wire encoding,
// the client/server signer adapters' Digest-vs-SigningInput routing)
// neither side's own unit tests can see in isolation.
func TestAuthorizationCodeFlowEdDSA(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{
		Profile: server.ProfileFAPISecurityWithMessageSigning, SignatureAlgorithm: fapi.EdDSA,
	})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts", "offline_access"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if tokens.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if !tokens.HasIDToken || tokens.Subject != fapitest.Subject {
		t.Fatalf("HasIDToken=%v Subject=%q, want true/%q", tokens.HasIDToken, tokens.Subject, fapitest.Subject)
	}
	if !tokens.HasRefreshToken {
		t.Errorf("HasRefreshToken = false, want true (offline_access was granted)")
	}

	if alg := jwsAlgorithm(t, tokens.IDToken.Reveal()); alg != "EdDSA" {
		t.Fatalf("ID token alg = %q, want EdDSA", alg)
	}
	if alg := jwsAlgorithm(t, tokens.AccessToken.Reveal()); alg != "EdDSA" {
		t.Fatalf("access token alg = %q, want EdDSA", alg)
	}

	// verifyAccessToken (harness_test.go) drives the DPoP proof and
	// resource.Verify path — its own use of h.NewResourceRequestDPoPProof
	// signs that proof with the same EdDSA key, exercising DPoP under
	// this algorithm too.
	verifyAccessToken(t, h, tokens)
}
