package fapitest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

// TestAuthorizationCodeFlowEncryptedIDToken is Phase 7's integration
// check for JWE-encrypted ID tokens: with the client and server both
// configured to agree on encryption (fapitest.Config.EncryptIDTokens),
// a real authorization_code flow over HTTP must still produce a usable
// TokenSet — the server signs then encrypts (OIDC Core §2/§10.2), the
// ID token crosses the wire as a JSON string in the token response
// exactly like an unencrypted one, and the client decrypts, verifies
// the nested JWT, and reports the same Subject a plaintext ID token
// would. This is the class of bug fapitest exists to catch (see
// doc.go) that neither side's own unit tests — server/idtoken_encryption_test.go,
// client/idtoken_internal_test.go — can see on their own, since each
// only ever hands the other a value it constructed directly, never one
// that actually crossed the wire.
func TestAuthorizationCodeFlowEncryptedIDToken(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, EncryptIDTokens: true})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if !tokens.HasIDToken || tokens.Subject != fapitest.Subject {
		t.Fatalf("HasIDToken=%v Subject=%q, want true/%q", tokens.HasIDToken, tokens.Subject, fapitest.Subject)
	}

	// A JWE compact serialization has 5 dot-separated segments; a bare
	// signed JWT has 3. This distinguishes "the client successfully
	// decrypted an encrypted ID token" from "the server never encrypted
	// it and the client validated a plain one instead" — both would
	// otherwise satisfy the assertions above.
	if segments := strings.Count(tokens.IDToken.Reveal(), ".") + 1; segments != 5 {
		t.Fatalf("ID token has %d dot-separated segments, want 5 (JWE compact serialization)", segments)
	}
}

// TestAuthorizationCodeFlowEncryptedIDTokenMessageSigningProfile mirrors
// TestAuthorizationCodeFlowMessageSigning (harness_test.go) with
// encryption also enabled, confirming JARM (signed authorization
// responses) and encrypted ID tokens compose without interfering with
// each other — two independent per-response-type protections that
// share no code path until the client's final token-response handling.
func TestAuthorizationCodeFlowEncryptedIDTokenMessageSigningProfile(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurityWithMessageSigning, EncryptIDTokens: true})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if !tokens.HasIDToken || tokens.Subject != fapitest.Subject {
		t.Fatalf("HasIDToken=%v Subject=%q, want true/%q", tokens.HasIDToken, tokens.Subject, fapitest.Subject)
	}
	if segments := strings.Count(tokens.IDToken.Reveal(), ".") + 1; segments != 5 {
		t.Fatalf("ID token has %d dot-separated segments, want 5 (JWE compact serialization)", segments)
	}
}
