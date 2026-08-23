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

// jweContentEncryption decodes the "enc" field from a JWE compact
// serialization's protected header, so a test can confirm which
// content-encryption algorithm was actually used — the dot-separated
// segment count alone can't distinguish A256GCM from A256CBC-HS512,
// since both produce a 5-segment JWE.
func jweContentEncryption(t *testing.T, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("jweContentEncryption: %d segments, want 5", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("jweContentEncryption: decode header: %v", err)
	}
	var header struct {
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("jweContentEncryption: unmarshal header: %v", err)
	}
	return header.Enc
}

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
	if enc := jweContentEncryption(t, tokens.IDToken.Reveal()); enc != "A256GCM" {
		t.Fatalf("enc = %q, want A256GCM", enc)
	}
}

// TestAuthorizationCodeFlowEncryptedIDTokenA256CBCHS512 is
// TestAuthorizationCodeFlowEncryptedIDToken with A256CBC-HS512 instead
// of the default A256GCM — Phase 3 of adding A256CBC-HS512 support
// (internal/jwe's own cipher work was Phases 1-2). This is the same
// class of wire-encoding check: A256CBC-HS512's ciphertext/tag/IV are
// different sizes than A256GCM's, so this confirms nothing on either
// side hardcoded GCM's shapes when the algorithm is actually
// configurable end to end.
func TestAuthorizationCodeFlowEncryptedIDTokenA256CBCHS512(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{
		Profile: server.ProfileFAPISecurity, EncryptIDTokens: true,
		IDTokenContentEncryption: fapi.A256CBCHS512,
	})
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
	if enc := jweContentEncryption(t, tokens.IDToken.Reveal()); enc != "A256CBC-HS512" {
		t.Fatalf("enc = %q, want A256CBC-HS512", enc)
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
