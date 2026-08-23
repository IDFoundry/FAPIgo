package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

const (
	idTokenTestIssuer   = "https://as.example.com"
	idTokenTestClientID = "test-client"
	idTokenTestSubject  = "end-user-1"
	idTokenTestNonce    = "opaque-nonce"
)

// idTokenFixedClock is a local Clock stand-in — client_test.go's own
// fixedClock lives in the external client_test package and isn't
// reachable from this white-box (package client) test file.
type idTokenFixedClock struct{ now time.Time }

func (c idTokenFixedClock) Now() time.Time { return c.now }

// fakeIDTokenIssuerKeys resolves a single fixed ECDSA public key for
// keys.IDTokenVerification — this test suite only needs to prove
// validateIDToken's dispatch and decryption logic, not exercise key
// rotation, which internal/token and keys/jwksissuer already cover.
type fakeIDTokenIssuerKeys struct {
	pub *ecdsa.PublicKey
}

func (f fakeIDTokenIssuerKeys) ResolveIssuerKeys(_ context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	if req.Purpose != keys.IDTokenVerification {
		return keys.IssuerKeySet{}, fmt.Errorf("fakeIDTokenIssuerKeys: unexpected purpose %v", req.Purpose)
	}
	return keys.IssuerKeySet{Keys: []keys.IssuerKey{{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: f.pub}}}, nil
}

func idTokenTestClient(t *testing.T, now time.Time, algorithms Algorithms, decryption keys.Decrypter) (*Client, *ecdsa.PrivateKey) {
	t.Helper()
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate id token key: %v", err)
	}
	issuer, err := fapi.ParseIssuerURL(idTokenTestIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	c := &Client{
		cfg: Config{
			Issuer:     issuer,
			ClientID:   fapi.ClientID(idTokenTestClientID),
			Algorithms: algorithms,
			Limits:     Limits{MaxIDTokenLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second},
		},
		deps: Dependencies{
			IssuerKeys: fakeIDTokenIssuerKeys{pub: &idKey.PublicKey},
			Clock:      idTokenFixedClock{now: now},
			Decryption: decryption,
		},
	}
	return c, idKey
}

func buildTestSignedIDToken(t *testing.T, idKey *ecdsa.PrivateKey, now time.Time) string {
	t.Helper()
	tok, err := token.IssueIDToken(token.IDTokenParams{
		Signer: idKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: idTokenTestIssuer, Subject: idTokenTestSubject, Audience: idTokenTestClientID,
		Nonce: idTokenTestNonce, Now: now, Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	return tok
}

// buildTestSignedIDTokenWithClaims mirrors buildTestSignedIDToken but
// also embeds ACR/AMR/AuthTime and a custom Parameters claim, for
// confirming validateIDToken actually propagates all of
// token.ValidatedIDToken rather than collapsing it to just Subject.
func buildTestSignedIDTokenWithClaims(t *testing.T, idKey *ecdsa.PrivateKey, now time.Time) string {
	t.Helper()
	tok, err := token.IssueIDToken(token.IDTokenParams{
		Signer: idKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: idTokenTestIssuer, Subject: idTokenTestSubject, Audience: idTokenTestClientID,
		Nonce: idTokenTestNonce, AuthTime: now, ACR: "urn:mace:incommon:iap:silver", AMR: []string{"pwd"},
		Now: now, Lifetime: time.Minute,
		Parameters: map[string]json.RawMessage{"email": json.RawMessage(`"end-user@example.com"`)},
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	return tok
}

// assertFullIDTokenClaims checks every field validateIDToken's caller
// should be able to reach beyond Subject — ACR/AMR/AuthTime/Parameters
// — using the exact values buildTestSignedIDTokenWithClaims embedded.
func assertFullIDTokenClaims(t *testing.T, validated token.ValidatedIDToken, now time.Time) {
	t.Helper()
	if validated.Subject != idTokenTestSubject {
		t.Errorf("Subject = %q, want %q", validated.Subject, idTokenTestSubject)
	}
	// auth_time is a JWT NumericDate (whole seconds), so sub-second
	// precision doesn't survive the round trip.
	if !validated.AuthTime.Equal(now.Truncate(time.Second)) {
		t.Errorf("AuthTime = %v, want %v", validated.AuthTime, now.Truncate(time.Second))
	}
	if validated.ACR != "urn:mace:incommon:iap:silver" {
		t.Errorf("ACR = %q, want %q", validated.ACR, "urn:mace:incommon:iap:silver")
	}
	if len(validated.AMR) != 1 || validated.AMR[0] != "pwd" {
		t.Errorf("AMR = %v, want [pwd]", validated.AMR)
	}
	email, ok := validated.Parameters["email"]
	if !ok || string(email) != `"end-user@example.com"` {
		t.Errorf(`Parameters["email"] = %s, ok=%v, want "end-user@example.com", true`, email, ok)
	}
}

// TestValidateIDTokenReturnsFullClaims confirms validateIDToken
// propagates the entire validated ID token, not just Subject, for an
// ordinary signed (unencrypted) token.
func TestValidateIDTokenReturnsFullClaims(t *testing.T) {
	now := time.Now()
	c, idKey := idTokenTestClient(t, now, Algorithms{IDToken: fapi.ES256}, nil)
	raw := buildTestSignedIDTokenWithClaims(t, idKey, now)

	validated, err := c.validateIDToken(context.Background(), raw, idTokenTestNonce)
	if err != nil {
		t.Fatalf("validateIDToken: %v", err)
	}
	assertFullIDTokenClaims(t, validated, now)
}

// TestValidateIDTokenReturnsFullClaimsWhenEncrypted is the case that
// actually matters: for an encrypted ID token, decryption happens
// entirely inside client, so this is the only way any claim besides
// Subject can ever reach a caller at all.
func TestValidateIDTokenReturnsFullClaimsWhenEncrypted(t *testing.T) {
	now := time.Now()
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	c, idKey := idTokenTestClient(t, now, Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.RSAOAEP256, IDTokenContentEncryption: fapi.A256GCM,
	}, decrypter)

	signed := buildTestSignedIDTokenWithClaims(t, idKey, now)
	info, err := decrypter.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	encrypted, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: info.PublicKey,
		ContentType: "JWT", Plaintext: []byte(signed),
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	validated, verr := c.validateIDToken(context.Background(), encrypted, idTokenTestNonce)
	if verr != nil {
		t.Fatalf("validateIDToken: %v", verr)
	}
	assertFullIDTokenClaims(t, validated, now)
}

func TestValidateIDTokenAcceptsPlainSignedToken(t *testing.T) {
	now := time.Now()
	c, idKey := idTokenTestClient(t, now, Algorithms{IDToken: fapi.ES256}, nil)
	raw := buildTestSignedIDToken(t, idKey, now)

	validated, err := c.validateIDToken(context.Background(), raw, idTokenTestNonce)
	if err != nil {
		t.Fatalf("validateIDToken: %v", err)
	}
	if validated.Subject != idTokenTestSubject {
		t.Fatalf("subject = %q, want %q", validated.Subject, idTokenTestSubject)
	}
}

func TestValidateIDTokenAcceptsEncryptedTokenRSAOAEP256(t *testing.T) {
	now := time.Now()
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	c, idKey := idTokenTestClient(t, now, Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.RSAOAEP256, IDTokenContentEncryption: fapi.A256GCM,
	}, decrypter)

	signed := buildTestSignedIDToken(t, idKey, now)
	info, err := decrypter.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	encrypted, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: info.PublicKey,
		ContentType: "JWT", Plaintext: []byte(signed),
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	validated, verr := c.validateIDToken(context.Background(), encrypted, idTokenTestNonce)
	if verr != nil {
		t.Fatalf("validateIDToken: %v", verr)
	}
	if validated.Subject != idTokenTestSubject {
		t.Fatalf("subject = %q, want %q", validated.Subject, idTokenTestSubject)
	}
}

func TestValidateIDTokenAcceptsEncryptedTokenECDHESA256KW(t *testing.T) {
	now := time.Now()
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.ECDHESA256KW,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	c, idKey := idTokenTestClient(t, now, Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.ECDHESA256KW, IDTokenContentEncryption: fapi.A256GCM,
	}, decrypter)

	signed := buildTestSignedIDToken(t, idKey, now)
	info, err := decrypter.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.ECDHESA256KW)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	encrypted, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: info.PublicKey,
		ContentType: "JWT", Plaintext: []byte(signed),
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	validated, verr := c.validateIDToken(context.Background(), encrypted, idTokenTestNonce)
	if verr != nil {
		t.Fatalf("validateIDToken: %v", verr)
	}
	if validated.Subject != idTokenTestSubject {
		t.Fatalf("subject = %q, want %q", validated.Subject, idTokenTestSubject)
	}
}

// The core downgrade-protection guarantee: a client that registered for
// encrypted ID tokens must reject a plain signed one outright, not fall
// back to accepting it.
func TestValidateIDTokenRejectsPlainTokenWhenEncryptionRequired(t *testing.T) {
	now := time.Now()
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	c, idKey := idTokenTestClient(t, now, Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.RSAOAEP256, IDTokenContentEncryption: fapi.A256GCM,
	}, decrypter)
	raw := buildTestSignedIDToken(t, idKey, now)

	_, verr := c.validateIDToken(context.Background(), raw, idTokenTestNonce)
	if verr == nil {
		t.Fatalf("validateIDToken(plain token, encryption required) = nil error, want error")
	}
	// Checking the exact message (not just that some error occurred)
	// pins this to the explicit downgrade-protection guard actually
	// firing, not an incidental error from further down the call chain.
	const want = "ID token is not encrypted, but this client is configured to require an encrypted ID token"
	if verr.PublicDescription() != want {
		t.Fatalf("PublicDescription() = %q, want %q", verr.PublicDescription(), want)
	}
}

// The symmetric case: an encrypted token arriving when this client
// never configured encryption support must also be rejected — this
// client has no configured algorithm or Decryption dependency to
// process it with, and the token's own header claim is not policy.
func TestValidateIDTokenRejectsEncryptedTokenWhenNotConfigured(t *testing.T) {
	now := time.Now()
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	c, idKey := idTokenTestClient(t, now, Algorithms{IDToken: fapi.ES256}, nil)

	signed := buildTestSignedIDToken(t, idKey, now)
	info, err := decrypter.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	encrypted, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: info.PublicKey,
		ContentType: "JWT", Plaintext: []byte(signed),
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	_, verr := c.validateIDToken(context.Background(), encrypted, idTokenTestNonce)
	if verr == nil {
		t.Fatalf("validateIDToken(encrypted token, not configured) = nil error, want error")
	}
	// Checking the exact message pins this to the explicit
	// "encryption arrived unexpectedly" guard firing, not merely to
	// jwe.Decrypt's own unrelated "invalid algorithm" rejection of the
	// zero IDTokenKeyManagement value this client configuration carries
	// — both would produce *an* error, but only the former proves this
	// guard, not an incidental side effect, is what's rejecting it.
	const want = "ID token is encrypted, but this client is not configured to expect an encrypted ID token"
	if verr.PublicDescription() != want {
		t.Fatalf("PublicDescription() = %q, want %q", verr.PublicDescription(), want)
	}
}

// RFC 7519 §5.2 requires a nested JWT's outer "cty" to be "JWT" — a
// decrypted payload missing (or misdeclaring) that must be rejected,
// not passed through to signature verification regardless.
func TestValidateIDTokenRejectsWrongContentType(t *testing.T) {
	now := time.Now()
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	c, idKey := idTokenTestClient(t, now, Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.RSAOAEP256, IDTokenContentEncryption: fapi.A256GCM,
	}, decrypter)

	signed := buildTestSignedIDToken(t, idKey, now)
	info, err := decrypter.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	// ContentType deliberately omitted, unlike the happy-path tests
	// above which always set it to "JWT".
	encrypted, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: info.PublicKey,
		Plaintext: []byte(signed),
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	if _, err := c.validateIDToken(context.Background(), encrypted, idTokenTestNonce); err == nil {
		t.Fatalf("validateIDToken(missing cty) = nil error, want error")
	}
}

func TestIsNestedJWTContentType(t *testing.T) {
	cases := map[string]bool{
		"JWT":              true,
		"jwt":              true,
		"application/JWT":  true,
		"application/jwt":  true,
		"":                 false,
		"json":             false,
		"application/jose": false,
	}
	for cty, want := range cases {
		if got := isNestedJWTContentType(cty); got != want {
			t.Errorf("isNestedJWTContentType(%q) = %v, want %v", cty, got, want)
		}
	}
}

func TestValidateIDTokenRejectsMalformedSegmentCount(t *testing.T) {
	now := time.Now()
	c, _ := idTokenTestClient(t, now, Algorithms{IDToken: fapi.ES256}, nil)
	for name, raw := range map[string]string{
		"one segment":   "not-a-token",
		"two segments":  "aaaa.bbbb",
		"four segments": "aaaa.bbbb.cccc.dddd",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.validateIDToken(context.Background(), raw, idTokenTestNonce); err == nil {
				t.Fatalf("validateIDToken(%s) = nil error, want error", name)
			}
		})
	}
}

func TestValidateIDTokenRejectsDecryptionWithWrongKey(t *testing.T) {
	now := time.Now()
	encryptTo, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	wrongKey, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	c, idKey := idTokenTestClient(t, now, Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.RSAOAEP256, IDTokenContentEncryption: fapi.A256GCM,
	}, wrongKey)

	signed := buildTestSignedIDToken(t, idKey, now)
	info, err := encryptTo.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	encrypted, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: info.PublicKey,
		ContentType: "JWT", Plaintext: []byte(signed),
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	if _, err := c.validateIDToken(context.Background(), encrypted, idTokenTestNonce); err == nil {
		t.Fatalf("validateIDToken(wrong decryption key) = nil error, want error")
	}
}
