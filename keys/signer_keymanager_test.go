package keys_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// TestNewKeyManagerFromSignersRoundTripES256 proves a KeyManager built
// directly over a stdlib *ecdsa.PrivateKey — which already implements
// crypto.Signer, no adapter needed — produces a signature that verifies
// against the reported public key, and confirms *ecdsa.PrivateKey.Sign
// already returns the ASN.1 DER format Signature.Value requires.
func TestNewKeyManagerFromSignersRoundTripES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	m, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: priv, KeyID: "es256-kid"},
		},
	)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}

	digest := sha256.Sum256([]byte("hello"))
	sig, err := m.Sign(context.Background(), keys.SigningRequest{
		Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Digest: digest[:],
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.KeyID != "es256-kid" {
		t.Fatalf("KeyID = %q, want %q", sig.KeyID, "es256-kid")
	}

	info, err := m.PublicKey(context.Background(), keys.AccessTokenSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pub, ok := info.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *ecdsa.PublicKey", info.PublicKey)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig.Value) {
		t.Fatal("signature does not verify against PublicKey's own reported key")
	}
}

// TestNewKeyManagerFromSignersRoundTripPS256 mirrors the ES256 test for
// PS256, confirming the RSA-PSS options this package supplies match
// what internal/jose's own signer verifies against.
func TestNewKeyManagerFromSignersRoundTripPS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	m, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.ClientAuthentication, Algorithm: fapi.PS256, Signer: priv},
		},
	)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}

	digest := sha256.Sum256([]byte("hello"))
	sig, err := m.Sign(context.Background(), keys.SigningRequest{
		Purpose: keys.ClientAuthentication, Algorithm: fapi.PS256, Digest: digest[:],
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	info, err := m.PublicKey(context.Background(), keys.ClientAuthentication, fapi.PS256)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pub, ok := info.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *rsa.PublicKey", info.PublicKey)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig.Value, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatalf("signature does not verify against PublicKey's own reported key: %v", err)
	}
}

// TestNewKeyManagerFromSignersRoundTripEdDSA confirms the raw,
// unhashed SigningInput reaches Sign as pure Ed25519 (opts.HashFunc()
// == crypto.Hash(0)), not Ed25519ph.
func TestNewKeyManagerFromSignersRoundTripEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	m, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.RequestObjectSigning, Algorithm: fapi.EdDSA, Signer: priv},
		},
	)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}

	message := []byte("hello")
	sig, err := m.Sign(context.Background(), keys.SigningRequest{
		Purpose: keys.RequestObjectSigning, Algorithm: fapi.EdDSA, SigningInput: message,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, message, sig.Value) {
		t.Fatal("signature does not verify against the reported public key")
	}
}

func TestNewKeyManagerFromSignersRejectsEmptySigners(t *testing.T) {
	if _, err := keys.NewKeyManagerFromSigners(nil); err == nil {
		t.Fatal("NewKeyManagerFromSigners(nil) = nil error, want error")
	}
}

func TestNewKeyManagerFromSignersRejectsNilSigner(t *testing.T) {
	if _, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: nil},
		},
	); err == nil {
		t.Fatal("NewKeyManagerFromSigners(nil signer) = nil error, want error")
	}
}

func TestNewKeyManagerFromSignersRejectsMissingAlgorithm(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	if _, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.AccessTokenSigning, Signer: priv},
		},
	); err == nil {
		t.Fatal("NewKeyManagerFromSigners(no algorithm) = nil error, want error")
	}
}

// TestNewKeyManagerFromSignersRejectsWrongKeyType confirms an RSA key
// registered for ES256 (or vice versa) fails at construction, not on
// the first Sign call.
func TestNewKeyManagerFromSignersRejectsWrongKeyType(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	if _, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: priv},
		},
	); err == nil {
		t.Fatal("NewKeyManagerFromSigners(rsa key for ES256) = nil error, want error")
	}
}

func TestNewKeyManagerFromSignersRejectsNonP256Curve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p-384 key: %v", err)
	}
	if _, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: priv},
		},
	); err == nil {
		t.Fatal("NewKeyManagerFromSigners(P-384 key for ES256) = nil error, want error")
	}
}

func TestNewKeyManagerFromSignersRejectsSmallRSAKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate 1024-bit rsa key: %v", err)
	}
	if _, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.ClientAuthentication, Algorithm: fapi.PS256, Signer: priv},
		},
	); err == nil {
		t.Fatal("NewKeyManagerFromSigners(1024-bit rsa key) = nil error, want error")
	}
}

func TestNewKeyManagerFromSignersSignRejectsUnconfiguredPurpose(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	m, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: priv},
		},
	)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	if _, err := m.Sign(context.Background(), keys.SigningRequest{
		Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Digest: []byte("x"),
	}); err == nil {
		t.Fatal("Sign(unconfigured purpose) = nil error, want error")
	}
	if _, err := m.PublicKey(context.Background(), keys.IDTokenSigning, fapi.ES256); err == nil {
		t.Fatal("PublicKey(unconfigured purpose) = nil error, want error")
	}
}

// TestNewKeyManagerFromSignersSignRejectsAlgorithmMismatch confirms a
// request for a different algorithm than the purpose was configured
// with is rejected rather than silently signed with the wrong scheme.
func TestNewKeyManagerFromSignersSignRejectsAlgorithmMismatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	m, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: priv},
		},
	)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	if _, err := m.Sign(context.Background(), keys.SigningRequest{
		Purpose: keys.AccessTokenSigning, Algorithm: fapi.PS256, Digest: []byte("x"),
	}); err == nil {
		t.Fatal("Sign(algorithm mismatch) = nil error, want error")
	}
}

// TestNewKeyManagerFromSignersDerivesKeyID: an empty KeyID becomes the
// RFC 7638 thumbprint of the signer's public key — the kid a published
// JWK for that key would have — so each new key gets its own kid.
func TestNewKeyManagerFromSignersDerivesKeyID(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa key: %v", err)
		}
		return priv
	}
	kidOf := func(priv crypto.Signer) string {
		m, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
			{Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: priv},
		})
		if err != nil {
			t.Fatalf("NewKeyManagerFromSigners: %v", err)
		}
		info, err := m.PublicKey(context.Background(), keys.IDTokenSigning, fapi.ES256)
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		return info.KeyID
	}
	priv := newKey()
	first, again, other := kidOf(priv), kidOf(priv), kidOf(newKey())
	if first == "" || first != again {
		t.Fatalf("derived kid = %q then %q, want the same non-empty kid for the same key", first, again)
	}
	if first == other {
		t.Fatalf("two different keys derived the same kid %q", first)
	}

	// The thumbprint is the one PublicJWKS's own JWK for the key has.
	pub := priv.Public().(*ecdsa.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32)))
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); first != want {
		t.Fatalf("derived kid = %q, want the RFC 7638 thumbprint %q", first, want)
	}
}

// TestNewKeyManagerFromSignersPublishesPreviousKeys: a purpose's
// Previous keys are published after its current one, so a signature
// made before a rotation stays verifiable; Sign still uses only the
// current key.
func TestNewKeyManagerFromSignersPublishesPreviousKeys(t *testing.T) {
	current, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	outgoing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	m, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{{
		Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: current, KeyID: "k2",
		Previous: []keys.PublicKeyInfo{{KeyID: "k1", PublicKey: outgoing.Public()}},
	}})
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	rotating, ok := m.(keys.RotatingKeyManager)
	if !ok {
		t.Fatal("KeyManager is not a keys.RotatingKeyManager")
	}
	set, err := rotating.PublicKeys(context.Background(), keys.IDTokenSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	if len(set.Keys) != 2 || set.Keys[0].KeyID != "k2" || set.Keys[1].KeyID != "k1" {
		t.Fatalf("PublicKeys = %+v, want k2 then k1", set.Keys)
	}
	jwks, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{
		{Manager: m, Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256},
	}, nil)
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("PublicJWKS published %d keys, want 2", len(jwks.Keys))
	}
	sig, err := m.Sign(context.Background(), keys.NewSigningRequest(keys.IDTokenSigning, fapi.ES256, make([]byte, 32)))
	if err != nil || sig.KeyID != "k2" {
		t.Fatalf("Sign = kid %q, %v; want the current key, k2", sig.KeyID, err)
	}
}

// TestNewKeyManagerFromSignersRefusesInconsistentSpecs covers the
// refusals a per-purpose spec makes possible at construction.
func TestNewKeyManagerFromSignersRefusesInconsistentSpecs(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa key: %v", err)
		}
		return priv
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	a, b := newKey(), newKey()
	for name, specs := range map[string][]keys.SignerSpec{
		"no purpose": {{Algorithm: fapi.ES256, Signer: a}},
		"one purpose twice": {
			{Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: a},
			{Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: b},
		},
		"one kid for two keys": {
			{Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: a, KeyID: "k"},
			{Purpose: keys.JARMSigning, Algorithm: fapi.ES256, Signer: b, KeyID: "k"},
		},
		"previous key with the current kid": {{
			Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: a, KeyID: "k",
			Previous: []keys.PublicKeyInfo{{KeyID: "k", PublicKey: b.Public()}},
		}},
		"previous key of the wrong type": {{
			Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: a,
			Previous: []keys.PublicKeyInfo{{KeyID: "old", PublicKey: rsaKey.Public()}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := keys.NewKeyManagerFromSigners(specs); err == nil {
				t.Fatal("NewKeyManagerFromSigners = nil error, want it refused")
			}
		})
	}

	// One key serving two purposes under one kid is fine.
	if _, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
		{Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: a, KeyID: "shared"},
		{Purpose: keys.JARMSigning, Algorithm: fapi.ES256, Signer: a, KeyID: "shared"},
	}); err != nil {
		t.Fatalf("NewKeyManagerFromSigners(one key, two purposes) = %v, want nil", err)
	}
}

func TestSigningPurposeString(t *testing.T) {
	if got := keys.IDTokenSigning.String(); got != "id_token_signing" {
		t.Fatalf("IDTokenSigning.String() = %q", got)
	}
	if got := keys.SigningPurpose(200).String(); got != "signing_purpose(200)" {
		t.Fatalf("SigningPurpose(200).String() = %q", got)
	}
}
