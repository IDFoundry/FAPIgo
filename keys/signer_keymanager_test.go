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
		map[keys.SigningPurpose]crypto.Signer{keys.AccessTokenSigning: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256},
		map[keys.SigningPurpose]string{keys.AccessTokenSigning: "es256-kid"},
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
		map[keys.SigningPurpose]crypto.Signer{keys.ClientAuthentication: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAuthentication: fapi.PS256},
		nil,
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
		map[keys.SigningPurpose]crypto.Signer{keys.RequestObjectSigning: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.RequestObjectSigning: fapi.EdDSA},
		nil,
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
	if _, err := keys.NewKeyManagerFromSigners(nil, nil, nil); err == nil {
		t.Fatal("NewKeyManagerFromSigners(nil) = nil error, want error")
	}
}

func TestNewKeyManagerFromSignersRejectsNilSigner(t *testing.T) {
	if _, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.AccessTokenSigning: nil},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256},
		nil,
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
		map[keys.SigningPurpose]crypto.Signer{keys.AccessTokenSigning: priv}, nil, nil,
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
		map[keys.SigningPurpose]crypto.Signer{keys.AccessTokenSigning: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256},
		nil,
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
		map[keys.SigningPurpose]crypto.Signer{keys.AccessTokenSigning: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256},
		nil,
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
		map[keys.SigningPurpose]crypto.Signer{keys.ClientAuthentication: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAuthentication: fapi.PS256},
		nil,
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
		map[keys.SigningPurpose]crypto.Signer{keys.AccessTokenSigning: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256},
		nil,
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
		map[keys.SigningPurpose]crypto.Signer{keys.AccessTokenSigning: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256},
		nil,
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
