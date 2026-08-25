package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// signerBackend pairs one purpose's crypto.Signer with the algorithm it
// signs under and its kid, resolved once at construction so Sign and
// PublicKey never have to re-derive the algorithm from the signer's
// concrete type.
type signerBackend struct {
	signer    crypto.Signer
	algorithm fapi.SignatureAlgorithm
	kid       string
}

// signerKeyManager implements KeyManager over a caller-supplied
// crypto.Signer per SigningPurpose. See NewKeyManagerFromSigners.
type signerKeyManager struct {
	backends map[SigningPurpose]signerBackend
}

// NewKeyManagerFromSigners builds a KeyManager over signers, one per
// SigningPurpose it should serve, and algorithms, the SignatureAlgorithm
// each purpose signs with — needed to route Digest vs SigningInput and
// choose crypto.SignerOpts (see SigningRequest's own doc comment)
// without inspecting the signer's concrete type, since a crypto.Signer
// wrapping an HSM/KMS key exposes no more than Public() and Sign(). kids
// supplies each purpose's "kid"; a purpose absent from kids gets an
// empty one.
//
// crypto.Signer is Go's own "delegate the primitive, not the key"
// abstraction, and it's what most HSM/KMS Go client wrappers already
// implement (PKCS#11 wrappers, cloud KMS wrapper libraries) — so this
// constructor gets both a static in-memory key (an *ecdsa.PrivateKey,
// *rsa.PrivateKey, or ed25519.PrivateKey all implement crypto.Signer
// directly) and an arbitrary KMS/HSM-backed signer working as a
// KeyManager, with no FAPIgo-specific glue code in either case.
//
// Every algorithm this module supports maps onto crypto.Signer.Sign
// exactly: *ecdsa.PrivateKey.Sign already returns ASN.1 DER — the
// format Signature.Value requires — *rsa.PrivateKey.Sign with the PSS
// options this function supplies already performs RSA-PSS, and
// ed25519.PrivateKey.Sign with crypto.Hash(0) already signs the raw
// message pure EdDSA requires. A third-party crypto.Signer is expected
// to honor that same Go convention; one that doesn't (e.g. a backend
// that returns raw R||S instead of ASN.1 DER for ECDSA) needs to be
// fixed in that wrapper, not worked around here.
//
// Each signer's reported public key is checked against its algorithm at
// construction time — including ES256's P-256 curve requirement and
// PS256's 2048-bit modulus floor, the same floors this module enforces
// everywhere else — so a misconfigured backend fails at startup, not on
// the first signing request.
func NewKeyManagerFromSigners(
	signers map[SigningPurpose]crypto.Signer,
	algorithms map[SigningPurpose]fapi.SignatureAlgorithm,
	kids map[SigningPurpose]string,
) (KeyManager, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("keys: NewKeyManagerFromSigners requires at least one signer")
	}
	backends := make(map[SigningPurpose]signerBackend, len(signers))
	for purpose, signer := range signers {
		if signer == nil {
			return nil, fmt.Errorf("keys: nil signer for signing purpose %v", purpose)
		}
		algorithm, ok := algorithms[purpose]
		if !ok {
			return nil, fmt.Errorf("keys: no algorithm specified for signing purpose %v", purpose)
		}
		if err := validateSignerForAlgorithm(signer, algorithm); err != nil {
			return nil, fmt.Errorf("keys: signing purpose %v: %w", purpose, err)
		}
		backends[purpose] = signerBackend{signer: signer, algorithm: algorithm, kid: kids[purpose]}
	}
	return &signerKeyManager{backends: backends}, nil
}

func validateSignerForAlgorithm(signer crypto.Signer, algorithm fapi.SignatureAlgorithm) error {
	switch algorithm {
	case fapi.ES256:
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ES256 requires an *ecdsa.PublicKey, got %T", signer.Public())
		}
		if pub.Curve != elliptic.P256() {
			return fmt.Errorf("ES256 requires a P-256 key")
		}
	case fapi.PS256:
		pub, ok := signer.Public().(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("PS256 requires an *rsa.PublicKey, got %T", signer.Public())
		}
		if pub.N == nil || pub.N.BitLen() < minRSAModulusBits {
			return fmt.Errorf("PS256 requires an RSA key of at least %d bits", minRSAModulusBits)
		}
	case fapi.EdDSA:
		if _, ok := signer.Public().(ed25519.PublicKey); !ok {
			return fmt.Errorf("EdDSA requires an ed25519.PublicKey, got %T", signer.Public())
		}
	default:
		return fmt.Errorf("unsupported signature algorithm %v", algorithm)
	}
	return nil
}

// Sign implements KeyManager.
func (m *signerKeyManager) Sign(_ context.Context, req SigningRequest) (Signature, error) {
	backend, ok := m.backends[req.Purpose]
	if !ok {
		return Signature{}, fmt.Errorf("keys: no signer configured for signing purpose %v", req.Purpose)
	}
	if req.Algorithm != backend.algorithm {
		return Signature{}, fmt.Errorf("keys: signing purpose %v is configured for %v, got a request for %v", req.Purpose, backend.algorithm, req.Algorithm)
	}

	switch req.Algorithm {
	case fapi.ES256:
		sig, err := backend.signer.Sign(rand.Reader, req.Digest, crypto.SHA256)
		if err != nil {
			return Signature{}, fmt.Errorf("keys: es256 sign: %w", err)
		}
		return Signature{KeyID: backend.kid, Value: sig}, nil

	case fapi.PS256:
		sig, err := backend.signer.Sign(rand.Reader, req.Digest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return Signature{}, fmt.Errorf("keys: ps256 sign: %w", err)
		}
		return Signature{KeyID: backend.kid, Value: sig}, nil

	case fapi.EdDSA:
		// crypto.Hash(0) signals pure Ed25519 (RFC 8037 §3.1), not
		// Ed25519ph — the message is req.SigningInput, unhashed, per
		// SigningRequest's own doc comment.
		sig, err := backend.signer.Sign(rand.Reader, req.SigningInput, crypto.Hash(0))
		if err != nil {
			return Signature{}, fmt.Errorf("keys: eddsa sign: %w", err)
		}
		return Signature{KeyID: backend.kid, Value: sig}, nil

	default:
		return Signature{}, fmt.Errorf("keys: unsupported signature algorithm %v", req.Algorithm)
	}
}

// PublicKey implements KeyManager.
func (m *signerKeyManager) PublicKey(_ context.Context, purpose SigningPurpose, _ fapi.SignatureAlgorithm) (PublicKeyInfo, error) {
	backend, ok := m.backends[purpose]
	if !ok {
		return PublicKeyInfo{}, fmt.Errorf("keys: no signer configured for signing purpose %v", purpose)
	}
	return PublicKeyInfo{KeyID: backend.kid, PublicKey: backend.signer.Public()}, nil
}
