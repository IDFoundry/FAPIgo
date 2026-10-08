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
	"github.com/idfoundry/fapigo/internal/jose"
)

// SignerSpec is one signing purpose's key for NewKeyManagerFromSigners:
// the purpose, the algorithm it signs with, the crypto.Signer that
// holds the key, and its kid — one value per purpose, so a purpose
// can't end up with a signer but no algorithm, or a kid for a purpose
// that has no signer.
type SignerSpec struct {
	// Purpose is the SigningPurpose this key serves. Required, and at
	// most one SignerSpec per purpose.
	Purpose SigningPurpose

	// Algorithm is the SignatureAlgorithm Signer signs with — needed to
	// route Digest vs SigningInput and choose crypto.SignerOpts (see
	// SigningRequest's own doc comment) without inspecting the signer's
	// concrete type, since a crypto.Signer wrapping an HSM/KMS key
	// exposes no more than Public() and Sign(). Required.
	Algorithm fapi.SignatureAlgorithm

	// Signer holds the key this purpose currently signs with. Required.
	Signer crypto.Signer

	// KeyID is the key's "kid". Empty derives one: the RFC 7638 JWK
	// thumbprint of Signer's public key (base64url, unpadded) — stable
	// for a given key, and different for every new key, so a rotation
	// never reuses a kid.
	KeyID string

	// Previous are the public halves of keys this purpose signed with
	// before Signer, still published (RotatingKeyManager.PublicKeys)
	// so a signature made with one stays verifiable until it expires —
	// a rotation's overlap window. Sign never uses them. Each must suit
	// Algorithm; an empty KeyID is derived as for KeyID. Drop a key from
	// Previous once nothing it signed can still be in use (e.g. after
	// the longest lifetime of anything signed for this purpose).
	Previous []PublicKeyInfo
}

// signerBackend pairs one purpose's crypto.Signer with the algorithm it
// signs under, its kid and the previous keys still published, resolved
// once at construction so Sign and PublicKey never have to re-derive
// anything from the signer's concrete type.
type signerBackend struct {
	signer    crypto.Signer
	algorithm fapi.SignatureAlgorithm
	kid       string
	previous  []PublicKeyInfo
}

// signerKeyManager implements RotatingKeyManager over a caller-supplied
// crypto.Signer per SigningPurpose. See NewKeyManagerFromSigners.
type signerKeyManager struct {
	backends map[SigningPurpose]signerBackend
}

// NewKeyManagerFromSigners builds a KeyManager over specs, one per
// SigningPurpose it should serve.
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
// Each signer's reported public key, and every previous key, is checked
// against its algorithm at construction time — including ES256's P-256
// curve requirement and PS256's 2048-bit modulus floor, the same floors
// this module enforces everywhere else — so a misconfigured backend
// fails at startup, not on the first signing request. So is the set as
// a whole: no purpose twice, and no kid naming two different keys.
//
// The KeyManager it returns is a RotatingKeyManager: PublicKeys
// publishes each purpose's current key followed by its
// SignerSpec.Previous keys, so rotating a key is a matter of moving the
// outgoing key's public half into Previous and building a new
// KeyManager with the incoming signer.
//
// Only the caller knows how the signers' keys are held, so pass
// DeclareCustody to say — required for production assurance (see
// KeyCustody). Without it, the KeyManager declares nothing and is
// accepted only under development assurance.
func NewKeyManagerFromSigners(specs []SignerSpec, opts ...CustodyOption) (KeyManager, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("keys: NewKeyManagerFromSigners requires at least one SignerSpec")
	}
	backends := make(map[SigningPurpose]signerBackend, len(specs))
	kids := make(map[string]crypto.PublicKey)
	for _, spec := range specs {
		backend, err := newSignerBackend(spec)
		if err != nil {
			return nil, err
		}
		if _, dup := backends[spec.Purpose]; dup {
			return nil, fmt.Errorf("keys: signing purpose %v appears in more than one SignerSpec", spec.Purpose)
		}
		if err := claimKeyID(kids, backend.kid, spec.Signer.Public()); err != nil {
			return nil, err
		}
		for _, prev := range backend.previous {
			if err := claimKeyID(kids, prev.KeyID, prev.PublicKey); err != nil {
				return nil, err
			}
		}
		backends[spec.Purpose] = backend
	}
	km := &signerKeyManager{backends: backends}
	if d := applyCustodyOptions(opts); d.declared {
		return custodyKeyManager{signerKeyManager: km, custody: d.custody}, nil
	}
	return km, nil
}

// newSignerBackend validates spec and resolves its kids.
func newSignerBackend(spec SignerSpec) (signerBackend, error) {
	if spec.Purpose == 0 {
		return signerBackend{}, fmt.Errorf("keys: a SignerSpec has no signing purpose")
	}
	if spec.Signer == nil {
		return signerBackend{}, fmt.Errorf("keys: nil signer for signing purpose %v", spec.Purpose)
	}
	if spec.Algorithm == 0 {
		return signerBackend{}, fmt.Errorf("keys: no algorithm specified for signing purpose %v", spec.Purpose)
	}
	kid, err := keyIDFor(spec.KeyID, spec.Signer.Public(), spec.Algorithm)
	if err != nil {
		return signerBackend{}, fmt.Errorf("keys: signing purpose %v: %w", spec.Purpose, err)
	}
	previous := make([]PublicKeyInfo, 0, len(spec.Previous))
	for i, prev := range spec.Previous {
		prevKID, err := keyIDFor(prev.KeyID, prev.PublicKey, spec.Algorithm)
		if err != nil {
			return signerBackend{}, fmt.Errorf("keys: signing purpose %v: previous key %d: %w", spec.Purpose, i, err)
		}
		previous = append(previous, PublicKeyInfo{KeyID: prevKID, PublicKey: prev.PublicKey})
	}
	return signerBackend{signer: spec.Signer, algorithm: spec.Algorithm, kid: kid, previous: previous}, nil
}

// keyIDFor checks pub against algorithm and returns kid, or, when kid
// is empty, pub's RFC 7638 JWK thumbprint.
func keyIDFor(kid string, pub crypto.PublicKey, algorithm fapi.SignatureAlgorithm) (string, error) {
	if err := validatePublicKeyForAlgorithm(pub, algorithm); err != nil {
		return "", err
	}
	if kid != "" {
		return kid, nil
	}
	jwk, err := jose.NewJWK(pub, algorithm)
	if err != nil {
		return "", err
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		return "", err
	}
	return thumbprint.String(), nil
}

// claimKeyID records kid as naming pub, refusing a kid already naming a
// different key — a JWK Set publishing both would leave a verifier
// unable to choose between them (RFC 7517 §4.5). The same key under the
// same kid, e.g. one key serving two purposes, is fine.
func claimKeyID(kids map[string]crypto.PublicKey, kid string, pub crypto.PublicKey) error {
	if existing, ok := kids[kid]; ok {
		if eq, ok := existing.(interface{ Equal(crypto.PublicKey) bool }); ok && eq.Equal(pub) {
			return nil
		}
		return fmt.Errorf("keys: kid %q names two different keys; give each key its own kid", kid)
	}
	kids[kid] = pub
	return nil
}

// custodyKeyManager is a signerKeyManager whose caller declared its
// KeyCustody.
type custodyKeyManager struct {
	*signerKeyManager
	custody KeyCustody
}

// KeyCustody implements KeyCustodyAssurance.
func (m custodyKeyManager) KeyCustody() KeyCustody { return m.custody }

func validatePublicKeyForAlgorithm(public crypto.PublicKey, algorithm fapi.SignatureAlgorithm) error {
	switch algorithm {
	case fapi.ES256:
		pub, ok := public.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ES256 requires an *ecdsa.PublicKey, got %T", public)
		}
		if pub.Curve != elliptic.P256() {
			return fmt.Errorf("ES256 requires a P-256 key")
		}
	case fapi.PS256:
		pub, ok := public.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("PS256 requires an *rsa.PublicKey, got %T", public)
		}
		if pub.N == nil || pub.N.BitLen() < minRSAModulusBits {
			return fmt.Errorf("PS256 requires an RSA key of at least %d bits", minRSAModulusBits)
		}
	case fapi.EdDSA:
		if _, ok := public.(ed25519.PublicKey); !ok {
			return fmt.Errorf("EdDSA requires an ed25519.PublicKey, got %T", public)
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

// PublicKeys implements RotatingKeyManager: purpose's current key, then
// its SignerSpec.Previous keys.
func (m *signerKeyManager) PublicKeys(_ context.Context, purpose SigningPurpose, _ fapi.SignatureAlgorithm) (SigningKeySet, error) {
	backend, ok := m.backends[purpose]
	if !ok {
		return SigningKeySet{}, fmt.Errorf("keys: no signer configured for signing purpose %v", purpose)
	}
	set := SigningKeySet{Keys: make([]PublicKeyInfo, 0, 1+len(backend.previous))}
	set.Keys = append(set.Keys, PublicKeyInfo{KeyID: backend.kid, PublicKey: backend.signer.Public()})
	set.Keys = append(set.Keys, backend.previous...)
	return set, nil
}
