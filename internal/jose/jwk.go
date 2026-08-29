package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	fapi "github.com/idfoundry/fapigo"
)

// JWK is a parsed, validated public key together with the algorithm it
// is to be used with, and which RFC 7517 §4.2 "use" it was built for.
// There is no exported way to construct one from raw coordinates — only
// NewJWK/NewEncryptionJWK (from a crypto.PublicKey the caller already
// trusts) or ParseJWK (which validates untrusted wire input) can
// produce one. Exactly one of sigAlg/encAlg is meaningful, chosen by
// use — the same "exactly one of these is populated, selected by a
// discriminator" shape keys.SigningRequest's own Digest/SigningInput
// split uses, for the same reason: a signing-use JWK and an
// encryption-use JWK are never interchangeable, so nothing here should
// let a caller read the wrong one by accident.
type JWK struct {
	pub    crypto.PublicKey
	use    jwkUse
	sigAlg fapi.SignatureAlgorithm
	encAlg fapi.KeyManagementAlgorithm
	kid    string
}

// jwkUse is RFC 7517 §4.2's "use" member, restricted to the two values
// this package ever produces.
type jwkUse string

const (
	jwkUseSignature  jwkUse = "sig"
	jwkUseEncryption jwkUse = "enc"
)

// NewJWK wraps pub for use with alg (a "use":"sig" JWK). It fails if
// pub's type or size does not match what alg requires.
func NewJWK(pub crypto.PublicKey, alg fapi.SignatureAlgorithm) (JWK, error) {
	if err := validateKeyForAlgorithm(pub, alg); err != nil {
		return JWK{}, err
	}
	return JWK{pub: pub, use: jwkUseSignature, sigAlg: alg}, nil
}

// NewEncryptionJWK wraps pub for use with alg (a "use":"enc" JWK) —
// RSAOAEP256 (an *rsa.PublicKey) or ECDHESA256KW (an *ecdh.PublicKey on
// curve P-256). It fails if pub's type, curve, or size does not match
// what alg requires.
func NewEncryptionJWK(pub crypto.PublicKey, alg fapi.KeyManagementAlgorithm) (JWK, error) {
	if err := validateKeyForKeyManagementAlgorithm(pub, alg); err != nil {
		return JWK{}, err
	}
	return JWK{pub: pub, use: jwkUseEncryption, encAlg: alg}, nil
}

// WithKeyID returns a copy of k with its "kid" member set to kid, so it
// appears in MarshalJSON's output. It exists for publishing a key in a
// JWKS document, where kid lets a verifier choose the right key; a JWK
// embedded directly in a JWS header (DPoP, request objects) doesn't need
// this — a kid there, if present, belongs in the surrounding JWS header
// instead, not duplicated into the embedded key.
func (k JWK) WithKeyID(kid string) JWK {
	k.kid = kid
	return k
}

// PublicKey returns the wrapped public key.
func (k JWK) PublicKey() crypto.PublicKey { return k.pub }

// Algorithm returns the algorithm this key is to be used with. Only
// meaningful for a JWK built by NewJWK/ParseJWK — the zero
// SignatureAlgorithm for one built by NewEncryptionJWK.
func (k JWK) Algorithm() fapi.SignatureAlgorithm { return k.sigAlg }

// algString returns the JOSE "alg" header value to marshal, drawn from
// whichever of sigAlg/encAlg use actually selects.
func (k JWK) algString() string {
	if k.use == jwkUseEncryption {
		return k.encAlg.String()
	}
	return k.sigAlg.String()
}

// Thumbprint computes the RFC 7638 JWK thumbprint: the SHA-256 digest of
// the key's required members, serialized with no whitespace and in
// lexicographic member-name order.
func (k JWK) Thumbprint() (Thumbprint, error) {
	var canonical string
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		size := coordinateSize(pub.Curve)
		x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size)))
		y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size)))
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, "P-256", x, y)
	case *rsa.PublicKey:
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
	case ed25519.PublicKey:
		// RFC 8037 §2's required OKP members, in the RFC 7638 §3.2
		// lexicographic order this thumbprint format requires: crv,
		// kty, x.
		x := base64.RawURLEncoding.EncodeToString(pub)
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, "Ed25519", x)
	case *ecdh.PublicKey:
		x, y, err := ecdhP256Coordinates(pub)
		if err != nil {
			return Thumbprint{}, fmt.Errorf("jose: %w", err)
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, "P-256",
			base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
	default:
		return Thumbprint{}, fmt.Errorf("jose: cannot compute thumbprint for key type %T", pub)
	}
	return Thumbprint(sha256.Sum256([]byte(canonical))), nil
}

// MarshalJSON encodes k as a public-only JWK containing exactly the
// members required for its key type, plus "use" and "alg" (see
// algString), plus "kid" if WithKeyID was used.
func (k JWK) MarshalJSON() ([]byte, error) {
	use, alg := string(k.use), k.algString()
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		size := coordinateSize(pub.Curve)
		raw := rawJWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size))),
			Y:   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size))),
			Use: use, Alg: alg, Kid: k.kid,
		}
		return json.Marshal(raw)
	case *rsa.PublicKey:
		raw := rawJWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			Use: use, Alg: alg, Kid: k.kid,
		}
		return json.Marshal(raw)
	case ed25519.PublicKey:
		raw := rawJWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
			Use: use, Alg: alg, Kid: k.kid,
		}
		return json.Marshal(raw)
	case *ecdh.PublicKey:
		x, y, err := ecdhP256Coordinates(pub)
		if err != nil {
			return nil, fmt.Errorf("jose: %w", err)
		}
		raw := rawJWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(x),
			Y:   base64.RawURLEncoding.EncodeToString(y),
			Use: use, Alg: alg, Kid: k.kid,
		}
		return json.Marshal(raw)
	default:
		return nil, fmt.Errorf("jose: cannot marshal key type %T", pub)
	}
}

// ecdhP256Coordinates extracts the X and Y coordinates from pub, which
// must be on curve P-256 — the only curve ECDHESA256KW supports.
// crypto/ecdh has no coordinate accessor of its own (deliberately: it
// keeps point representation curve-specific), so this decodes
// PublicKey.Bytes()'s uncompressed SEC1 point encoding (0x04 || X || Y,
// each a fixed 32 bytes for P-256) directly.
func ecdhP256Coordinates(pub *ecdh.PublicKey) (x, y []byte, err error) {
	if pub.Curve() != ecdh.P256() {
		return nil, nil, fmt.Errorf("cannot encode ecdh key on curve %v as a JWK: only P-256 is supported", pub.Curve())
	}
	raw := pub.Bytes()
	const uncompressedP256Len = 1 + 32 + 32
	if len(raw) != uncompressedP256Len {
		return nil, nil, fmt.Errorf("unexpected P-256 public key encoding length %d, want %d", len(raw), uncompressedP256Len)
	}
	if raw[0] != 0x04 {
		return nil, nil, fmt.Errorf("unexpected P-256 public key encoding: leading byte 0x%02x, want 0x04 (uncompressed)", raw[0])
	}
	return raw[1:33], raw[33:65], nil
}

// ParseJWK parses and validates a public JWK from untrusted wire data,
// checking it against alg. It rejects any member indicating private
// key material (e.g. "d", "k") — a "public" JWK unexpectedly carrying
// that is either a server bug leaking private keys or actively
// malicious, not something to tolerate. Every other member this
// package doesn't act on (e.g. "x5c", "x5u", "x5t", "x5t#S256", "use")
// is ignored, not rejected: RFC 7517 §4 requires exactly this —
// "Additional members can be present in the JWK; if not understood by
// implementations encountering them, they MUST be ignored" — and this
// package never resolves a key via its certificate chain, so an x5c
// present alongside otherwise-valid key material changes nothing about
// which key gets used.
func ParseJWK(data []byte, alg fapi.SignatureAlgorithm) (JWK, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var raw rawJWK
	if err := dec.Decode(&raw); err != nil {
		return JWK{}, fmt.Errorf("jose: parse jwk: %w", err)
	}
	if raw.D != nil || raw.K != nil || raw.P != nil || raw.Q != nil ||
		raw.Dp != nil || raw.Dq != nil || raw.Qi != nil {
		return JWK{}, ErrPrivateKeyMaterial
	}

	var pub crypto.PublicKey
	var err error
	switch raw.Kty {
	case "EC":
		pub, err = parseECPublicKey(raw)
	case "RSA":
		pub, err = parseRSAPublicKey(raw)
	case "OKP":
		pub, err = parseOKPPublicKey(raw)
	default:
		err = fmt.Errorf("jose: unsupported key type %q", raw.Kty)
	}
	if err != nil {
		return JWK{}, err
	}

	if err := validateKeyForAlgorithm(pub, alg); err != nil {
		return JWK{}, err
	}
	return JWK{pub: pub, use: jwkUseSignature, sigAlg: alg}, nil
}

func parseECPublicKey(raw rawJWK) (crypto.PublicKey, error) {
	if raw.Crv != "P-256" {
		return nil, fmt.Errorf("jose: unsupported EC curve %q", raw.Crv)
	}
	x, err := decodeCoordinate(raw.X)
	if err != nil {
		return nil, fmt.Errorf("jose: decode jwk x: %w", err)
	}
	y, err := decodeCoordinate(raw.Y)
	if err != nil {
		return nil, fmt.Errorf("jose: decode jwk y: %w", err)
	}
	curve := elliptic.P256()
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, fmt.Errorf("jose: jwk ec point is the point at infinity")
	}
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("jose: jwk ec point is not on curve P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func parseRSAPublicKey(raw rawJWK) (crypto.PublicKey, error) {
	n, err := decodeCoordinate(raw.N)
	if err != nil {
		return nil, fmt.Errorf("jose: decode jwk n: %w", err)
	}
	e, err := decodeExponent(raw.E)
	if err != nil {
		return nil, fmt.Errorf("jose: decode jwk e: %w", err)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseOKPPublicKey(raw rawJWK) (crypto.PublicKey, error) {
	if raw.Crv != "Ed25519" {
		return nil, fmt.Errorf("jose: unsupported OKP curve %q", raw.Crv)
	}
	if raw.X == "" {
		return nil, fmt.Errorf("jose: jwk x is required")
	}
	x, err := base64.RawURLEncoding.DecodeString(raw.X)
	if err != nil {
		return nil, fmt.Errorf("jose: decode jwk x: %w", err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jose: jwk x must be %d bytes for Ed25519, got %d", ed25519.PublicKeySize, len(x))
	}
	return ed25519.PublicKey(x), nil
}

// Thumbprint is an RFC 7638 JWK thumbprint.
type Thumbprint [32]byte

// String returns the base64url (no padding) encoding of t.
func (t Thumbprint) String() string {
	return base64.RawURLEncoding.EncodeToString(t[:])
}

// Equal reports whether t and other are the same thumbprint.
func (t Thumbprint) Equal(other Thumbprint) bool {
	return t == other
}

// rawJWK is the wire representation of a JWK (RFC 7517). Only the
// public-key members this package acts on, plus the private-key
// members it explicitly checks for and rejects, are listed here —
// every other member (certificate-chain hints, "key_ops", ...) is left
// for encoding/json's own default behavior (silently ignored) rather
// than modeled, per RFC 7517 §4's own ignore-unknown-members rule; see
// ParseJWK's doc comment. "use" is marshaled (MarshalJSON sets it from
// JWK.use) but still not read back on parse — ParseJWK's caller already
// states which alg/purpose it expects a JWK to satisfy, the same way
// every other role-declared expectation in this module isn't
// re-derived from untrusted input.
type rawJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`

	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	// Presence of any of the following indicates private key material,
	// not acceptable in a public JWK used for DPoP or request-object
	// verification.
	D  json.RawMessage `json:"d,omitempty"`
	K  json.RawMessage `json:"k,omitempty"`
	P  json.RawMessage `json:"p,omitempty"`
	Q  json.RawMessage `json:"q,omitempty"`
	Dp json.RawMessage `json:"dp,omitempty"`
	Dq json.RawMessage `json:"dq,omitempty"`
	Qi json.RawMessage `json:"qi,omitempty"`
}

func validateKeyForAlgorithm(pub crypto.PublicKey, alg fapi.SignatureAlgorithm) error {
	switch alg {
	case fapi.ES256:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("jose: ES256 requires an ECDSA public key, got %T", pub)
		}
		if key.Curve != elliptic.P256() {
			return fmt.Errorf("jose: ES256 requires curve P-256")
		}
	case fapi.PS256:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("jose: PS256 requires an RSA public key, got %T", pub)
		}
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("jose: PS256 requires an RSA key of at least 2048 bits, got %d", key.N.BitLen())
		}
	case fapi.EdDSA:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("jose: EdDSA requires an Ed25519 public key, got %T", pub)
		}
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("jose: EdDSA requires a %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(key))
		}
	default:
		return fmt.Errorf("jose: unsupported algorithm %v", alg)
	}
	return nil
}

// validateKeyForKeyManagementAlgorithm is validateKeyForAlgorithm's
// counterpart for the two fapi.KeyManagementAlgorithm values this
// module supports (RSAOAEP256, ECDHESA256KW) rather than the three
// fapi.SignatureAlgorithm ones — a different closed set, since a
// signing key and a key-management key are never interchangeable even
// when they happen to share a Go type (RSA does; EC/ECDH don't, since
// *ecdsa.PublicKey and *ecdh.PublicKey are distinct types for the same
// curve).
func validateKeyForKeyManagementAlgorithm(pub crypto.PublicKey, alg fapi.KeyManagementAlgorithm) error {
	switch alg {
	case fapi.RSAOAEP256:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("jose: RSAOAEP256 requires an RSA public key, got %T", pub)
		}
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("jose: RSAOAEP256 requires an RSA key of at least 2048 bits, got %d", key.N.BitLen())
		}
	case fapi.ECDHESA256KW:
		key, ok := pub.(*ecdh.PublicKey)
		if !ok {
			return fmt.Errorf("jose: ECDHESA256KW requires an ECDH public key, got %T", pub)
		}
		if key.Curve() != ecdh.P256() {
			return fmt.Errorf("jose: ECDHESA256KW requires curve P-256")
		}
	default:
		return fmt.Errorf("jose: unsupported key management algorithm %v", alg)
	}
	return nil
}

func coordinateSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

func decodeCoordinate(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func decodeExponent(s string) (int, error) {
	n, err := decodeCoordinate(s)
	if err != nil {
		return 0, err
	}
	if !n.IsInt64() {
		return 0, fmt.Errorf("exponent out of range")
	}
	v := n.Int64()
	if v < 3 || v > 1<<31-1 || v%2 == 0 {
		return 0, fmt.Errorf("exponent out of range or not a valid RSA public exponent")
	}
	return int(v), nil
}
