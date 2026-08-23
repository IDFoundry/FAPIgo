package jose

import (
	"bytes"
	"crypto"
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

// JWK is a parsed, validated public key together with the
// SignatureAlgorithm it is to be used with. There is no exported way to
// construct one from raw coordinates — only NewJWK (from a
// crypto.PublicKey the caller already trusts) or ParseJWK (which
// validates untrusted wire input) can produce one.
type JWK struct {
	pub crypto.PublicKey
	alg fapi.SignatureAlgorithm
	kid string
}

// NewJWK wraps pub for use with alg. It fails if pub's type or size does
// not match what alg requires.
func NewJWK(pub crypto.PublicKey, alg fapi.SignatureAlgorithm) (JWK, error) {
	if err := validateKeyForAlgorithm(pub, alg); err != nil {
		return JWK{}, err
	}
	return JWK{pub: pub, alg: alg}, nil
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

// Algorithm returns the algorithm this key is to be used with.
func (k JWK) Algorithm() fapi.SignatureAlgorithm { return k.alg }

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
	default:
		return Thumbprint{}, fmt.Errorf("jose: cannot compute thumbprint for key type %T", pub)
	}
	return Thumbprint(sha256.Sum256([]byte(canonical))), nil
}

// MarshalJSON encodes k as a public-only JWK containing exactly the
// members required for its key type, plus "kid" if WithKeyID was used.
func (k JWK) MarshalJSON() ([]byte, error) {
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		size := coordinateSize(pub.Curve)
		raw := rawJWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size))),
			Y:   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size))),
			Kid: k.kid,
		}
		return json.Marshal(raw)
	case *rsa.PublicKey:
		raw := rawJWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			Kid: k.kid,
		}
		return json.Marshal(raw)
	case ed25519.PublicKey:
		raw := rawJWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
			Kid: k.kid,
		}
		return json.Marshal(raw)
	default:
		return nil, fmt.Errorf("jose: cannot marshal key type %T", pub)
	}
}

// ParseJWK parses and validates a public JWK from untrusted wire data,
// checking it against alg. It rejects any member indicating private key
// material (e.g. "d", "k") or an embedded certificate chain ("x5c",
// "x5u", "x5t", "x5t#S256"), and rejects any member it does not
// recognize.
func ParseJWK(data []byte, alg fapi.SignatureAlgorithm) (JWK, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw rawJWK
	if err := dec.Decode(&raw); err != nil {
		return JWK{}, fmt.Errorf("jose: parse jwk: %w", err)
	}
	if raw.D != nil || raw.K != nil || raw.P != nil || raw.Q != nil ||
		raw.Dp != nil || raw.Dq != nil || raw.Qi != nil {
		return JWK{}, ErrPrivateKeyMaterial
	}
	if raw.X5c != nil || raw.X5u != nil || raw.X5t != nil || raw.X5tS256 != nil {
		return JWK{}, ErrCertificateChain
	}

	var pub crypto.PublicKey
	switch raw.Kty {
	case "EC":
		if raw.Crv != "P-256" {
			return JWK{}, fmt.Errorf("jose: unsupported EC curve %q", raw.Crv)
		}
		x, err := decodeCoordinate(raw.X)
		if err != nil {
			return JWK{}, fmt.Errorf("jose: decode jwk x: %w", err)
		}
		y, err := decodeCoordinate(raw.Y)
		if err != nil {
			return JWK{}, fmt.Errorf("jose: decode jwk y: %w", err)
		}
		curve := elliptic.P256()
		if x.Sign() == 0 && y.Sign() == 0 {
			return JWK{}, fmt.Errorf("jose: jwk ec point is the point at infinity")
		}
		if !curve.IsOnCurve(x, y) {
			return JWK{}, fmt.Errorf("jose: jwk ec point is not on curve P-256")
		}
		pub = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	case "RSA":
		n, err := decodeCoordinate(raw.N)
		if err != nil {
			return JWK{}, fmt.Errorf("jose: decode jwk n: %w", err)
		}
		e, err := decodeExponent(raw.E)
		if err != nil {
			return JWK{}, fmt.Errorf("jose: decode jwk e: %w", err)
		}
		pub = &rsa.PublicKey{N: n, E: e}
	case "OKP":
		if raw.Crv != "Ed25519" {
			return JWK{}, fmt.Errorf("jose: unsupported OKP curve %q", raw.Crv)
		}
		if raw.X == "" {
			return JWK{}, fmt.Errorf("jose: jwk x is required")
		}
		x, err := base64.RawURLEncoding.DecodeString(raw.X)
		if err != nil {
			return JWK{}, fmt.Errorf("jose: decode jwk x: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return JWK{}, fmt.Errorf("jose: jwk x must be %d bytes for Ed25519, got %d", ed25519.PublicKeySize, len(x))
		}
		pub = ed25519.PublicKey(x)
	default:
		return JWK{}, fmt.Errorf("jose: unsupported key type %q", raw.Kty)
	}

	if err := validateKeyForAlgorithm(pub, alg); err != nil {
		return JWK{}, err
	}
	return JWK{pub: pub, alg: alg}, nil
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

// rawJWK is the wire representation of a JWK (RFC 7517). Fields beyond
// the public-key members are listed explicitly so ParseJWK can detect
// and reject private-key or certificate-chain material by name, while
// DisallowUnknownFields rejects anything not listed here at all.
type rawJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`

	Use    string          `json:"use,omitempty"`
	KeyOps json.RawMessage `json:"key_ops,omitempty"`
	Alg    string          `json:"alg,omitempty"`
	Kid    string          `json:"kid,omitempty"`

	// Presence of any of the following indicates private key material
	// or an embedded certificate chain, neither of which is acceptable
	// in a public JWK used for DPoP or request-object verification.
	D  json.RawMessage `json:"d,omitempty"`
	K  json.RawMessage `json:"k,omitempty"`
	P  json.RawMessage `json:"p,omitempty"`
	Q  json.RawMessage `json:"q,omitempty"`
	Dp json.RawMessage `json:"dp,omitempty"`
	Dq json.RawMessage `json:"dq,omitempty"`
	Qi json.RawMessage `json:"qi,omitempty"`

	X5c     json.RawMessage `json:"x5c,omitempty"`
	X5u     json.RawMessage `json:"x5u,omitempty"`
	X5t     json.RawMessage `json:"x5t,omitempty"`
	X5tS256 json.RawMessage `json:"x5t#S256,omitempty"`
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
