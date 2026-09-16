package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// historicalKeysJWTType is the JWS "typ" header value every Federation
// Historical Keys response JWT MUST carry (OpenID Federation 1.0
// §8.7.2: "explicitly typed by setting the typ header parameter to
// jwk-set+jwt to prevent cross-JWT confusion, per Section 3.11 of
// [RFC8725]. Historical keys JWTs without a typ header parameter or
// with a different typ value MUST be rejected").
const historicalKeysJWTType = "jwk-set+jwt"

// KeyRevocationReason is a HistoricalKey's own "revoked.reason" value
// (OpenID Federation 1.0 §8.7.3) — a defined string type rather than a
// closed Go enum, since "a federation MAY specify and utilize
// additional reasons," mirroring TrustMarkStatus's own precedent for
// the identical situation.
type KeyRevocationReason string

const (
	// KeyRevocationReasonUnspecified is a general or unspecified reason
	// for the key status change. §8.7.3: "The reason MAY be omitted
	// instead of using the unspecified value" — an omitted reason and
	// this value are both legitimate, not interchangeable defaults one
	// implies the other.
	KeyRevocationReasonUnspecified KeyRevocationReason = "unspecified"

	// KeyRevocationReasonCompromised indicates the private key is
	// believed to have been compromised.
	KeyRevocationReasonCompromised KeyRevocationReason = "compromised"

	// KeyRevocationReasonSuperseded indicates the JWK is no longer
	// active.
	KeyRevocationReasonSuperseded KeyRevocationReason = "superseded"
)

// KeyRevocation is a HistoricalKey's own "revoked" member (OpenID
// Federation 1.0 §8.7.2), when present. Its absence on a HistoricalKey
// means the key merely expired normally — it was never revoked.
type KeyRevocation struct {
	RevokedAt time.Time
	Reason    KeyRevocationReason
}

// HistoricalKey is one entry of a Federation Historical Keys response's
// "keys" claim (§8.7.2) — a JWK plus the historical-keys-specific
// lifetime/revocation metadata that make it meaningful for verifying an
// old, still-relevant statement after key rotation, unlike an ordinary
// currently-active key in a ParsedJWK.
type HistoricalKey struct {
	KeyID     string
	Algorithm fapi.SignatureAlgorithm
	PublicKey crypto.PublicKey

	// IssuedAt is the key's own "iat" member, if present — OPTIONAL.
	IssuedAt time.Time

	// ExpiresAt is the key's own "exp" member — REQUIRED; §8.7.2: "After
	// this time the key MUST NOT be considered valid."
	ExpiresAt time.Time

	// NotBefore is the key's own "nbf" member, if present — OPTIONAL;
	// §8.7.2 itself notes it's "typically superfluous" for Historical
	// Keys specifically, since iat/exp already establish the key's
	// lifetime, but is registered for a profile that issues keys not
	// immediately valid at issuance.
	NotBefore time.Time

	// Revoked is the key's own "revoked" member, if present — nil means
	// the key merely expired normally, not that it was revoked.
	Revoked *KeyRevocation
}

// HistoricalKeysClaims is a parsed Federation Historical Keys response
// JWT payload (OpenID Federation 1.0 §8.7.2).
type HistoricalKeysClaims struct {
	Issuer   string
	IssuedAt time.Time

	// Keys is the "keys" claim. A malformed or unsupported individual
	// entry is skipped, not fatal to the whole response — the same
	// "one bad entry doesn't invalidate an otherwise usable key set"
	// stance jose.ParseJWKSet already takes for an ordinary JWK Set (see
	// Claims.JWKS's own doc comment for why), extended here to also
	// cover a well-formed key missing its own REQUIRED "exp" member.
	Keys []HistoricalKey
}

// HistoricalKeysResponse is a parsed, but not yet signature-verified,
// Federation Historical Keys response JWT — the same "claims safe to
// read as lookup keys, never as a basis for trust until Verify
// succeeds" contract every other type in this package already
// establishes.
type HistoricalKeysResponse struct {
	compact jose.Compact
	claims  HistoricalKeysClaims
}

// ParseHistoricalKeysResponse parses token without verifying its
// signature.
func ParseHistoricalKeysResponse(token string) (HistoricalKeysResponse, error) {
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return HistoricalKeysResponse{}, fmt.Errorf("federation: %w", err)
	}
	if compact.Header.Type != historicalKeysJWTType {
		return HistoricalKeysResponse{}, ErrHistoricalKeysWrongType
	}
	claims, err := parseHistoricalKeysClaims(compact.Payload)
	if err != nil {
		return HistoricalKeysResponse{}, err
	}
	return HistoricalKeysResponse{compact: compact, claims: claims}, nil
}

// KeyID returns the response header's "kid", or "" if absent —
// identifying the signing key used for this response itself, never one
// of the historical keys named inside its own "keys" claim. Untrusted
// until Verify succeeds; use only to select which of the issuer's
// currently published keys to verify against.
func (r HistoricalKeysResponse) KeyID() string { return r.compact.Header.KeyID }

// Algorithm returns the algorithm the response header claims to use.
// Untrusted until Verify succeeds — a caller must still supply the
// algorithm it expects via HistoricalKeysVerifyPolicy rather than
// trusting this value, exactly as jose.Compact.Verify requires.
func (r HistoricalKeysResponse) Algorithm() fapi.SignatureAlgorithm {
	return r.compact.Header.Algorithm
}

// ClaimedIssuer returns the response's unverified "iss" claim, for use
// as a lookup key only (e.g. which entity's currently published keys to
// resolve candidates from before Verify runs).
func (r HistoricalKeysResponse) ClaimedIssuer() string { return r.claims.Issuer }

// HistoricalKeysVerifyPolicy is the set of checks Verify enforces
// against a HistoricalKeysResponse.
type HistoricalKeysVerifyPolicy struct {
	// ExpectedIssuer is the entity the caller is trying to authenticate
	// as having issued this response — the response's iss claim must
	// equal it exactly.
	ExpectedIssuer string

	// Algorithm is the algorithm ExpectedIssuer is registered or
	// discovered to sign with. The response header's algorithm must
	// equal it exactly — this is what prevents algorithm-confusion
	// attacks, so it must come from the issuer's own currently published
	// jwks (via its kid), never trusted from the response itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate iat against. There is no exp claim to
	// also check here — §8.7.2 defines no expiry for the response JWT
	// itself (each individual HistoricalKey carries its own exp
	// instead); this response is a point-in-time answer, not a
	// credential with its own validity window, the same shape
	// TrustMarkStatusResponseVerifyPolicy already has for the identical
	// reason.
	Now time.Time

	// MaxClockSkew bounds how far in the future an iat claim may be.
	// Zero means no tolerance.
	MaxClockSkew time.Duration
}

// Verify checks r's signature against pub and its claims against
// policy, returning the response's now-trusted claims.
func (r HistoricalKeysResponse) Verify(pub crypto.PublicKey, policy HistoricalKeysVerifyPolicy) (HistoricalKeysClaims, error) {
	if policy.ExpectedIssuer == "" {
		return HistoricalKeysClaims{}, fmt.Errorf("federation: ExpectedIssuer is empty")
	}
	if policy.Now.IsZero() {
		return HistoricalKeysClaims{}, fmt.Errorf("federation: Now is zero")
	}

	if err := r.compact.Verify(pub, policy.Algorithm); err != nil {
		return HistoricalKeysClaims{}, fmt.Errorf("federation: %w", err)
	}
	c := r.claims

	if c.Issuer != policy.ExpectedIssuer {
		return HistoricalKeysClaims{}, ErrHistoricalKeysIssuerMismatch
	}
	if policy.Now.Before(c.IssuedAt.Add(-policy.MaxClockSkew)) {
		return HistoricalKeysClaims{}, ErrHistoricalKeysNotYetValid
	}

	return c, nil
}

// rawHistoricalKey is one "keys" array entry's historical-keys-specific
// members — parsed separately from its JWK material (kty/crv/x/y/n/e/
// kid/alg), which goes through jose.ParseJWKSet via a synthetic
// single-entry set instead, reusing that package's own algorithm
// detection and shape validation rather than duplicating it.
type rawHistoricalKey struct {
	IAT     *int64 `json:"iat"`
	EXP     *int64 `json:"exp"`
	NBF     *int64 `json:"nbf"`
	Revoked *struct {
		RevokedAt int64  `json:"revoked_at"`
		Reason    string `json:"reason"`
	} `json:"revoked"`
}

func parseHistoricalKeysClaims(payload []byte) (HistoricalKeysClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return HistoricalKeysClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, err := popRequiredString(raw, "iss")
	if err != nil {
		return HistoricalKeysClaims{}, err
	}
	iat, err := popRequiredInt64(raw, "iat")
	if err != nil {
		return HistoricalKeysClaims{}, err
	}
	keysRaw, ok := raw["keys"]
	if !ok {
		return HistoricalKeysClaims{}, fmt.Errorf("%w: missing \"keys\"", ErrMalformedClaims)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(keysRaw, &entries); err != nil {
		return HistoricalKeysClaims{}, fmt.Errorf("%w: keys: %v", ErrMalformedClaims, err)
	}

	keys := make([]HistoricalKey, 0, len(entries))
	for _, entry := range entries {
		key, ok := parseHistoricalKeyEntry(entry)
		if !ok {
			continue
		}
		keys = append(keys, key)
	}

	return HistoricalKeysClaims{Issuer: iss, IssuedAt: time.Unix(iat, 0), Keys: keys}, nil
}

// parseHistoricalKeyEntry parses one "keys" array entry, reporting ok
// false for anything that doesn't yield a usable HistoricalKey (an
// unsupported/malformed JWK, or a missing REQUIRED "exp") — see
// HistoricalKeysClaims.Keys's own doc comment for why that's a skip,
// not a hard failure of the whole response.
func parseHistoricalKeyEntry(entry json.RawMessage) (HistoricalKey, bool) {
	wrapped, err := json.Marshal(map[string][]json.RawMessage{"keys": {entry}})
	if err != nil {
		return HistoricalKey{}, false
	}
	parsed, err := jose.ParseJWKSet(wrapped)
	if err != nil || len(parsed) != 1 {
		return HistoricalKey{}, false
	}

	var extra rawHistoricalKey
	if err := json.Unmarshal(entry, &extra); err != nil {
		return HistoricalKey{}, false
	}
	if extra.EXP == nil {
		return HistoricalKey{}, false
	}

	key := HistoricalKey{
		KeyID: parsed[0].KeyID, Algorithm: parsed[0].Algorithm, PublicKey: parsed[0].PublicKey,
		ExpiresAt: time.Unix(*extra.EXP, 0),
	}
	if extra.IAT != nil {
		key.IssuedAt = time.Unix(*extra.IAT, 0)
	}
	if extra.NBF != nil {
		key.NotBefore = time.Unix(*extra.NBF, 0)
	}
	if extra.Revoked != nil {
		key.Revoked = &KeyRevocation{
			RevokedAt: time.Unix(extra.Revoked.RevokedAt, 0),
			Reason:    KeyRevocationReason(extra.Revoked.Reason),
		}
	}
	return key, true
}

// HistoricalKeyParams describes one key to include in a Federation
// Historical Keys response.
type HistoricalKeyParams struct {
	KeyID     string
	Algorithm fapi.SignatureAlgorithm
	PublicKey crypto.PublicKey

	// IssuedAt sets the key's own "iat" member when non-zero. Optional.
	IssuedAt time.Time

	// ExpiresAt sets the key's own "exp" member. Required.
	ExpiresAt time.Time

	// NotBefore sets the key's own "nbf" member when non-zero. Optional.
	NotBefore time.Time

	// Revoked sets the key's own "revoked" member when non-nil.
	// Optional.
	Revoked *KeyRevocation
}

// CreateHistoricalKeysResponseParams describes one Federation Historical
// Keys response to create (OpenID Federation 1.0 §8.7.2).
type CreateHistoricalKeysResponseParams struct {
	// Signer produces the response's signature — this entity's own
	// currently active federation key (a historical key itself, being
	// retired, is never used to sign the response naming it).
	Signer crypto.Signer

	// Algorithm Signer signs with.
	Algorithm fapi.SignatureAlgorithm

	// KeyID is recorded in the response's "kid" header. Required —
	// OpenID Federation 1.0 §8.7.2: "Historical keys JWTs MUST include
	// the kid (Key ID) header parameter."
	KeyID string

	// Issuer is the "iss" claim — this entity's own Entity Identifier.
	Issuer string

	// Now is the response's issuance time ("iat").
	Now time.Time

	// Keys is the "keys" claim — every historical key to publish.
	// Required, at least one.
	Keys []HistoricalKeyParams
}

// CreateHistoricalKeysResponse builds and signs a Federation Historical
// Keys response JWT for p.
func CreateHistoricalKeysResponse(p CreateHistoricalKeysResponseParams) (string, error) {
	if p.Signer == nil {
		return "", fmt.Errorf("federation: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return "", fmt.Errorf("federation: invalid algorithm %v", p.Algorithm)
	}
	if p.KeyID == "" {
		return "", fmt.Errorf(`federation: key id is required (OpenID Federation 1.0 §8.7.2: "Historical keys JWTs MUST include the kid (Key ID) header parameter")`)
	}
	if p.Issuer == "" {
		return "", fmt.Errorf("federation: issuer is empty")
	}
	if p.Now.IsZero() {
		return "", fmt.Errorf("federation: now is zero")
	}
	if len(p.Keys) == 0 {
		return "", fmt.Errorf("federation: keys is empty")
	}

	keys := make([]json.RawMessage, len(p.Keys))
	for i, k := range p.Keys {
		raw, err := historicalKeyJSON(k)
		if err != nil {
			return "", fmt.Errorf("federation: keys[%d]: %w", i, err)
		}
		keys[i] = raw
	}

	claims := map[string]any{
		"iss": p.Issuer, "iat": p.Now.Unix(), "keys": keys,
	}
	return signClaims(p.Signer, p.Algorithm, p.KeyID, historicalKeysJWTType, claims)
}

// historicalKeyJSON builds one "keys" array entry: k's own JWK
// representation (via jose.NewJWK, the same base every other JWK this
// module emits goes through), extended with the historical-keys-specific
// iat/exp/nbf/revoked members §8.7.2 defines on top of the base JWK
// shape.
func historicalKeyJSON(k HistoricalKeyParams) (json.RawMessage, error) {
	if k.KeyID == "" {
		return nil, fmt.Errorf("key id is required")
	}
	if !k.Algorithm.IsValid() {
		return nil, fmt.Errorf("invalid algorithm %v", k.Algorithm)
	}
	if k.PublicKey == nil {
		return nil, fmt.Errorf("public key is required")
	}
	if k.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("exp is required")
	}

	jwk, err := jose.NewJWK(k.PublicKey, k.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("build jwk: %w", err)
	}
	base, err := jwk.WithKeyID(k.KeyID).MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal jwk: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(base, &fields); err != nil {
		return nil, fmt.Errorf("unmarshal jwk: %w", err)
	}

	if !k.IssuedAt.IsZero() {
		fields["iat"], _ = json.Marshal(k.IssuedAt.Unix())
	}
	fields["exp"], _ = json.Marshal(k.ExpiresAt.Unix())
	if !k.NotBefore.IsZero() {
		fields["nbf"], _ = json.Marshal(k.NotBefore.Unix())
	}
	if k.Revoked != nil {
		fields["revoked"], _ = json.Marshal(map[string]any{
			"revoked_at": k.Revoked.RevokedAt.Unix(), "reason": string(k.Revoked.Reason),
		})
	}
	return json.Marshal(fields)
}
