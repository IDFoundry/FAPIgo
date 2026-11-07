package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	fapi "github.com/idfoundry/fapigo"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
)

// These name the internal/federation types a Federation Historical Keys
// response is built from and parsed into (OpenID Federation 1.0 §8.7.2),
// so code outside this module can construct HistoricalKeysIssuer's
// input and read Resolver.FetchHistoricalKeys' output by name.
type (
	// HistoricalKeyParams is one retired key to publish through
	// HistoricalKeysIssuer.Response: its "kid" (KeyID, required), the
	// algorithm it signed with (Algorithm, required), its public key
	// (PublicKey, required — never a private key), its "exp" (ExpiresAt,
	// required: §8.7.2 "After this time the key MUST NOT be considered
	// valid"), its optional "iat" (IssuedAt) and "nbf" (NotBefore), and
	// its optional "revoked" object (Revoked).
	HistoricalKeyParams = intfed.HistoricalKeyParams

	// HistoricalKey is one verified "keys" entry, as
	// Resolver.FetchHistoricalKeys returns it in HistoricalKeysClaims.
	HistoricalKey = intfed.HistoricalKey

	// KeyRevocation is a historical key's "revoked" object (§8.7.2):
	// RevokedAt (its "revoked_at", required when the object is present)
	// and Reason (its "reason", optional).
	KeyRevocation = intfed.KeyRevocation

	// KeyRevocationReason is a KeyRevocation's "reason" (§8.7.3).
	KeyRevocationReason = intfed.KeyRevocationReason
)

// The key revocation reasons OpenID Federation 1.0 §8.7.3 defines. A
// federation MAY define more; see HistoricalKeysIssueConfig's
// AdditionalRevocationReasons.
const (
	KeyRevocationReasonUnspecified = intfed.KeyRevocationReasonUnspecified
	KeyRevocationReasonCompromised = intfed.KeyRevocationReasonCompromised
	KeyRevocationReasonSuperseded  = intfed.KeyRevocationReasonSuperseded
)

// HistoricalKeysIssueConfig configures a HistoricalKeysIssuer. It is
// copied by NewHistoricalKeysIssuer; mutating a HistoricalKeysIssueConfig
// afterwards has no effect.
type HistoricalKeysIssueConfig struct {
	// EntityID is this entity's own Entity Identifier — the "iss" every
	// Federation Historical Keys response it signs carries (§8.7.2: "The
	// Entity's Entity Identifier"), and the entity ID a peer passes to
	// Resolver.FetchHistoricalKeys. Any Federation Entity may publish a
	// federation_historical_keys_endpoint (§5.1.1), so nothing here
	// requires a particular role. Required.
	EntityID string

	// AdditionalRevocationReasons are the "reason" values Response
	// accepts on top of §8.7.3's own unspecified, compromised and
	// superseded — §8.7.3: "A federation MAY specify and utilize
	// additional reasons depending on the trust or security framework in
	// use." Empty (the default) accepts only §8.7.3's three, so a typo
	// isn't published as though it were a reason. NewHistoricalKeysIssuer
	// refuses an empty entry.
	AdditionalRevocationReasons []KeyRevocationReason
}

// HistoricalKeysIssueDependencies are a HistoricalKeysIssuer's injected
// collaborators. NewHistoricalKeysIssuer rejects a nil/zero value for
// every field except JWKS — there is no implicit default signer, key or
// clock.
type HistoricalKeysIssueDependencies struct {
	// Signer produces every response's signature — this entity's
	// currently active federation key (§8.7.2: "It is signed with a
	// Federation Entity Key"), the one a peer's
	// Resolver.FetchHistoricalKeys verifies against after resolving this
	// entity's Trust Chain. Never one of the retired keys the response
	// reports on: Response refuses to publish Signer's own key.
	Signer crypto.Signer

	// Algorithm Signer signs with.
	Algorithm fapi.SignatureAlgorithm

	// KeyID identifies Signer's key within this entity's own published
	// jwks — recorded in every response's "kid" header. Required —
	// §8.7.2: "Historical keys JWTs MUST include the kid (Key ID) header
	// parameter with its value being the Key ID of the signing key used."
	KeyID string

	// JWKS is this entity's currently published federation keys — the
	// "jwks" claim of its own Entity Configuration (see
	// SelfIssueDependencies.JWKS), including any key still published
	// alongside Signer's during a rotation's overlap. Optional: when set,
	// Response also refuses a retired key whose kid or public key appears
	// here, since a key still in the Entity Configuration isn't
	// historical yet (§8.7.4: historical keys are those "no longer
	// published in the Entity's Entity Configuration"). Signer's own key
	// is refused whether or not JWKS is set.
	JWKS json.RawMessage

	Clock Clock
}

// HistoricalKeysIssuer signs Federation Historical Keys responses
// (OpenID Federation 1.0 §8.7.2) listing this entity's own retired
// federation signing keys, so a statement signed before a key rollover
// can still be checked against the key that signed it. It is the
// producing counterpart of Resolver.FetchHistoricalKeys. Construct one
// with NewHistoricalKeysIssuer.
//
// Like every other type in this package, HistoricalKeysIssuer is
// transport-agnostic: it signs and returns a token. Serving it is the
// caller's: answer a GET (§8.7.1; this package covers no
// client-authenticated POST variant, on either side) at the URL this
// entity publishes as federation_historical_keys_endpoint in its own
// federation_entity metadata (§5.1.1: an https URL with no fragment),
// with WriteHistoricalKeys. This package keeps no record of which keys
// an entity has retired, or when — the caller's own key management
// supplies Response's input.
type HistoricalKeysIssuer struct {
	cfg    HistoricalKeysIssueConfig
	deps   HistoricalKeysIssueDependencies
	active []jose.ParsedJWK
}

// NewHistoricalKeysIssuer validates cfg and deps and returns a
// HistoricalKeysIssuer.
func NewHistoricalKeysIssuer(cfg HistoricalKeysIssueConfig, deps HistoricalKeysIssueDependencies) (*HistoricalKeysIssuer, error) {
	if cfg.EntityID == "" {
		return nil, fmt.Errorf("federation: config: entity ID is required")
	}
	if err := ValidEntityID(cfg.EntityID); err != nil {
		return nil, fmt.Errorf("federation: config: %w", err)
	}
	if slices.Contains(cfg.AdditionalRevocationReasons, "") {
		return nil, fmt.Errorf("federation: config: additional revocation reasons must not be empty")
	}
	if deps.Signer == nil {
		return nil, fmt.Errorf("federation: dependencies: signer is required")
	}
	if deps.KeyID == "" {
		return nil, fmt.Errorf("federation: dependencies: key id is required")
	}
	if deps.Clock == nil {
		return nil, fmt.Errorf("federation: dependencies: clock is required")
	}
	var active []jose.ParsedJWK
	if len(deps.JWKS) > 0 {
		parsed, err := jose.ParseTrustedJWKSet(deps.JWKS)
		if err != nil {
			return nil, fmt.Errorf("federation: dependencies: jwks: %w", err)
		}
		active = parsed
	}
	cfg.AdditionalRevocationReasons = slices.Clone(cfg.AdditionalRevocationReasons)
	return &HistoricalKeysIssuer{cfg: cfg, deps: deps, active: active}, nil
}

// Response signs and returns a Federation Historical Keys response
// (OpenID Federation 1.0 §8.7.2: iss == Config.EntityID, iat from
// Dependencies.Clock) whose "keys" claim lists keys, in order. The
// returned token is a jwk-set+jwt compact serialization, meant to be
// served verbatim with WriteHistoricalKeys.
//
// keys may be empty — an entity that hasn't yet retired a key publishes
// an empty "keys" array. Each entry must have a KeyID unique within
// keys, a valid Algorithm, a PublicKey matching it (a public key: a
// private key is refused, never published), and a non-zero ExpiresAt
// not before its IssuedAt or NotBefore. A Revoked entry must have a
// non-zero RevokedAt, and a Reason that is empty (§8.7.3: "The reason
// MAY be omitted"), one of §8.7.3's own, or one of
// Config.AdditionalRevocationReasons. Response refuses an entry that is
// still an active key — Dependencies.Signer's own key or KeyID, or
// (when Dependencies.JWKS is set) any key or kid published there — so a
// key's lifecycle can't be misreported by a caller passing the wrong
// slice. An expired key can later be reissued here with Revoked set
// (§8.7: "an expired key can be later additionally marked as revoked").
func (i *HistoricalKeysIssuer) Response(keys []HistoricalKeyParams) (string, error) {
	seen := make(map[string]bool, len(keys))
	for n, k := range keys {
		if err := i.checkRetiredKey(k); err != nil {
			return "", fmt.Errorf("federation: historical keys response: keys[%d]: %w", n, err)
		}
		if seen[k.KeyID] {
			return "", fmt.Errorf("federation: historical keys response: keys[%d]: duplicate kid %q", n, k.KeyID)
		}
		seen[k.KeyID] = true
	}

	token, err := intfed.CreateHistoricalKeysResponse(intfed.CreateHistoricalKeysResponseParams{
		Signer: i.deps.Signer, Algorithm: i.deps.Algorithm, KeyID: i.deps.KeyID,
		Issuer: i.cfg.EntityID, Now: i.deps.Clock.Now(), Keys: keys,
	})
	if err != nil {
		return "", fmt.Errorf("federation: issue historical keys response: %w", err)
	}
	return token, nil
}

// checkRetiredKey applies Response's per-key rules beyond the shape
// checks intfed.CreateHistoricalKeysResponse already makes (kid,
// algorithm, key-type-for-algorithm, exp, revoked_at).
func (i *HistoricalKeysIssuer) checkRetiredKey(k HistoricalKeyParams) error {
	if err := checkRetiredKeyShape(k); err != nil {
		return err
	}
	if err := i.checkRevocation(k); err != nil {
		return err
	}
	return i.checkNotActive(k)
}

// checkRetiredKeyShape checks k's own members: a kid, a public (never
// private) key, and an exp not before its iat or nbf.
func checkRetiredKeyShape(k HistoricalKeyParams) error {
	if k.KeyID == "" {
		return fmt.Errorf("kid is required")
	}
	if k.PublicKey == nil {
		return fmt.Errorf("kid %q: public key is required", k.KeyID)
	}
	if _, ok := k.PublicKey.(crypto.Signer); ok {
		return fmt.Errorf("kid %q: a private key was passed where a public key is required", k.KeyID)
	}
	if k.ExpiresAt.IsZero() {
		return fmt.Errorf("kid %q: exp is required", k.KeyID)
	}
	if (!k.IssuedAt.IsZero() && k.ExpiresAt.Before(k.IssuedAt)) || (!k.NotBefore.IsZero() && k.ExpiresAt.Before(k.NotBefore)) {
		return fmt.Errorf("kid %q: exp is before iat or nbf", k.KeyID)
	}
	return nil
}

// checkRevocation checks k's "revoked" object, when present: a
// revoked_at, and a reason Response accepts.
func (i *HistoricalKeysIssuer) checkRevocation(k HistoricalKeyParams) error {
	if k.Revoked == nil {
		return nil
	}
	if k.Revoked.RevokedAt.IsZero() {
		return fmt.Errorf("kid %q: revoked_at is required", k.KeyID)
	}
	if !i.knownRevocationReason(k.Revoked.Reason) {
		return fmt.Errorf("kid %q: unknown revocation reason %q", k.KeyID, k.Revoked.Reason)
	}
	return nil
}

// checkNotActive refuses k when it is still an active key: Signer's own
// key or KeyID, or one published in Dependencies.JWKS.
func (i *HistoricalKeysIssuer) checkNotActive(k HistoricalKeyParams) error {
	if k.KeyID == i.deps.KeyID || samePublicKey(k.PublicKey, i.deps.Signer.Public()) {
		return fmt.Errorf("kid %q: is the active signing key", k.KeyID)
	}
	for _, active := range i.active {
		if k.KeyID == active.KeyID || samePublicKey(k.PublicKey, active.PublicKey) {
			return fmt.Errorf("kid %q: is still published in the entity's jwks", k.KeyID)
		}
	}
	return nil
}

func (i *HistoricalKeysIssuer) knownRevocationReason(reason KeyRevocationReason) bool {
	switch reason {
	case "", KeyRevocationReasonUnspecified, KeyRevocationReasonCompromised, KeyRevocationReasonSuperseded:
		return true
	}
	return slices.Contains(i.cfg.AdditionalRevocationReasons, reason)
}

// samePublicKey reports whether a and b are the same public key, via
// the Equal method every crypto/* public key type implements.
func samePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// WriteHistoricalKeys writes jwt — HistoricalKeysIssuer.Response's own
// return value — to w as a complete Federation Historical Keys response
// (OpenID Federation 1.0 §8.7.2: "A successful response MUST use the
// HTTP status code 200 with the content type application/jwk-set+jwt"):
// the Content-Type header HistoricalKeysContentType, then jwt verbatim
// as the body. Like WriteEntityStatement, it writes to an
// http.ResponseWriter the caller already has, nothing more, and must be
// called before anything else writes to w.
func WriteHistoricalKeys(w http.ResponseWriter, jwt string) {
	w.Header().Set("Content-Type", HistoricalKeysContentType)
	_, _ = w.Write([]byte(jwt))
}
