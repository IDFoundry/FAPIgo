package requestobject

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// ReplayChecker records that a request object's "jti" has been used,
// failing if it has been seen before. As with dpop.ReplayChecker and
// clientassertion.ReplayChecker, implementations are expected to key
// storage by a namespaced digest of jti, not the raw value.
type ReplayChecker interface {
	UseOnce(ctx context.Context, jti string, expiresAt time.Time) error
}

// Object is a parsed, but not yet signature-verified, request object.
// KeyID, Algorithm, ClaimedIssuer and Parameter are available before
// Verify succeeds so a caller can look up which registered client and
// key to verify against, and which client to attribute a rejected
// request to for error reporting — that is a safe use of unverified
// data, since it only selects what to check against, not what to trust.
// Nothing from Object should influence an authorization decision until
// Verify returns a VerifiedObject.
type Object struct {
	compact jose.Compact
	claims  Claims
}

// Parse parses a request object without verifying its signature.
func Parse(token string) (Object, error) {
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return Object{}, fmt.Errorf("requestobject: %w", err)
	}
	if compact.Header.Type != "" && !isRequestObjectType(compact.Header.Type) {
		return Object{}, ErrWrongType
	}
	claims, err := parseClaims(compact.Payload)
	if err != nil {
		return Object{}, err
	}
	return Object{compact: compact, claims: claims}, nil
}

// KeyID returns the object header's "kid", or "" if absent. Untrusted
// until Verify succeeds; use only to select which key to verify against.
func (o Object) KeyID() string { return o.compact.Header.KeyID }

// Algorithm returns the algorithm the object header claims to use.
// Untrusted until Verify succeeds — callers must still supply the
// algorithm they expect via VerifyPolicy rather than trusting this
// value, exactly as jose.Compact.Verify requires.
func (o Object) Algorithm() fapi.SignatureAlgorithm { return o.compact.Header.Algorithm }

// ClaimedIssuer returns the object's unverified "iss" claim, for use as
// a client-lookup key only.
func (o Object) ClaimedIssuer() string { return o.claims.Issuer }

// Parameter returns the unverified authorization request parameter
// named name, for use as a lookup key only (e.g. resolving a registered
// redirect_uri set before the signature has been checked). Nothing
// derived from it should influence an authorization decision until
// Verify succeeds.
func (o Object) Parameter(name string) (json.RawMessage, bool) {
	v, ok := o.claims.Parameters[name]
	return v, ok
}

// VerifyPolicy is the set of checks Verify enforces against an Object.
type VerifyPolicy struct {
	// ExpectedClientID is the client the caller is trying to
	// authenticate. The object's iss claim must equal it exactly.
	ExpectedClientID string

	// ExpectedAudience is the authorization server issuer identifier the
	// object's aud claim must equal exactly.
	ExpectedAudience string

	// Algorithm is the algorithm this client is registered to sign
	// request objects with. The object header's algorithm must equal it
	// exactly — this is what prevents algorithm-confusion attacks, so it
	// must come from the client's registration, never from the object
	// itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate exp/nbf against.
	Now time.Time

	// MaxLifetime bounds how far in the future (relative to Now) the
	// object's exp claim may be, and symmetrically how far in the past
	// its nbf claim may be — an object is meant to represent one short,
	// coherent validity window around when it was created, not two
	// independently-bounded claims, so the same limit governs both
	// directions. Required — there is no implicit default.
	MaxLifetime time.Duration

	// MaxClockSkew bounds how far in the future (relative to Now) an nbf
	// claim may be, and extends how long past exp an object is still
	// accepted. Zero means no tolerance.
	MaxClockSkew time.Duration

	// RequireNotBefore rejects an object with no nbf claim at all,
	// rather than simply skipping the not-yet-valid check for it. FAPI
	// 2.0 Message Signing Final §5.3.1 mandates nbf ("shall require the
	// request object to contain an nbf claim"); the base FAPI 2.0
	// Security Profile does not (it relies on request_uri's own short
	// lifetime instead, per its "Main differences to FAPI 1.0" table) —
	// so the caller sets this only under
	// ProfileFAPISecurityWithMessageSigning, not unconditionally.
	RequireNotBefore bool

	// Replay, if non-nil, is used to detect object replay by jti — but
	// only when the object actually carries one. Neither RFC 9101 nor
	// FAPI 2.0 Message Signing Final requires a request object to
	// include jti (message-signing's own replay defense is its
	// mandatory, tightly-bounded nbf/exp window, not a jti claim), and
	// the OIDF conformance suite's own request objects never carry one
	// under the plain FAPI2 profile — only its Brazil-specific profile
	// behavior adds one. So a missing jti here is not an error unless
	// RequireJTI is set; it just means this particular object skips
	// replay-by-jti, the same as a nil Replay would. This is fine
	// architecturally because — when a request object is only ever
	// accepted via a PAR request_uri that is itself single-use —
	// replay detection here was always meant as defense in depth, not
	// the primary control.
	Replay ReplayChecker

	// RequireJTI rejects an object with no jti claim at all, rather than
	// simply skipping replay-by-jti for it. Unlike PAR's request object
	// (accepted only via a single-use request_uri, where jti is genuine
	// defense in depth — see Replay's own doc comment), FAPI-CIBA's
	// backchannel authentication request has no such single-use wrapper
	// of its own, so the OIDF FAPI-CIBA-ID1 conformance suite mandates
	// jti unconditionally (confirmed by its
	// EnsureRequestObjectMissingJtiFails negative test) — the caller
	// sets this only for that request kind, not for PAR's.
	RequireJTI bool
}

// VerifiedObject is what remains once a request object has been
// verified: the authenticated client ID and the authorization request
// parameters it carried.
type VerifiedObject struct {
	ClientID   string
	Parameters map[string]json.RawMessage
	ExpiresAt  time.Time
}

// Verify checks o's signature against pub and its claims against policy.
func (o Object) Verify(ctx context.Context, pub crypto.PublicKey, policy VerifyPolicy) (VerifiedObject, error) {
	if policy.ExpectedClientID == "" {
		return VerifiedObject{}, fmt.Errorf("requestobject: ExpectedClientID is empty")
	}
	if policy.ExpectedAudience == "" {
		return VerifiedObject{}, fmt.Errorf("requestobject: ExpectedAudience is empty")
	}
	if policy.Now.IsZero() {
		return VerifiedObject{}, fmt.Errorf("requestobject: Now is zero")
	}
	if policy.MaxLifetime <= 0 {
		return VerifiedObject{}, fmt.Errorf("requestobject: MaxLifetime must be positive")
	}

	if err := o.compact.Verify(pub, policy.Algorithm); err != nil {
		return VerifiedObject{}, fmt.Errorf("requestobject: %w", err)
	}
	c := o.claims

	if c.Issuer != policy.ExpectedClientID {
		return VerifiedObject{}, ErrIssuerMismatch
	}
	if !slices.Contains(c.Audience, policy.ExpectedAudience) {
		return VerifiedObject{}, ErrAudienceMismatch
	}

	if policy.Now.After(c.ExpiresAt.Add(policy.MaxClockSkew)) {
		return VerifiedObject{}, ErrExpired
	}
	if c.ExpiresAt.Sub(policy.Now) > policy.MaxLifetime {
		return VerifiedObject{}, ErrLifetimeExceeded
	}
	if c.NotBefore.IsZero() {
		if policy.RequireNotBefore {
			return VerifiedObject{}, ErrMissingNotBefore
		}
	} else if policy.Now.Before(c.NotBefore.Add(-policy.MaxClockSkew)) {
		return VerifiedObject{}, ErrNotYetValid
	} else if policy.Now.Sub(c.NotBefore) > policy.MaxLifetime {
		return VerifiedObject{}, ErrNotBeforeTooOld
	}

	if c.JTI == "" && policy.RequireJTI {
		return VerifiedObject{}, ErrMissingJTI
	}
	if policy.Replay != nil && c.JTI != "" {
		// The TTL must cover the same skew the acceptance check above
		// grants (line 171), or a replay in (ExpiresAt, ExpiresAt+skew]
		// would still be accepted but no longer be in the replay store.
		if err := policy.Replay.UseOnce(ctx, c.JTI, c.ExpiresAt.Add(policy.MaxClockSkew)); err != nil {
			return VerifiedObject{}, fmt.Errorf("requestobject: replay check: %w", err)
		}
	}

	return VerifiedObject{ClientID: c.Issuer, Parameters: c.Parameters, ExpiresAt: c.ExpiresAt}, nil
}
