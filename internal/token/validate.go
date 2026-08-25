package token

import (
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// AccessToken is a parsed, but not yet signature-verified, JWT access
// token. KeyID, Algorithm and ClaimedIssuer are available before
// Validate succeeds so a caller can look up which key to verify
// against — that is a safe use of unverified data, since it only
// selects what to check against, not what to trust. Nothing from
// AccessToken, including its scope or confirmation claim, should
// influence an authorization decision until Validate returns a
// ValidatedAccessToken.
type AccessToken struct {
	compact jose.Compact
	claims  AccessTokenClaims
}

// ParseAccessToken parses a JWT access token without verifying its
// signature.
func ParseAccessToken(tok string) (AccessToken, error) {
	compact, err := jose.ParseCompact(tok)
	if err != nil {
		return AccessToken{}, fmt.Errorf("token: %w", err)
	}
	if compact.Header.Type != atJWTType {
		return AccessToken{}, ErrWrongType
	}
	claims, err := parseAccessTokenClaims(compact.Payload)
	if err != nil {
		return AccessToken{}, err
	}
	return AccessToken{compact: compact, claims: claims}, nil
}

// KeyID returns the token header's "kid", or "" if absent. Untrusted
// until Validate succeeds; use only to select which key to verify
// against.
func (t AccessToken) KeyID() string { return t.compact.Header.KeyID }

// Algorithm returns the algorithm the token header claims to use.
// Untrusted until Validate succeeds — callers must still supply the
// algorithm they expect via AccessTokenValidatePolicy rather than
// trusting this value, exactly as jose.Compact.Verify requires.
func (t AccessToken) Algorithm() fapi.SignatureAlgorithm { return t.compact.Header.Algorithm }

// ClaimedIssuer returns the token's unverified "iss" claim, for use as a
// key-lookup hint only.
func (t AccessToken) ClaimedIssuer() string { return t.claims.Issuer }

// AccessTokenValidatePolicy is the set of checks Validate enforces
// against an AccessToken.
type AccessTokenValidatePolicy struct {
	// ExpectedIssuer is the authorization server the caller expects this
	// token to have come from. The token's iss claim must equal it
	// exactly.
	ExpectedIssuer string

	// ExpectedAudience is the resource the caller expects this token to
	// be scoped to. The token's aud claim must equal it exactly.
	ExpectedAudience string

	// Algorithm is the algorithm this authorization server is
	// registered (or discovered) to sign access tokens with. The token
	// header's algorithm must equal it exactly — this is what prevents
	// algorithm-confusion attacks, so it must come from the server's
	// metadata, never from the token itself.
	Algorithm fapi.SignatureAlgorithm

	Now         time.Time
	MaxLifetime time.Duration
}

// ValidatedAccessToken is what remains once an access token has been
// validated.
type ValidatedAccessToken struct {
	Subject    string
	ClientID   string
	Scope      string
	Parameters map[string]json.RawMessage
	ExpiresAt  time.Time

	// JTI is the token's "jti" claim, now trusted — the signature has
	// been verified by this point, unlike AccessToken.KeyID()/
	// ClaimedIssuer(), which are documented as pre-verification lookup
	// hints only. A caller can use this to check token-specific
	// revocation (RFC 6750 §3.1's invalid_token case).
	JTI string

	// JKT is the token's "cnf.jkt" claim, now trusted, or "" if the
	// token carried no confirmation claim at all. This package no
	// longer checks it against an expected value itself (see this
	// struct's — and AccessTokenValidatePolicy's — history: that check
	// moved to the resource package's Verify(), which enforces DPoP
	// binding once, uniformly, regardless of access-token format).
	// Callers that need sender-constraint enforcement must compare this
	// themselves.
	JKT string
}

// Validate checks t's signature against pub and its claims against
// policy.
func (t AccessToken) Validate(pub crypto.PublicKey, policy AccessTokenValidatePolicy) (ValidatedAccessToken, error) {
	if policy.ExpectedIssuer == "" {
		return ValidatedAccessToken{}, fmt.Errorf("token: ExpectedIssuer is empty")
	}
	if policy.ExpectedAudience == "" {
		return ValidatedAccessToken{}, fmt.Errorf("token: ExpectedAudience is empty")
	}
	if policy.Now.IsZero() {
		return ValidatedAccessToken{}, fmt.Errorf("token: Now is zero")
	}
	if policy.MaxLifetime <= 0 {
		return ValidatedAccessToken{}, fmt.Errorf("token: MaxLifetime must be positive")
	}

	if err := t.compact.Verify(pub, policy.Algorithm); err != nil {
		return ValidatedAccessToken{}, fmt.Errorf("token: %w", err)
	}
	c := t.claims

	if c.Issuer != policy.ExpectedIssuer {
		return ValidatedAccessToken{}, ErrIssuerMismatch
	}
	// RFC 9068 §3 doesn't narrow RFC 7519 §4.1.3's general "aud", so an
	// access token's audience may legitimately be a multi-element array
	// (e.g. one token scoped to a small set of resource servers) — this
	// resource need only be named among them, not be the sole entry.
	// Unlike an ID token's aud (see IDTokenValidatePolicy's own
	// ExpectedAudience/TrustedAudiences), RFC 9068 states no equivalent
	// "reject if it names an audience you don't trust" rule, so no
	// trust-list is needed here.
	if !containsString(c.Audience, policy.ExpectedAudience) {
		return ValidatedAccessToken{}, ErrAudienceMismatch
	}
	// Ordinary "is it expired as of now" is deliberately NOT checked
	// here — that's resource.Verify()'s job, applied once, uniformly,
	// regardless of access-token format (see ValidatedAccessToken.JKT's
	// doc comment for the same reasoning, applied to sender-constraint
	// binding). MaxLifetime is a different, JWT-specific defense — an
	// opaque token has no signed exp claim an attacker could forge, so
	// it has no equivalent here.
	if c.ExpiresAt.Sub(policy.Now) > policy.MaxLifetime {
		return ValidatedAccessToken{}, ErrLifetimeExceeded
	}

	var jkt string
	if c.Confirmation != nil {
		jkt = c.Confirmation.JKT
	}

	return ValidatedAccessToken{
		Subject:    c.Subject,
		ClientID:   c.ClientID,
		Scope:      c.Scope,
		Parameters: c.Parameters,
		ExpiresAt:  c.ExpiresAt,
		JTI:        c.JTI,
		JKT:        jkt,
	}, nil
}

// IDToken is a parsed, but not yet signature-verified, ID token. As with
// AccessToken, KeyID/Algorithm/ClaimedIssuer are safe to use as lookup
// hints before Validate succeeds, but nothing else should be trusted
// until then.
type IDToken struct {
	compact jose.Compact
	claims  IDTokenClaims
}

// ParseIDToken parses an ID token without verifying its signature.
func ParseIDToken(tok string) (IDToken, error) {
	compact, err := jose.ParseCompact(tok)
	if err != nil {
		return IDToken{}, fmt.Errorf("token: %w", err)
	}
	claims, err := parseIDTokenClaims(compact.Payload)
	if err != nil {
		return IDToken{}, err
	}
	return IDToken{compact: compact, claims: claims}, nil
}

// KeyID returns the token header's "kid", or "" if absent. Untrusted
// until Validate succeeds; use only to select which key to verify
// against.
func (t IDToken) KeyID() string { return t.compact.Header.KeyID }

// Algorithm returns the algorithm the token header claims to use.
// Untrusted until Validate succeeds.
func (t IDToken) Algorithm() fapi.SignatureAlgorithm { return t.compact.Header.Algorithm }

// ClaimedIssuer returns the token's unverified "iss" claim, for use as a
// key-lookup hint only.
func (t IDToken) ClaimedIssuer() string { return t.claims.Issuer }

// IDTokenValidatePolicy is the set of checks Validate enforces against
// an IDToken.
type IDTokenValidatePolicy struct {
	// ExpectedIssuer is the authorization server the caller expects this
	// token to have come from. The token's iss claim must equal it
	// exactly.
	ExpectedIssuer string

	// ExpectedAudience is the caller's own client ID. The token's aud
	// claim — a single string or, per OIDC Core §2, an array — must
	// contain it.
	ExpectedAudience string

	// TrustedAudiences lists any other party the caller trusts to also
	// be named alongside ExpectedAudience in a multi-valued aud. OIDC
	// Core §3.1.3.7 step 3 requires rejecting an ID token "if it
	// contains additional audiences not trusted by the Client" — by
	// default (nil/empty) this package trusts none, so every element of
	// aud besides ExpectedAudience causes rejection, preserving the
	// exact-match behavior this package has always had. Set only to
	// entries the caller has an actual, specific reason to trust.
	TrustedAudiences []string

	// Algorithm is the algorithm this authorization server is
	// registered (or discovered) to sign ID tokens with. The token
	// header's algorithm must equal it exactly.
	Algorithm fapi.SignatureAlgorithm

	// ExpectedNonce, if non-empty, requires the token's nonce claim to
	// equal it exactly — this is what binds the ID token back to the
	// specific authorization request that requested it. Leave empty
	// only when the authorization request itself carried no nonce.
	ExpectedNonce string

	Now          time.Time
	MaxLifetime  time.Duration
	MaxClockSkew time.Duration
}

// ValidatedIDToken is what remains once an ID token has been validated.
// AuthTime, ACR and AMR are exposed for the caller to apply its own
// freshness/assurance policy (e.g. a requested max_age or acr_values) —
// this package only checks what it can check generically.
type ValidatedIDToken struct {
	Subject    string
	AuthTime   time.Time // zero if the token carried no auth_time
	ACR        string
	AMR        []string
	Parameters map[string]json.RawMessage
	ExpiresAt  time.Time
}

// Validate checks t's signature against pub and its claims against
// policy.
func (t IDToken) Validate(pub crypto.PublicKey, policy IDTokenValidatePolicy) (ValidatedIDToken, error) {
	if policy.ExpectedIssuer == "" {
		return ValidatedIDToken{}, fmt.Errorf("token: ExpectedIssuer is empty")
	}
	if policy.ExpectedAudience == "" {
		return ValidatedIDToken{}, fmt.Errorf("token: ExpectedAudience is empty")
	}
	if policy.Now.IsZero() {
		return ValidatedIDToken{}, fmt.Errorf("token: Now is zero")
	}
	if policy.MaxLifetime <= 0 {
		return ValidatedIDToken{}, fmt.Errorf("token: MaxLifetime must be positive")
	}

	if err := t.compact.Verify(pub, policy.Algorithm); err != nil {
		return ValidatedIDToken{}, fmt.Errorf("token: %w", err)
	}
	c := t.claims

	if c.Issuer != policy.ExpectedIssuer {
		return ValidatedIDToken{}, ErrIssuerMismatch
	}
	// OIDC Core §3.1.3.7 step 3: aud "MUST contain" the Client's own
	// client_id "as an audience value", and "MAY contain an array with
	// more than one element. The ID Token MUST be rejected... if it
	// contains additional audiences not trusted by the Client" — every
	// element must be either ExpectedAudience itself or one of
	// policy.TrustedAudiences, and ExpectedAudience must actually be
	// present (not merely permitted).
	sawExpectedAudience := false
	for _, aud := range c.Audience {
		if aud == policy.ExpectedAudience {
			sawExpectedAudience = true
			continue
		}
		if !containsString(policy.TrustedAudiences, aud) {
			return ValidatedIDToken{}, ErrAudienceMismatch
		}
	}
	if !sawExpectedAudience {
		return ValidatedIDToken{}, ErrAudienceMismatch
	}
	// OIDC Core §3.1.3.7 steps 9-10: when aud has multiple entries, the
	// Client SHOULD verify azp is present; when azp is present
	// (regardless of aud's length), the Client SHOULD verify it equals
	// the Client's own client_id. This package treats both as enforced,
	// not merely advisory: azp exists specifically to disambiguate which
	// party a multi-audience ID token was authorized for, and silently
	// ignoring it would defeat that purpose exactly where it matters —
	// when the token also names a trusted third-party audience.
	if len(c.Audience) > 1 && c.AZP == "" {
		return ValidatedIDToken{}, ErrMissingAuthorizedParty
	}
	if c.AZP != "" && c.AZP != policy.ExpectedAudience {
		return ValidatedIDToken{}, ErrAuthorizedPartyMismatch
	}
	if policy.Now.After(c.ExpiresAt.Add(policy.MaxClockSkew)) {
		return ValidatedIDToken{}, ErrExpired
	}
	if c.ExpiresAt.Sub(policy.Now) > policy.MaxLifetime {
		return ValidatedIDToken{}, ErrLifetimeExceeded
	}
	if policy.ExpectedNonce != "" {
		if subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(policy.ExpectedNonce)) != 1 {
			return ValidatedIDToken{}, ErrNonceMismatch
		}
	}

	return ValidatedIDToken{
		Subject:    c.Subject,
		AuthTime:   c.AuthTime,
		ACR:        c.ACR,
		AMR:        c.AMR,
		Parameters: c.Parameters,
		ExpiresAt:  c.ExpiresAt,
	}, nil
}
