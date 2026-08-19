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

	// ExpectedThumbprint, if non-nil, requires the token to be
	// sender-constrained to this DPoP key: its cnf.jkt claim must equal
	// ExpectedThumbprint exactly, and a token with no cnf.jkt at all is
	// rejected. Leave nil to skip sender-constraint checking (e.g. for a
	// bearer-token deployment); that policy choice belongs above this
	// package.
	ExpectedThumbprint *jose.Thumbprint

	Now          time.Time
	MaxLifetime  time.Duration
	MaxClockSkew time.Duration
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
	if c.Audience != policy.ExpectedAudience {
		return ValidatedAccessToken{}, ErrAudienceMismatch
	}
	if policy.Now.After(c.ExpiresAt.Add(policy.MaxClockSkew)) {
		return ValidatedAccessToken{}, ErrExpired
	}
	if c.ExpiresAt.Sub(policy.Now) > policy.MaxLifetime {
		return ValidatedAccessToken{}, ErrLifetimeExceeded
	}

	if policy.ExpectedThumbprint != nil {
		if c.Confirmation == nil {
			return ValidatedAccessToken{}, ErrMissingConfirmation
		}
		want := policy.ExpectedThumbprint.String()
		if subtle.ConstantTimeCompare([]byte(c.Confirmation.JKT), []byte(want)) != 1 {
			return ValidatedAccessToken{}, ErrConfirmationMismatch
		}
	}

	return ValidatedAccessToken{
		Subject:    c.Subject,
		ClientID:   c.ClientID,
		Scope:      c.Scope,
		Parameters: c.Parameters,
		ExpiresAt:  c.ExpiresAt,
		JTI:        c.JTI,
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
	// claim must equal it exactly.
	ExpectedAudience string

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
	// OIDC Core §3.1.3.7 step 3: "aud... MAY contain an array with more
	// than one element. The ID Token MUST be rejected... if it contains
	// additional audiences not trusted by the Client." This package
	// implements no mechanism for a caller to name any audience as
	// trusted besides itself, so every element must equal
	// ExpectedAudience — not merely contain it — until one is added.
	for _, aud := range c.Audience {
		if aud != policy.ExpectedAudience {
			return ValidatedIDToken{}, ErrAudienceMismatch
		}
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
