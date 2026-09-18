package token

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
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
	// token carried no confirmation claim at all (or was bound via
	// X5TS256 instead — the two are mutually exclusive, see
	// Confirmation's own doc comment). This package no longer checks it
	// against an expected value itself (see this struct's — and
	// AccessTokenValidatePolicy's — history: that check moved to the
	// resource package's Verify(), which enforces sender-constraint
	// binding once, uniformly, regardless of access-token format).
	// Callers that need sender-constraint enforcement must compare this
	// themselves.
	JKT string

	// X5TS256 is the token's "cnf.x5t#S256" claim (RFC 8705 §3.1), now
	// trusted, or "" if the token was bound via JKT instead (or not
	// bound at all). Mirrors JKT's own contract exactly, for mTLS
	// binding instead of DPoP.
	X5TS256 string

	// Issuer and Audience are the token's "iss" and "aud" claims,
	// already checked against policy.ExpectedIssuer/ExpectedAudience
	// above. Exposed the same way ValidatedIDToken's own Issuer/
	// Audience are: for the caller's own telemetry, audit, or display,
	// not for re-validation.
	Issuer   string
	Audience []string

	// IssuedAt is the token's "iat" — required to be present and
	// well-formed for parsing to succeed at all, but not itself checked
	// against any policy here (RFC 9068 defines no equivalent to an ID
	// token's max-age-since-iat check). Exposed for a caller's own
	// telemetry, mirroring ValidatedIDToken.IssuedAt's identical
	// contract.
	IssuedAt time.Time
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

	var jkt, x5ts256 string
	if c.Confirmation != nil {
		jkt = c.Confirmation.JKT
		x5ts256 = c.Confirmation.X5TS256
	}

	return ValidatedAccessToken{
		Subject:    c.Subject,
		ClientID:   c.ClientID,
		Scope:      c.Scope,
		Parameters: c.Parameters,
		ExpiresAt:  c.ExpiresAt,
		JTI:        c.JTI,
		JKT:        jkt,
		X5TS256:    x5ts256,
		Issuer:     c.Issuer,
		Audience:   c.Audience,
		IssuedAt:   c.IssuedAt,
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

// ParseIDToken parses an ID token without verifying its signature,
// rejecting one longer than jose.DefaultMaxCompactBytes.
func ParseIDToken(tok string) (IDToken, error) {
	return ParseIDTokenMax(tok, jose.DefaultMaxCompactBytes)
}

// ParseIDTokenMax is ParseIDToken with an explicit size ceiling, in
// bytes, instead of jose.DefaultMaxCompactBytes — for a caller whose
// issuer may legitimately return an ID token shaped by however many
// scopes/claims it granted, rather than a fixed handful.
func ParseIDTokenMax(tok string, maxBytes int) (IDToken, error) {
	compact, err := jose.ParseCompactMax(tok, maxBytes)
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

	// AccessToken is the access token issued alongside this ID token in
	// the same response (OIDC Core §3.1.3.6) — checked against the
	// token's own at_hash claim when present. Every flow this module
	// implements returns access_token together with id_token (this
	// package never validates an ID token issued from the Authorization
	// Endpoint alone, the one case OIDC Core exempts from requiring
	// at_hash at all), so a caller normally always has one to supply
	// here. Leaving this empty while the token actually carries an
	// at_hash claim is treated as a caller error, not silently
	// tolerated — see Validate's own at_hash handling.
	AccessToken string

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

	// IssuedAt is the token's "iat" — required to be present and
	// well-formed for parsing to succeed at all, and bounded by
	// MaxLifetime the same way ExpiresAt is (see Validate's own iat
	// check). Exposed for a caller's own telemetry or cross-checks
	// beyond that one bound.
	IssuedAt time.Time

	// Issuer, Audience, Nonce and AZP are the token's "iss", "aud",
	// "nonce" and "azp" claims, already checked against
	// policy.ExpectedIssuer/ExpectedAudience/TrustedAudiences/
	// ExpectedNonce (and, for AZP, policy.ExpectedAudience — see
	// Validate's own azp check) below. Exposed the same way IssuedAt
	// is: for a caller's own telemetry, audit, or display, not for
	// re-validation — Validate has already done that. Nonce and AZP are
	// "" when the token carried neither.
	Issuer   string
	Audience []string
	Nonce    string
	AZP      string
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
	// OIDC Core §3.1.3.7 step 10: iat "can be used to reject tokens that
	// were issued too far away from the current time" — the same
	// MaxLifetime bound already governing how far exp may sit in the
	// future, applied symmetrically to how far iat may sit in the past,
	// mirroring requestobject.VerifyPolicy's own nbf-vs-exp symmetry
	// under one shared window.
	if policy.Now.Sub(c.IssuedAt) > policy.MaxLifetime {
		return ValidatedIDToken{}, ErrIssuedAtTooOld
	}
	if policy.ExpectedNonce != "" {
		if subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(policy.ExpectedNonce)) != 1 {
			return ValidatedIDToken{}, ErrNonceMismatch
		}
	}
	// OIDC Core §3.1.3.6: at_hash, when present, binds this ID token to
	// one specific access token — "the Client MUST validate the access
	// token by calculating its hash... and comparing it to the value of
	// the at_hash Claim." A token with no at_hash at all is not itself
	// rejected here: OIDC Core marks it REQUIRED only "except when the
	// ID Token is issued from the Authorization Endpoint" — this
	// package has no way to know from the claims alone whether an
	// issuer that omitted it did so because it doesn't implement this
	// check, and rejecting every such token would make this a stricter
	// contract than what was actually reported missing (see this
	// field's own doc comment for the narrower, present-but-unusable
	// case this package does still treat as an error).
	if c.ATHash != "" {
		if policy.AccessToken == "" {
			return ValidatedIDToken{}, fmt.Errorf("token: id token carries at_hash but no access token was supplied to check it against")
		}
		wantHash, err := computeATHash(policy.AccessToken, policy.Algorithm)
		if err != nil {
			return ValidatedIDToken{}, fmt.Errorf("token: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(c.ATHash), []byte(wantHash)) != 1 {
			return ValidatedIDToken{}, ErrAccessTokenHashMismatch
		}
	}

	return ValidatedIDToken{
		Subject:    c.Subject,
		AuthTime:   c.AuthTime,
		ACR:        c.ACR,
		AMR:        c.AMR,
		Parameters: c.Parameters,
		ExpiresAt:  c.ExpiresAt,
		IssuedAt:   c.IssuedAt,
		Issuer:     c.Issuer,
		Audience:   c.Audience,
		Nonce:      c.Nonce,
		AZP:        c.AZP,
	}, nil
}

// computeATHash implements OIDC Core §3.1.3.6's at_hash construction:
// "the base64url encoding of the left-most half of the hash of the
// octets of the ASCII representation of the access_token value, where
// the hash algorithm used is the hash algorithm used in the alg Header
// Parameter of the ID Token's JOSE Header" — ES256/PS256 both use
// SHA-256 (RFC 7518 §3.4/§3.5).
//
// EdDSA has no such pairing defined by JOSE itself — OIDC Core predates
// RFC 8037 and never mentions EdDSA at all, and a 2021 OpenID WG
// proposal to standardize an EdDSA-to-hash mapping was never formally
// ratified (its tracking issue, bitbucket.org/openid/connect/issues/1125,
// is now dead). This is a real gap, not a detail this package failed to
// find — so SHA-512 for Ed25519 (the only EdDSA variant this module
// supports — see fapi.EdDSA's own doc comment) is convention, not a
// spec requirement: it's what Ed25519 itself already uses internally
// for key expansion and signing, and independently-written
// implementations converged on it anyway, rather than each inferring a
// hash from the key type in their own incompatible way — confirmed
// against panva/oidc-token-hash (the reference implementation the OIDC
// ecosystem generally defers to for this), coreos/go-oidc, and at least
// one production IdP's own public docs. Ed448 would need SHAKE256 by
// the same convention, but this module has no Ed448 support to need it.
func computeATHash(accessToken string, alg fapi.SignatureAlgorithm) (string, error) {
	var sum []byte
	switch alg {
	case fapi.ES256, fapi.PS256:
		digest := sha256.Sum256([]byte(accessToken))
		sum = digest[:]
	case fapi.EdDSA:
		digest := sha512.Sum512([]byte(accessToken))
		sum = digest[:]
	default:
		return "", fmt.Errorf("at_hash: unsupported signature algorithm %v", alg)
	}
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}
