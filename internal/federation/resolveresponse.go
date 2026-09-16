package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// resolveResponseJWTType is the JWS "typ" header value every Resolve
// Response JWT MUST carry (OpenID Federation 1.0 §8.3.2: "explicitly
// typed by setting the typ header parameter to resolve-response+jwt to
// prevent cross-JWT confusion, per Section 3.11 of [RFC8725]. Resolve
// responses without a typ header parameter or with a different typ
// value MUST be rejected").
const resolveResponseJWTType = "resolve-response+jwt"

// ResolveResponseClaims is a parsed Resolve Response JWT payload
// (OpenID Federation 1.0 §8.3.2).
type ResolveResponseClaims struct {
	Issuer  string
	Subject string

	IssuedAt  time.Time
	ExpiresAt time.Time

	// Metadata is the "metadata" claim — the subject's Resolved
	// Metadata, per the requested Entity Type(s), exactly as
	// Claims.Metadata describes.
	Metadata map[string]json.RawMessage

	// TrustChain is the "trust_chain" claim — the raw compact-serialized
	// Entity Statement JWTs composing the Trust Chain from the subject
	// to the selected Trust Anchor, in that order, exactly as received.
	// This package does not itself re-verify each entry: trust in this
	// response already rests on Verify's own signature check against a
	// key established independently of anything the response itself
	// claims (see federation.Resolver.ResolveViaEndpoint, this
	// package's own caller for the "how" of that). A caller wanting to
	// independently confirm which Trust Anchor was actually used, or
	// perform its own deeper audit, can still parse these entries
	// itself with Parse.
	TrustChain []string

	// TrustMarks is the "trust_marks" claim, if present — Trust Marks
	// the resolver already verified as valid and issued by an issuer the
	// queried Trust Anchor trusts for that type (§8.3: "The response set
	// MUST include only verified Trust Marks"). Unlike Claims.TrustMarks
	// (an Entity Configuration's own, self-asserted and unverified
	// "trust_marks" claim), these arrive pre-vetted by the resolver
	// itself — still parsed here as raw RawTrustMark wrappers for a
	// consistent shape, not because this package re-verifies them again.
	TrustMarks []RawTrustMark
}

// ResolveResponse is a parsed, but not yet signature-verified, Resolve
// Response JWT — the same "claims safe to read as lookup keys, never as
// a basis for trust until Verify succeeds" contract every other type in
// this package already establishes.
type ResolveResponse struct {
	compact jose.Compact
	claims  ResolveResponseClaims
}

// ParseResolveResponse parses token without verifying its signature.
func ParseResolveResponse(token string) (ResolveResponse, error) {
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return ResolveResponse{}, fmt.Errorf("federation: %w", err)
	}
	if compact.Header.Type != resolveResponseJWTType {
		return ResolveResponse{}, ErrResolveResponseWrongType
	}
	claims, err := parseResolveResponseClaims(compact.Payload)
	if err != nil {
		return ResolveResponse{}, err
	}
	return ResolveResponse{compact: compact, claims: claims}, nil
}

// KeyID returns the response header's "kid", or "" if absent. Untrusted
// until Verify succeeds; use only to select which of the issuer's
// published keys to verify against.
func (r ResolveResponse) KeyID() string { return r.compact.Header.KeyID }

// Algorithm returns the algorithm the response header claims to use.
// Untrusted until Verify succeeds — a caller must still supply the
// algorithm it expects via ResolveResponseVerifyPolicy rather than
// trusting this value, exactly as jose.Compact.Verify requires.
func (r ResolveResponse) Algorithm() fapi.SignatureAlgorithm { return r.compact.Header.Algorithm }

// ClaimedIssuer returns the response's unverified "iss" claim, for use
// as a lookup key only (e.g. which entity's published keys to resolve
// candidates from before Verify runs).
func (r ResolveResponse) ClaimedIssuer() string { return r.claims.Issuer }

// ResolveResponseVerifyPolicy is the set of checks Verify enforces
// against a ResolveResponse.
type ResolveResponseVerifyPolicy struct {
	// ExpectedIssuer is the entity the caller is trying to authenticate
	// as having issued this response — the response's iss claim must
	// equal it exactly. In practice this is usually the same entity
	// whose keys were resolved to check the signature in the first
	// place; the meaningful security property comes from where those
	// keys came from, not from this comparison alone — the identical
	// relationship every other Verify in this package has between its
	// own ExpectedIssuer and the key source a caller resolved it from.
	ExpectedIssuer string

	// ExpectedSubject is the entity the caller actually queried about —
	// the response's sub claim must equal it exactly.
	ExpectedSubject string

	// Algorithm is the algorithm ExpectedIssuer is registered or
	// discovered to sign with. The response header's algorithm must
	// equal it exactly — this is what prevents algorithm-confusion
	// attacks, so it must come from the issuer's own published jwks
	// (via its kid), never trusted from the response itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate iat/exp against.
	Now time.Time

	// MaxClockSkew bounds how far in the future an iat claim may be, and
	// extends how long past exp a response is still accepted. Zero
	// means no tolerance.
	MaxClockSkew time.Duration
}

// Verify checks r's signature against pub and its claims against
// policy, returning the response's now-trusted claims.
func (r ResolveResponse) Verify(pub crypto.PublicKey, policy ResolveResponseVerifyPolicy) (ResolveResponseClaims, error) {
	if policy.ExpectedIssuer == "" {
		return ResolveResponseClaims{}, fmt.Errorf("federation: ExpectedIssuer is empty")
	}
	if policy.ExpectedSubject == "" {
		return ResolveResponseClaims{}, fmt.Errorf("federation: ExpectedSubject is empty")
	}
	if policy.Now.IsZero() {
		return ResolveResponseClaims{}, fmt.Errorf("federation: Now is zero")
	}

	if err := r.compact.Verify(pub, policy.Algorithm); err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("federation: %w", err)
	}
	c := r.claims

	if c.Issuer != policy.ExpectedIssuer {
		return ResolveResponseClaims{}, ErrResolveResponseIssuerMismatch
	}
	if c.Subject != policy.ExpectedSubject {
		return ResolveResponseClaims{}, ErrResolveResponseSubjectMismatch
	}
	if policy.Now.After(c.ExpiresAt.Add(policy.MaxClockSkew)) {
		return ResolveResponseClaims{}, ErrResolveResponseExpired
	}
	if policy.Now.Before(c.IssuedAt.Add(-policy.MaxClockSkew)) {
		return ResolveResponseClaims{}, ErrResolveResponseNotYetValid
	}

	return c, nil
}

func parseResolveResponseClaims(payload []byte) (ResolveResponseClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, err := popRequiredString(raw, "iss")
	if err != nil {
		return ResolveResponseClaims{}, err
	}
	sub, err := popRequiredString(raw, "sub")
	if err != nil {
		return ResolveResponseClaims{}, err
	}
	iat, err := popRequiredInt64(raw, "iat")
	if err != nil {
		return ResolveResponseClaims{}, err
	}
	exp, err := popRequiredInt64(raw, "exp")
	if err != nil {
		return ResolveResponseClaims{}, err
	}
	metadataRaw, ok := raw["metadata"]
	if !ok {
		return ResolveResponseClaims{}, fmt.Errorf("%w: missing \"metadata\"", ErrMalformedClaims)
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("%w: metadata: %v", ErrMalformedClaims, err)
	}
	trustChainRaw, ok := raw["trust_chain"]
	if !ok {
		return ResolveResponseClaims{}, fmt.Errorf("%w: missing \"trust_chain\"", ErrMalformedClaims)
	}
	var trustChain []string
	if err := json.Unmarshal(trustChainRaw, &trustChain); err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("%w: trust_chain: %v", ErrMalformedClaims, err)
	}

	c := ResolveResponseClaims{
		Issuer: iss, Subject: sub,
		IssuedAt: time.Unix(iat, 0), ExpiresAt: time.Unix(exp, 0),
		Metadata: metadata, TrustChain: trustChain,
	}
	if trustMarksRaw, ok := raw["trust_marks"]; ok {
		var trustMarks []struct {
			TrustMarkType string `json:"trust_mark_type"`
			TrustMark     string `json:"trust_mark"`
		}
		if err := json.Unmarshal(trustMarksRaw, &trustMarks); err != nil {
			return ResolveResponseClaims{}, fmt.Errorf("%w: trust_marks: %v", ErrMalformedClaims, err)
		}
		c.TrustMarks = make([]RawTrustMark, len(trustMarks))
		for i, tm := range trustMarks {
			if tm.TrustMarkType == "" || tm.TrustMark == "" {
				return ResolveResponseClaims{}, fmt.Errorf("%w: trust_marks[%d]: trust_mark_type and trust_mark are both required", ErrMalformedClaims, i)
			}
			c.TrustMarks[i] = RawTrustMark{TrustMarkType: tm.TrustMarkType, TrustMark: tm.TrustMark}
		}
	}
	return c, nil
}

// CreateResolveResponseParams describes one Resolve Response to create
// (OpenID Federation 1.0 §8.3.2). This is a low-level signing primitive
// only — it does not itself perform a Trust Chain resolution or decide
// Metadata/TrustChain/TrustMarks; a caller (typically an entity acting
// as a resolve endpoint, having already resolved Subject some other
// way, e.g. via Resolver.Resolve) supplies those already computed.
type CreateResolveResponseParams struct {
	// Signer produces the response's signature — this entity's own
	// federation key.
	Signer crypto.Signer

	// Algorithm Signer signs with.
	Algorithm fapi.SignatureAlgorithm

	// KeyID is recorded in the response's "kid" header. Required —
	// OpenID Federation 1.0 §8.3.2: "The resolve response JWT MUST
	// include the kid (Key ID) header parameter."
	KeyID string

	// Issuer is the "iss" claim — this entity's own Entity Identifier,
	// the one operating the resolve endpoint that answered the request.
	Issuer string

	// Subject is the "sub" claim — the entity that was resolved.
	Subject string

	// Now is the response's issuance time ("iat").
	Now time.Time

	// Lifetime bounds how far in the future the response's own "exp"
	// claim is set, relative to Now. §8.3.2: exp "MUST be the minimum
	// of the exp value of the Trust Chain from which the resolve
	// response was derived, as well as any Trust Mark included in the
	// response" — computing that minimum is the caller's own
	// responsibility (this function has no opinion on how the
	// resolution it's reporting was performed); pass the
	// already-computed remaining lifetime here.
	Lifetime time.Duration

	// Metadata is the "metadata" claim — the subject's Resolved
	// Metadata. Required.
	Metadata map[string]json.RawMessage

	// TrustChain is the "trust_chain" claim — the raw compact-serialized
	// Entity Statement JWTs composing the Trust Chain from Subject to
	// the selected Trust Anchor, in that order. Required.
	TrustChain []string

	// TrustMarks is the "trust_marks" claim — every already-verified
	// Trust Mark to include (§8.3: "The response set MUST include only
	// verified Trust Marks" — verifying them is the caller's own
	// responsibility before they ever reach here). Optional.
	TrustMarks []RawTrustMark
}

// CreateResolveResponse builds and signs a Resolve Response JWT for p.
func CreateResolveResponse(p CreateResolveResponseParams) (string, error) {
	if p.Signer == nil {
		return "", fmt.Errorf("federation: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return "", fmt.Errorf("federation: invalid algorithm %v", p.Algorithm)
	}
	if p.KeyID == "" {
		return "", fmt.Errorf(`federation: key id is required (OpenID Federation 1.0 §8.3.2: "The resolve response JWT MUST include the kid (Key ID) header parameter")`)
	}
	if p.Issuer == "" {
		return "", fmt.Errorf("federation: issuer is empty")
	}
	if p.Subject == "" {
		return "", fmt.Errorf("federation: subject is empty")
	}
	if p.Now.IsZero() {
		return "", fmt.Errorf("federation: now is zero")
	}
	if p.Lifetime <= 0 {
		return "", fmt.Errorf("federation: lifetime must be positive")
	}
	if len(p.Metadata) == 0 {
		return "", fmt.Errorf("federation: metadata is empty")
	}
	if len(p.TrustChain) == 0 {
		return "", fmt.Errorf("federation: trust chain is empty")
	}

	claims := map[string]any{
		"iss": p.Issuer, "sub": p.Subject,
		"iat": p.Now.Unix(), "exp": p.Now.Add(p.Lifetime).Unix(),
		"metadata": p.Metadata, "trust_chain": p.TrustChain,
	}
	if p.TrustMarks != nil {
		trustMarks := make([]map[string]string, len(p.TrustMarks))
		for i, tm := range p.TrustMarks {
			trustMarks[i] = map[string]string{"trust_mark_type": tm.TrustMarkType, "trust_mark": tm.TrustMark}
		}
		claims["trust_marks"] = trustMarks
	}

	return signClaims(p.Signer, p.Algorithm, p.KeyID, resolveResponseJWTType, claims)
}
