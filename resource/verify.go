package resource

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/grantrevocation"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/storage"
)

// VerifyRequest describes one incoming request to verify: the HTTP
// method and target URL it was made against, its raw Authorization
// header value, and either its raw DPoP header value or the TLS client
// certificate presented on the connection it arrived on — whichever
// the resolved access token turns out to actually need (see Verify's
// own doc comment). Every access token this package accepts is
// sender-constrained one way or the other; a bearer token presented
// with neither a DPoP proof nor a client certificate is rejected.
type VerifyRequest struct {
	Method string
	URL    *url.URL

	// Authorization is the request's one Authorization header. A request
	// with more than one is malformed (RFC 9110 §5.3: the field isn't a
	// list): VerifyRequestFromHTTP marks it so for Verify to refuse, and
	// an adapter filling this field itself refuses it first, rather than
	// passing one of them on. A proxy in front might act on another.
	Authorization string

	// DPoPProofs is every "DPoP" header value the request carried, in
	// receipt order — pass net/http's own Header.Values("DPoP")
	// directly, not Header.Get, which silently collapses multiple
	// values down to the first instead of letting Verify reject the
	// request as RFC 9449 §7.1 requires. Empty means no DPoP header was
	// present at all. Only relevant when Authorization uses the "DPoP"
	// scheme.
	DPoPProofs []string

	// PeerCertificate is the TLS client certificate presented on the
	// connection this request arrived on, if any. Only relevant when
	// Authorization uses the "Bearer" scheme (RFC 8705 §3.4 — an
	// mTLS-bound access token is presented as an ordinary Bearer token;
	// there is no additional signed proof artifact the way DPoP has
	// one). An HTTP adapter reads this straight from the connection's
	// own TLS state; this package never terminates TLS itself.
	//
	// Behind a proxy that terminates TLS, set it from however the proxy
	// forwards the certificate — but only from your own proxy, over a
	// hop the client can't reach or forge, with the proxy removing any
	// copy of its forwarding header the client sent. A certificate is
	// public, so having one proves nothing; only the TLS handshake
	// proves the client holds its private key. A certificate taken
	// from anything the client controls lets anyone present a stolen
	// certificate-bound token.
	PeerCertificate *x509.Certificate

	// repeatedAuthorization is VerifyRequestFromHTTP's mark of a request
	// with more than one Authorization header.
	repeatedAuthorization bool
}

// AuthorizationContext is what Verify returns for a successfully
// verified request: who is acting (Subject), on behalf of which client
// (ClientID), with what granted scope, and any additional claims the
// access token carried.
type AuthorizationContext struct {
	Subject   string
	ClientID  string
	Scopes    []string
	Claims    map[string]json.RawMessage
	ExpiresAt time.Time

	// Key is the access token's revocation-lookup identifier (see
	// ResolvedAccessToken.Key), exposed for a caller's own audit
	// logging — it's already available at this point (see
	// Dependencies.Revocation), so surfacing it costs nothing.
	Key string

	// Issuer, Audience and IssuedAt mirror ResolvedAccessToken's own
	// fields of the same name — see that type's doc comment, including
	// why they're always zero for an opaque access token.
	Issuer   string
	Audience []string
	IssuedAt time.Time

	// NextDPoPNonce is a freshly issued DPoP nonce the caller should set
	// as this response's own DPoP-Nonce header, so its next call already
	// carries a valid one instead of needing its own challenge/retry
	// round trip (RFC 9449 §8's own proactive-refresh recommendation):
	// SetDPoPNonce does that.
	// Always "" when Dependencies.Nonces is nil (nonce-challenge support
	// disabled); otherwise always populated on a successful Verify.
	NextDPoPNonce string

	// usedDPoP records that the request presented its token with the
	// DPoP scheme, so NewInsufficientScopeError can answer in kind.
	usedDPoP bool
}

// Verify checks req's Authorization header and its sender-constraining
// credential — a DPoP proof or a presented mTLS client certificate —
// together: token verification is inseparable from HTTP request
// context, so there is no bare VerifyJWT or VerifyDPoP entry point; see
// ARCHITECTURE.md, "Resource server verifies in HTTP context, not in
// isolation". Which credential is expected is driven by the
// Authorization scheme on the wire ("DPoP" or "Bearer" — RFC 8705
// §3.4's own convention for mTLS-bound tokens), then cross-checked
// against the resolved access token's own SenderConstrain once
// resolved, so a token bound one way can never be redeemed by
// presenting the other credential. On success it returns the
// AuthorizationContext the caller is granted; on failure it returns a
// typed Error describing what's safe to expose to the caller of the
// protected API.
//
// A request presenting no credentials at all — no Authorization header,
// or a scheme this verifier doesn't accept — fails with an *Error whose
// Code is empty: RFC 6750 §3.1 and RFC 9449 §7.2 answer it with 401 and
// a challenge carrying no error information (see Error.WriteJSON).
func (v *Verifier) Verify(ctx context.Context, req VerifyRequest) (AuthorizationContext, error) {
	authz, usedDPoP, err := v.verify(ctx, req)
	if err != nil && usedDPoP {
		// RFC 9449 §7.2: the request used the DPoP scheme, so its error
		// goes in a DPoP challenge. A copy: an AccessTokenResolver's own
		// *Error isn't this method's to modify.
		var e *Error
		if errors.As(err, &e) {
			c := *e
			c.dpopChallenge = true
			return AuthorizationContext{}, &c
		}
	}
	return authz, err
}

// verify is Verify, also reporting whether the request used the DPoP
// scheme, which decides the challenge an error is sent with.
func (v *Verifier) verify(ctx context.Context, req VerifyRequest) (AuthorizationContext, bool, error) {
	dpopProof, raw, usedDPoP, perr := parseAuthorization(req)
	if perr != nil {
		return AuthorizationContext{}, usedDPoP, perr
	}

	now := v.deps.Clock.Now()

	senderConstrain, verifiedProof, certThumbprint, verr := v.resolveCredential(ctx, req, dpopProof, raw, usedDPoP, now)
	if verr != nil {
		return AuthorizationContext{}, usedDPoP, verr
	}

	resolved, verr := v.resolveAccessToken(ctx, raw, now)
	if verr != nil {
		return AuthorizationContext{}, usedDPoP, verr
	}
	if verr := v.checkBinding(resolved, senderConstrain, verifiedProof, certThumbprint, now); verr != nil {
		return AuthorizationContext{}, usedDPoP, verr
	}
	if verr := v.checkNotRevoked(ctx, resolved); verr != nil {
		return AuthorizationContext{}, usedDPoP, verr
	}

	if senderConstrain == storage.SenderConstrainDPoP {
		if verr := v.consumeDPoPProof(ctx, verifiedProof, now); verr != nil {
			return AuthorizationContext{}, usedDPoP, verr
		}
	}

	var nextNonce string
	if v.deps.Nonces != nil && senderConstrain == storage.SenderConstrainDPoP {
		var err error
		nextNonce, err = v.issueDPoPNonce(ctx, now)
		if err != nil {
			return AuthorizationContext{}, usedDPoP, newError(ErrorServerError, 500, "failed to issue dpop nonce", err)
		}
	}

	return AuthorizationContext{
		Subject:       resolved.Subject,
		ClientID:      resolved.ClientID,
		Scopes:        resolved.Scopes,
		Claims:        resolved.Claims,
		ExpiresAt:     resolved.ExpiresAt,
		Key:           resolved.Key,
		Issuer:        resolved.Issuer,
		Audience:      resolved.Audience,
		IssuedAt:      resolved.IssuedAt,
		NextDPoPNonce: nextNonce,
		usedDPoP:      usedDPoP,
	}, usedDPoP, nil
}

// parseAuthorization checks req's shape and splits its Authorization
// header: the one DPoP proof, if any, the access token, and whether the
// DPoP scheme was used. usedDPoP is set on error too, for the challenge
// the error is sent with.
func parseAuthorization(req VerifyRequest) (dpopProof, raw string, usedDPoP bool, err *Error) {
	if req.Method == "" {
		return "", "", false, newError(ErrorInvalidRequest, 400, "method is required", nil)
	}
	if req.URL == nil {
		return "", "", false, newError(ErrorInvalidRequest, 400, "url is required", nil)
	}

	dpopProof, dpopOK := dpop.ResolveHeaderValues(req.DPoPProofs)
	if !dpopOK {
		// RFC 9449 §4.3 check 1: a proof is valid only as the one DPoP
		// header field.
		return "", "", true, newError(ErrorInvalidDPoPProof, 401, "multiple DPoP proofs are not permitted", nil)
	}

	if req.repeatedAuthorization {
		return "", "", false, newError(ErrorInvalidRequest, 400, "multiple Authorization headers are not permitted", nil)
	}
	if strings.TrimSpace(req.Authorization) == "" {
		return "", "", false, noCredentials("no Authorization header")
	}
	scheme, raw, _ := strings.Cut(req.Authorization, " ")
	usedDPoP = strings.EqualFold(scheme, "DPoP")
	if !usedDPoP && !strings.EqualFold(scheme, "Bearer") {
		return "", "", false, noCredentials("authorization scheme is neither DPoP nor Bearer")
	}
	if raw == "" {
		return "", "", usedDPoP, newError(ErrorInvalidRequest, 400, "authorization header has no access token", nil)
	}
	return dpopProof, raw, usedDPoP, nil
}

// resolveAccessToken resolves raw through Dependencies.AccessTokens.
func (v *Verifier) resolveAccessToken(ctx context.Context, raw string, now time.Time) (ResolvedAccessToken, *Error) {
	resolved, err := v.deps.AccessTokens.ResolveAccessToken(ctx, ResolveAccessTokenRequest{Raw: raw, Now: now})
	if err != nil {
		// A *Error carries its own exposure (see AccessTokenResolver's
		// own doc comment on why that's the implementation's call, not
		// this method's) — propagate it unchanged. A bare error (a
		// third-party AccessTokenResolver that didn't follow that
		// convention) falls back to the same invalid_token/401 every
		// other rejection here defaults to, except a cancelled or
		// timed-out context, which is a 500 (see lookupError).
		if rerr, ok := err.(*Error); ok {
			return ResolvedAccessToken{}, rerr
		}
		return ResolvedAccessToken{}, lookupError(err)
	}
	return resolved, nil
}

// checkBinding checks that resolved is bound to the credential the
// request presented, and hasn't expired.
func (v *Verifier) checkBinding(resolved ResolvedAccessToken, senderConstrain storage.SenderConstrain, verifiedProof dpop.VerifiedProof, certThumbprint string, now time.Time) *Error {
	// A token bound one way can't be redeemed by presenting the other
	// credential — checked explicitly, not left to an incidental
	// thumbprint mismatch, since a DPoP JKT and an mTLS x5t#S256 live in
	// unrelated value spaces and a caller shouldn't have to reason about
	// whether they could ever collide.
	if resolved.SenderConstrain != senderConstrain {
		return newError(ErrorInvalidToken, 401, "access token is not bound via the presented credential's mechanism", nil)
	}

	// Sender-constraint binding and ordinary expiry are enforced here,
	// once, uniformly for every AccessTokenResolver implementation —
	// see that interface's own doc comment for why this moved out of
	// each implementation. Constant-time: resolved.Thumbprint (from an
	// implementation that never set it) is "", which always
	// length-mismatches a real presented credential's own thumbprint
	// encoding (never empty) and so always fails closed. The one empty
	// presented value — a Bearer request with no client certificate —
	// is refused explicitly, so it can never equal that "".
	var presented string
	if senderConstrain == storage.SenderConstrainMTLS {
		presented = certThumbprint
	} else {
		presented = verifiedProof.Thumbprint.String()
	}
	if presented == "" || subtle.ConstantTimeCompare([]byte(resolved.Thumbprint), []byte(presented)) != 1 {
		return newError(ErrorInvalidToken, 401, "access token is not bound to the presented credential", nil)
	}
	if now.After(resolved.ExpiresAt.Add(v.cfg.Limits.MaxClockSkew)) {
		return newError(ErrorInvalidToken, 401, "access token has expired", nil)
	}
	return nil
}

// checkNotRevoked checks that neither resolved itself nor the grant it
// was issued from has been revoked.
func (v *Verifier) checkNotRevoked(ctx context.Context, resolved ResolvedAccessToken) *Error {
	revoked, err := v.deps.Revocation.IsRevoked(ctx, resolved.Key)
	if err != nil {
		return newError(ErrorServerError, 500, "failed to check token revocation", err)
	}
	if revoked {
		return newError(ErrorInvalidToken, 401, "access token has been revoked", nil)
	}
	return v.checkGrantNotRevoked(ctx, resolved.Claims)
}

// resolveCredential verifies whichever sender-constraining credential
// scheme (the Authorization header's own DPoP/Bearer distinction —
// RFC 8705 §3.4's convention for mTLS-bound tokens) demands, and
// reports back which SenderConstrain the caller must now cross-check
// the resolved access token against. Split out of Verify purely to keep
// that method's own token-resolution/binding/revocation pipeline
// readable — this is the one genuinely separable sub-task within it.
func (v *Verifier) resolveCredential(ctx context.Context, req VerifyRequest, dpopProof, raw string, usedDPoP bool, now time.Time) (storage.SenderConstrain, dpop.VerifiedProof, string, *Error) {
	if usedDPoP {
		if dpopProof == "" {
			return 0, dpop.VerifiedProof{}, "", newError(ErrorInvalidRequest, 400, "DPoP header is required", nil)
		}
		// No Replay here: recording the jti, like checking the nonce,
		// writes to storage, so both wait until consumeDPoPProof, after
		// the access token is known to be valid and bound to this
		// proof's key. A proof anyone can sign with their own key and a
		// made-up token must not be able to write to either store.
		verifiedProof, err := dpop.Verify(ctx, dpop.VerifyRequest{
			Proof:        dpopProof,
			Method:       req.Method,
			URL:          req.URL,
			AccessToken:  raw,
			Now:          now,
			MaxProofAge:  v.cfg.Limits.MaxDPoPProofAge,
			MaxClockSkew: v.cfg.Limits.MaxClockSkew,
		})
		if err != nil {
			return 0, dpop.VerifiedProof{}, "", newError(ErrorInvalidDPoPProof, 401, "DPoP proof verification failed", err)
		}
		return storage.SenderConstrainDPoP, verifiedProof, "", nil
	}
	// Bearer: RFC 8705 §3.4's presentation of an mTLS-bound token. With
	// no certificate on the connection the thumbprint stays "", and the
	// request is refused once the token is resolved: RFC 8705 §3 answers
	// a certificate that doesn't match the token's with 401
	// invalid_token, and no certificate matches none. Unlike a missing
	// DPoP header under the DPoP scheme, nothing is missing from the
	// HTTP request itself, so this isn't invalid_request.
	if req.PeerCertificate == nil {
		return storage.SenderConstrainMTLS, dpop.VerifiedProof{}, "", nil
	}
	return storage.SenderConstrainMTLS, dpop.VerifiedProof{}, mtls.Thumbprint(req.PeerCertificate), nil
}

// consumeDPoPProof applies the checks on a DPoP proof that write to
// storage — the nonce challenge (RFC 9449 §9) and jti replay detection —
// once Verify has established that the access token is valid, unrevoked
// and bound to the proof's key. Done any earlier, an unauthenticated
// caller could make every request write a nonce or jti record. The nonce
// comes first, so a proof that only lacks a current nonce doesn't also
// spend its jti.
func (v *Verifier) consumeDPoPProof(ctx context.Context, proof dpop.VerifiedProof, now time.Time) *Error {
	if v.deps.Nonces != nil {
		if challenge := v.checkDPoPNonce(ctx, proof.Nonce, now); challenge != nil {
			return challenge
		}
	}
	if err := v.dpopReplayChecker().UseOnce(ctx, proof.JTI, proof.IssuedAt.Add(v.cfg.Limits.MaxDPoPProofAge)); err != nil {
		return newError(ErrorInvalidDPoPProof, 401, "DPoP proof verification failed", fmt.Errorf("dpop: replay check: %w", err))
	}
	return nil
}

// checkGrantNotRevoked refuses an access token whose grant has been
// revoked (server.RevokeGrant): one carrying a grant_id claim the
// revocation store records as revoked. A token without one is
// unaffected — its grant has no ID to revoke it by.
func (v *Verifier) checkGrantNotRevoked(ctx context.Context, claims map[string]json.RawMessage) *Error {
	raw, ok := claims[grantrevocation.Claim]
	if !ok {
		return nil
	}
	var grantID string
	if err := json.Unmarshal(raw, &grantID); err != nil || grantID == "" {
		return newError(ErrorInvalidToken, 401, "access token's grant_id is malformed", err)
	}
	revoked, err := v.deps.Revocation.IsRevoked(ctx, grantrevocation.Key(grantID))
	if err != nil {
		return newError(ErrorServerError, 500, "failed to check grant revocation", err)
	}
	if revoked {
		return newError(ErrorInvalidToken, 401, "access token's grant has been revoked", nil)
	}
	return nil
}
