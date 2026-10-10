package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/grantrevocation"
)

// TokenRevocationRequest is a request to this server's token revocation
// endpoint (RFC 7009), for RevokeToken. Build it from an *http.Request
// with TokenRevocationRequestFromHTTP.
type TokenRevocationRequest struct {
	// HTTP is the request's form: "token", an optional
	// "token_type_hint", and the client's authentication parameters.
	HTTP FormRequest

	// ClientAttestations/ClientAttestationPoPs and PeerCertificate
	// authenticate the client exactly as at the token endpoint — see
	// AuthorizationCodeExchangeRequest. No DPoP proof is involved:
	// revocation isn't sender-constrained (RFC 9449 doesn't cover it).
	ClientAttestations    []string
	ClientAttestationPoPs []string
	PeerCertificate       *x509.Certificate
}

// TokenRevocationRequestFromHTTP reads a TokenRevocationRequest from r:
// its form, its client attestation headers and its TLS client
// certificate. An error is an *Error to write as the response.
func TokenRevocationRequestFromHTTP(r *http.Request) (TokenRevocationRequest, error) {
	parts, err := readHTTPRequestParts(r)
	return TokenRevocationRequest{
		HTTP:                  parts.HTTP,
		ClientAttestations:    parts.ClientAttestations,
		ClientAttestationPoPs: parts.ClientAttestationPoPs,
		PeerCertificate:       parts.PeerCertificate,
	}, err
}

// TokenRevocationResult is what a RevokeToken call revoked, for the
// embedder only: the endpoint's response is the same empty 200 whatever
// it says (RFC 7009 §2.2), and must stay so.
type TokenRevocationResult struct {
	// Revoked reports that this call revoked a live refresh token.
	Revoked bool

	// GrantID is that token's grant ID (GrantedAuthorization.GrantID,
	// IssueRefreshTokenRequest.GrantID), when it had one: the grant this
	// call ended, so the embedder can delete data it kept for it. Empty
	// unless Revoked. Two concurrent revocations of the same token can
	// both report it, so act on it idempotently.
	GrantID string
}

// RevokeToken serves the token revocation endpoint (RFC 7009,
// Config.Endpoints.Revocation). A nil error means the endpoint answers
// 200 with an empty body, whatever the result says; otherwise write the
// *Error as the response. The result tells the embedder what was
// revoked, and is never for the client.
//
// It authenticates the client by its registered method, exactly as the
// token endpoint does, then revokes the refresh token in "token" if this
// client may: one issued to it and, for a client authenticated by Client
// Attestation, bound to the same Client Instance Key (as
// RefreshAccessToken requires — draft-ietf-oauth-attestation-based-client-auth-07
// §10.3). Revoking a refresh token also revokes the authorization grant
// it came from, so the access tokens issued under it stop working too
// (RFC 7009 §2.1): the grant's GrantID if it has one (RevokeGrant) —
// which is why a GrantID must name one grant only
// (GrantedAuthorization.GrantID) — and, when Dependencies.Revocation
// can be read, the authorization code it was issued from, as code reuse
// revokes it.
//
// A token that is unknown, expired, already revoked, or another
// client's or client instance's is answered 200 and left as it is: RFC
// 7009 §2.2 answers an invalid token that way, and a response that told
// these apart would confirm the token exists to whoever presented it.
// For another client's token this deliberately departs from RFC 7009
// §2.1, which has the server refuse a token not issued to the
// requesting client with an error: that error too would tell the
// requester the token is live. The audit record (below) still tells the
// cases apart for the operator.
//
// Only refresh tokens can be revoked. A token in JWT form, or one sent
// with token_type_hint "access_token" that isn't a refresh token this
// client may revoke, is refused with unsupported_token_type (RFC 7009
// §2.2.1): access tokens are short-lived, and revoking one would need
// every resource server to check a per-token record. Revoke the grant
// instead (RevokeGrant). The hint is only a hint (RFC 7009 §2.1): a
// refresh token sent as "access_token" is still revoked.
//
// A grant is revoked before its refresh token is deleted, so a failure
// part way (answered server_error) never leaves the grant's access
// tokens working with the refresh token gone: a retry finds the token
// and finishes, or the grant is already revoked and the token with it.
//
// Every call records an AuditEventRevokeToken.
func (s *Server) RevokeToken(ctx context.Context, req TokenRevocationRequest) (TokenRevocationResult, error) {
	if s.cfg.Endpoints.Revocation.IsZero() {
		return TokenRevocationResult{}, s.revocationFail(ctx, "", newError(ErrorServerError, 500, "token revocation is not enabled (Config.Endpoints.Revocation)", nil))
	}
	params, err := formParametersToMap(req.HTTP.Parameters)
	if err != nil {
		return TokenRevocationResult{}, s.revocationFail(ctx, "", newError(ErrorInvalidRequest, 400, "the request's parameters are duplicated, too many, or too large", err))
	}
	client, _, authn, authErr := s.authenticateRequest(ctx, params, requestCredentials{
		PeerCertificate: req.PeerCertificate, ClientAttestations: req.ClientAttestations, ClientAttestationPoPs: req.ClientAttestationPoPs,
	}, []fapi.URL{s.cfg.Endpoints.Revocation}, []fapi.URL{s.cfg.MTLSEndpoints.Revocation})
	if authErr != nil {
		return TokenRevocationResult{}, s.revocationFail(ctx, "", authErr)
	}
	token := params["token"]
	if token == "" {
		return TokenRevocationResult{}, s.revocationFail(ctx, client.ID(), newError(ErrorInvalidRequest, 400, "token is required", nil))
	}
	unsupported := newError(ErrorUnsupportedTokenType, 400, "only refresh tokens can be revoked", nil)
	if strings.Contains(token, ".") {
		return TokenRevocationResult{}, s.revocationFail(ctx, client.ID(), unsupported)
	}
	result, revokeErr := s.revokeRefreshToken(ctx, client.ID(), authn.InstanceKey, token)
	if revokeErr != nil {
		return TokenRevocationResult{}, s.revocationFail(ctx, client.ID(), revokeErr)
	}
	// The hint only orders the search (RFC 7009 §2.1), so a refresh
	// token sent as "access_token" is still revoked above. One that
	// isn't a refresh token this client may revoke is answered as the
	// access token it was said to be, which this server can't revoke.
	if !result.Revoked && params["token_type_hint"] == "access_token" {
		return TokenRevocationResult{}, s.revocationFail(ctx, client.ID(), unsupported)
	}
	// The client gets the same 200 either way; the audit record says
	// whether anything was revoked, so an operator can see requests for
	// tokens that are unknown or not the client's.
	description := ""
	if !result.Revoked {
		description = "not revoked"
	}
	s.audit(ctx, AuditEventRevokeToken, client.ID(), AuditOutcomeSuccess, description)
	return result, nil
}

// revokeRefreshToken revokes rawToken if it is a live refresh token
// clientID (and, when set, the client instance holding instanceKey) may
// revoke, and does nothing otherwise — see RevokeToken. It reports
// what it revoked.
func (s *Server) revokeRefreshToken(ctx context.Context, clientID fapi.ClientID, instanceKey, rawToken string) (TokenRevocationResult, *Error) {
	grant, _, grantErr := s.redeemRefreshGrant(ctx, clientID, instanceKey, rawToken)
	if grantErr != nil {
		if grantErr.Code() == ErrorServerError {
			// A stored grant that won't decode, or a revocation check
			// that failed: a fault, not a token this client can't revoke.
			return TokenRevocationResult{}, grantErr
		}
		// Unknown, expired, revoked, another client's or instance's, or
		// its grant already revoked: nothing this client may revoke.
		return TokenRevocationResult{}, nil
	}
	// The grant goes first: if that fails, the refresh token is still
	// there for the client to revoke again, and once it succeeds the
	// token is refused with its grant even if deleting it then fails.
	// The other order could leave the token deleted but the grant's
	// access tokens working, with a retry answered "not revoked".
	if grant.GrantID != "" {
		if err := s.RevokeGrant(ctx, grant.GrantID); err != nil {
			return TokenRevocationResult{}, newError(ErrorServerError, 500, "failed to revoke the refresh token's grant", err)
		}
	}
	if revokeErr := s.revokeCodeGrant(ctx, grant.CodeGrantID); revokeErr != nil {
		return TokenRevocationResult{}, revokeErr
	}
	if err := s.deps.Grants.RevokeRefreshToken(ctx, sha256.Sum256([]byte(rawToken))); err != nil {
		return TokenRevocationResult{}, newError(ErrorServerError, 500, "failed to revoke the refresh token", err)
	}
	return TokenRevocationResult{Revoked: true, GrantID: grant.GrantID}, nil
}

// revokeCodeGrant revokes the authorization code grant codeGrantID
// (grantRecord.CodeGrantID), as code reuse does, so every access token
// issued from that code, or later from its refresh tokens, is refused
// even when the application set no GrantID. Without a revocation store
// resource servers can read there is nothing to revoke against, and
// the refresh token's deletion alone has to do.
func (s *Server) revokeCodeGrant(ctx context.Context, codeGrantID string) *Error {
	if codeGrantID == "" {
		return nil
	}
	if _, ok := s.grantRevocationReader(); !ok {
		return nil
	}
	until := s.deps.Clock.Now().Add(s.grantRevocationHorizon())
	if err := s.deps.Revocation.Revoke(ctx, grantrevocation.CodeKey(codeGrantID), until); err != nil {
		return newError(ErrorServerError, 500, "failed to revoke the refresh token's grant", err)
	}
	return nil
}

func (s *Server) revocationFail(ctx context.Context, clientID fapi.ClientID, err *Error) error {
	s.audit(ctx, AuditEventRevokeToken, clientID, AuditOutcomeFailure, string(err.Code()))
	return err
}
