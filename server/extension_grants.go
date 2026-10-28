package server

import (
	"context"
	"fmt"
	"slices"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// Parameters returns the request's form parameters, for an embedder
// serving a grant_type this package doesn't at the same endpoint (see
// Config.AdditionalGrantTypes). It applies the rules this package's own
// grants apply: a repeated parameter, or too many or too large ones, is
// refused with an invalid_request *Error. The one exception is RFC
// 8707's "resource", which a client may repeat: it isn't in the map at
// all, so it can't be read as one value when the client sent several.
// Read it with Resources.
func (t TokenEndpointRequest) Parameters() (map[string]string, error) {
	rest, _ := splitResourceParameters(t.parts.HTTP.Parameters)
	params, err := formParametersToMap(rest)
	if err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "the request's parameters are duplicated, too many, or too large", err)
	}
	return params, nil
}

// Resources returns the request's RFC 8707 "resource" parameters, in
// order: every one the client sent, which is what a check of the
// resources an embedder's grant may be used for has to look at. Pass
// them as IssueAccessTokenRequest.Resources and
// IssueRefreshTokenRequest.Resources, which refuse any the client or
// this server doesn't allow — every one, with resource indicators
// turned off (neither Config.Resources nor a ResourcePolicy). Nil when
// there are none, or when the request has more parameters than
// Parameters accepts.
func (t TokenEndpointRequest) Resources() []string {
	_, resources := splitResourceParameters(t.parts.HTTP.Parameters)
	return resources
}

// AttestedClientAuthentication is the request's attestation headers,
// and its client_id parameter if it has one, for
// AuthenticateAttestedClient — which refuses a client_id naming another
// client than the attestation does. client_id is read exactly as
// Parameters reads it, so the two never disagree: an empty value is no
// client_id at all (RFC 6749 §3.1), and when Parameters refuses the
// request — a repeated parameter, an empty client_id repeated included,
// or too many or too large ones — AuthenticateAttestedClient refuses it
// too, with the same invalid_request. A request that also carries a
// client_assertion or client_assertion_type is refused with
// invalid_request as well: RFC 6749 §2.3 allows one client
// authentication method per request.
func (t TokenEndpointRequest) AttestedClientAuthentication() AttestedClientAuthenticationRequest {
	req := AttestedClientAuthenticationRequest{
		ClientAttestations:    t.parts.ClientAttestations,
		ClientAttestationPoPs: t.parts.ClientAttestationPoPs,
	}
	params, err := t.Parameters()
	if err != nil {
		req.malformed = true
		return req
	}
	req.ClientID = params["client_id"]
	req.otherClientAuth = params["client_assertion"] != "" || params["client_assertion_type"] != ""
	return req
}

// TokenBinding is what a token request's sender-constraining credential
// binds an issued access token to (VerifyTokenRequestBinding).
//
// IssueAccessToken accepts only a TokenBinding VerifyTokenRequestBinding
// returned, for the same client: the access token is bound to its
// Thumbprint, so a hand-built one, or one verified for another client,
// would bind it to a key that never proved possession at the token
// endpoint. IssueRefreshToken records Thumbprint for reference only, so
// it accepts any binding of the client's registered kind.
type TokenBinding struct {
	// Thumbprint is the credential's thumbprint, as
	// AccessTokenParams.Thumbprint takes it: the DPoP key's RFC 7638
	// JWK thumbprint, or the client certificate's x5t#S256 (RFC 8705
	// §3.1).
	Thumbprint string

	// SenderConstrain is which of the two it is: the client's
	// registered sender constraint.
	SenderConstrain storage.SenderConstrain

	// NextDPoPNonce, when not "", is the DPoP-Nonce to send the client
	// with the token response (RFC 9449 §8), as TokenResult.NextDPoPNonce
	// is for this server's own grants.
	NextDPoPNonce string

	// verifiedFor is the client VerifyTokenRequestBinding verified the
	// credential for. Unexported, so only a binding it returned carries
	// one: see IssueAccessToken.
	verifiedFor fapi.ClientID
}

// VerifyTokenRequestBinding verifies req's sender-constraining
// credential for client, exactly as this server's own token requests
// are verified, for a grant it doesn't serve (Config.AdditionalGrantTypes).
// client is the one the request authenticated as — from
// AuthenticateAttestedClient, for example — and its registered sender
// constraint decides the check:
//
//   - SenderConstrainDPoP: exactly one DPoP proof, for POST to
//     Endpoints.Token or its MTLSEndpoints alias, within
//     Limits.MaxDPoPProofAge and MaxClockSkew, not seen before — one
//     replay record with this server's own token requests — and, when
//     Dependencies.Nonces is set, carrying a current nonce: otherwise
//     the error is ErrorUseDPoPNonce, carrying a fresh one for its
//     DPoP-Nonce header, as WriteJSON sends it.
//   - SenderConstrainMTLS: the request's TLS client certificate (set it
//     with TokenEndpointRequest.SetPeerCertificate behind a
//     TLS-terminating proxy).
//
// It checks only the binding: the client's authentication, its
// permission to use the grant, and the grant itself are the caller's.
// Errors are *Error, as at this server's token endpoint. Every call
// records an AuditEventVerifyTokenRequestBinding.
func (s *Server) VerifyTokenRequestBinding(ctx context.Context, client storage.RegisteredClient, req TokenEndpointRequest) (TokenBinding, error) {
	binding, err := s.verifyExtensionGrantBinding(ctx, client, req)
	if err != nil {
		s.audit(ctx, AuditEventVerifyTokenRequestBinding, client.ID(), AuditOutcomeFailure, string(err.Code()))
		return TokenBinding{}, err
	}
	s.audit(ctx, AuditEventVerifyTokenRequestBinding, client.ID(), AuditOutcomeSuccess, "")
	return binding, nil
}

func (s *Server) verifyExtensionGrantBinding(ctx context.Context, client storage.RegisteredClient, req TokenEndpointRequest) (TokenBinding, *Error) {
	proof, err := resolveDPoPProof(req.parts.DPoPProofs)
	if err != nil {
		return TokenBinding{}, err
	}
	thumbprint, err := s.verifyTokenRequestBinding(ctx, client, proof, req.parts.PeerCertificate)
	if err != nil {
		return TokenBinding{}, err
	}
	nextNonce, err := s.nextDPoPNonce(ctx, client, s.deps.Clock.Now())
	if err != nil {
		return TokenBinding{}, err
	}
	return TokenBinding{Thumbprint: thumbprint, SenderConstrain: client.SenderConstrain(), NextDPoPNonce: nextNonce, verifiedFor: client.ID()}, nil
}

// ownGrantTypes are the grant types this package serves itself, and
// forbiddenGrantTypes those the FAPI 2.0 Security Profile rules out: the
// resource owner password credentials grant, and the implicit flow.
var (
	ownGrantTypes       = []string{"authorization_code", "refresh_token", "client_credentials", CIBAGrantType}
	forbiddenGrantTypes = []string{"password", "implicit"}
)

func validateAdditionalGrantTypes(grantTypes []string) error {
	for i, gt := range grantTypes {
		switch {
		case gt == "" || strings.ContainsFunc(gt, func(r rune) bool { return r <= ' ' || r == 0x7f }):
			return fmt.Errorf("server: config: additional_grant_types: %q is not a grant type", gt)
		case slices.Contains(ownGrantTypes, gt):
			return fmt.Errorf("server: config: additional_grant_types: %q is served by this package", gt)
		case slices.Contains(forbiddenGrantTypes, gt):
			return fmt.Errorf("server: config: additional_grant_types: FAPI 2.0 doesn't allow %q", gt)
		case slices.Contains(grantTypes[:i], gt):
			return fmt.Errorf("server: config: additional_grant_types: %q is listed twice", gt)
		}
	}
	return nil
}
