package server

import (
	"context"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// AttestedClientAuthenticationRequest is the client credential material
// of a request to a token endpoint this server doesn't serve itself —
// such as one for an OpenID4VCI pre-authorized_code grant — for
// AuthenticateAttestedClient.
type AttestedClientAuthenticationRequest struct {
	// ClientAttestations/ClientAttestationPoPs are the request's
	// OAuth-Client-Attestation and OAuth-Client-Attestation-PoP header
	// values, every one of each: ClientAttestationHeadersFromHTTP reads
	// them from an *http.Request. AuthenticateAttestedClient requires
	// exactly one of each (draft-ietf-oauth-attestation-based-client-auth-12
	// §7.1 rule 1, §7.2 rule 1), so pass them all rather than picking
	// one.
	ClientAttestations    []string
	ClientAttestationPoPs []string

	// ClientID is the request's own client_id parameter, if it has one.
	// AuthenticateAttestedClient refuses a request whose client_id names
	// a different client from the attestation's sub (draft-12 §7.1 rule
	// 7, §7.5). Optional: a request without a client_id parameter leaves
	// it empty.
	ClientID string

	// malformed is set by TokenEndpointRequest.AttestedClientAuthentication
	// for a request whose parameters Parameters refuses, so its client_id
	// can't be read one way here and another way there.
	malformed bool
}

// AttestedClient is the client AuthenticateAttestedClient authenticated.
type AttestedClient struct {
	// Client is the registered client the Client Attestation's sub names.
	Client storage.RegisteredClient

	// AttestationExpiresAt is when the verified Client Attestation
	// expires.
	AttestationExpiresAt time.Time

	// instanceKey is the RFC 7638 thumbprint of the Client Instance Key
	// the attestation's PoP verified under: what IssueRefreshToken
	// binds a refresh token to. Unexported, so only an AttestedClient
	// this server authenticated carries one. authenticatedID is the
	// client it was verified for: IssueRefreshToken refuses a Client
	// changed since, so the key can't be attached to another client.
	instanceKey     string
	authenticatedID fapi.ClientID
}

// AuthenticateAttestedClient authenticates a client with a Client
// Attestation and its Client Attestation PoP (OAuth 2.0
// Attestation-Based Client Authentication,
// draft-ietf-oauth-attestation-based-client-auth-12, also accepting
// draft-07's shape), exactly as this server's own endpoints do, for a
// token endpoint grant this server doesn't serve — such as OpenID4VCI's
// pre-authorized_code grant, which HAIP 1.0 §4.4.1 requires client
// authentication for.
//
// It requires Config.AttestationBasedClientAuthentication, and a client
// registered for storage.ClientAuthMethodAttestation. The attestation
// must verify under Dependencies.AttesterTrust, with the algorithms in
// Config.Algorithms and within Limits.MaxClientAttestationLifetime; the
// PoP must verify against the attestation's cnf key, name Config.Issuer
// as its aud (and the client as its iss, if it has one), be within
// Limits.MaxClientAttestationPoPAge, and not have been used before by
// the same Client Instance. The
// PoP's audience being the issuer means the grant belongs at this
// server's own token endpoint URL — authorization server metadata has
// only the one — with the embedder routing it by grant_type. PoPs share
// one replay record with this server's own endpoints, so a PoP used at
// either can't be replayed at the other.
//
// It only authenticates the client. Whether that client may use the
// grant, the grant itself, and any DPoP proof are the caller's to check.
// The client is the one the attestation names: use AttestedClient.Client
// for the grant, and pass the request's own client_id parameter, if it
// has one, as ClientID: a request naming a different client is refused.
// A request with no attestation headers at all is refused, like one with
// more than one of either. Errors are *Error with ErrorInvalidClient
// (401), as at a token endpoint — that includes a PoP whose use couldn't
// be recorded, so an unavailable replay store fails closed — except for
// an attestation that has expired, which is ErrorUseFreshAttestation
// (400), a request from TokenEndpointRequest.AttestedClientAuthentication
// whose parameters TokenEndpointRequest.Parameters refuses, which is
// ErrorInvalidRequest (400), and a Dependencies.ClientAttestationStatus
// (or client store) that couldn't decide, which is ErrorServerError
// (500); an attestation that checker reports revoked is
// ErrorInvalidClient. Every call records an AuditEventAuthenticateAttestedClient.
func (s *Server) AuthenticateAttestedClient(ctx context.Context, req AttestedClientAuthenticationRequest) (AttestedClient, error) {
	attestation, pop, err := resolveAttestationHeaders(req.ClientAttestations, req.ClientAttestationPoPs)
	if req.malformed {
		err = newError(ErrorInvalidRequest, 400, "the request's parameters are duplicated, too many, or too large", nil)
	} else if err == nil && attestation == "" {
		err = newError(ErrorInvalidClient, 401, "client authentication is required", nil)
	}
	if err != nil {
		s.audit(ctx, AuditEventAuthenticateAttestedClient, "", AuditOutcomeFailure, string(err.Code()))
		return AttestedClient{}, err
	}
	client, verified, err := s.authenticateClientViaAttestation(ctx, req.ClientID, attestation, pop)
	if err != nil {
		s.audit(ctx, AuditEventAuthenticateAttestedClient, "", AuditOutcomeFailure, string(err.Code()))
		return AttestedClient{}, err
	}
	s.audit(ctx, AuditEventAuthenticateAttestedClient, client.ID(), AuditOutcomeSuccess, "")
	return AttestedClient{Client: client, AttestationExpiresAt: verified.ExpiresAt, instanceKey: verified.InstanceKey, authenticatedID: client.ID()}, nil
}
