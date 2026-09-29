package server

import (
	"crypto/x509"
	"net/http"
)

// httpRequestParts is what every client-authenticated endpoint request
// carries besides its form: the DPoP proofs, the attestation-based client
// authentication headers and the TLS client certificate. Each request
// type below has exactly these fields, so one read fills any of them —
// and if one of them gains a field, the conversions below stop
// compiling until this struct, and readHTTPRequestParts, gain it too.
type httpRequestParts struct {
	HTTP FormRequest

	DPoPProofs []string

	ClientAttestations    []string
	ClientAttestationPoPs []string

	PeerCertificate *x509.Certificate
}

// readHTTPRequestParts reads everything from r at once, so an adapter
// can't forget a header that only some clients send.
func readHTTPRequestParts(r *http.Request) (httpRequestParts, error) {
	form, err := FormRequestFromHTTP(r)
	if err != nil {
		return httpRequestParts{}, err
	}
	attestations, pops := ClientAttestationHeadersFromHTTP(r)
	return httpRequestParts{
		HTTP:                  form,
		DPoPProofs:            DPoPProofsFromHTTP(r),
		ClientAttestations:    attestations,
		ClientAttestationPoPs: pops,
		PeerCertificate:       PeerCertificateFromHTTP(r),
	}, nil
}

// PushAuthorizationRequestFromHTTP builds a PushAuthorizationRequest
// from a pushed authorization request's *http.Request: its form
// (FormRequestFromHTTP), DPoP proofs (DPoPProofsFromHTTP), client
// attestation headers (ClientAttestationHeadersFromHTTP) and TLS client
// certificate (PeerCertificateFromHTTP). Filling the struct field by
// field compiles just as well with a field left out, and then fails only
// for the clients that need it — typically those using mTLS or
// attestation-based client authentication.
//
// Behind a proxy that terminates TLS, r carries no client certificate:
// set PeerCertificate afterwards from however the proxy forwards it.
func PushAuthorizationRequestFromHTTP(r *http.Request) (PushAuthorizationRequest, error) {
	parts, err := readHTTPRequestParts(r)
	return PushAuthorizationRequest(parts), err
}

// BeginBackchannelAuthenticationRequestFromHTTP is
// PushAuthorizationRequestFromHTTP for the CIBA backchannel
// authentication endpoint.
func BeginBackchannelAuthenticationRequestFromHTTP(r *http.Request) (BeginBackchannelAuthenticationRequest, error) {
	parts, err := readHTTPRequestParts(r)
	return BeginBackchannelAuthenticationRequest(parts), err
}

// TokenEndpointRequest is a token endpoint request read from HTTP, not
// yet tied to a grant: the body can only be read once, and which request
// type it becomes depends on its grant_type. Switch on GrantType, then
// take the matching typed request.
type TokenEndpointRequest struct {
	parts httpRequestParts
}

// TokenEndpointRequestFromHTTP reads a token endpoint request the way
// PushAuthorizationRequestFromHTTP reads a pushed authorization request
// — see it for what's read and for TLS-terminating proxies
// (SetPeerCertificate here).
func TokenEndpointRequestFromHTTP(r *http.Request) (TokenEndpointRequest, error) {
	parts, err := readHTTPRequestParts(r)
	return TokenEndpointRequest{parts: parts}, err
}

// GrantType is the request's grant_type parameter: "authorization_code",
// "refresh_token", "client_credentials" or CIBAGrantType for the grants
// this package implements.
func (t TokenEndpointRequest) GrantType() string { return t.parts.HTTP.Get("grant_type") }

// SetPeerCertificate sets the TLS client certificate, for a server
// behind a proxy that terminates TLS and forwards the certificate itself.
func (t *TokenEndpointRequest) SetPeerCertificate(cert *x509.Certificate) {
	t.parts.PeerCertificate = cert
}

// AuthorizationCodeExchange is the request for ExchangeAuthorizationCode.
func (t TokenEndpointRequest) AuthorizationCodeExchange() AuthorizationCodeExchangeRequest {
	return AuthorizationCodeExchangeRequest(t.parts)
}

// RefreshToken is the request for RefreshAccessToken.
func (t TokenEndpointRequest) RefreshToken() RefreshTokenRequest {
	return RefreshTokenRequest(t.parts)
}

// ClientCredentials is the request for RequestClientCredentialsToken.
func (t TokenEndpointRequest) ClientCredentials() ClientCredentialsTokenRequest {
	return ClientCredentialsTokenRequest(t.parts)
}

// BackchannelTokenExchange is the request for
// ExchangeBackchannelAuthentication.
func (t TokenEndpointRequest) BackchannelTokenExchange() BackchannelTokenExchangeRequest {
	return BackchannelTokenExchangeRequest(t.parts)
}
