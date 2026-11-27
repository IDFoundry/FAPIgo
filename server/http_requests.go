package server

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"

	fapi "github.com/idfoundry/fapigo"
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
// can't forget a header that only some clients send. A request whose
// only credential is the Authorization header is refused here
// (authorizationHeaderOnly), but only once its form has been read: a
// form FormRequestFromHTTP refuses (too large, too many parameters,
// malformed) is that 400, whatever the Authorization header says.
func readHTTPRequestParts(r *http.Request) (httpRequestParts, error) {
	form, err := FormRequestFromHTTP(r)
	if err != nil {
		return httpRequestParts{}, err
	}
	attestations, pops := ClientAttestationHeadersFromHTTP(r)
	parts := httpRequestParts{
		HTTP:                  form,
		DPoPProofs:            DPoPProofsFromHTTP(r),
		ClientAttestations:    attestations,
		ClientAttestationPoPs: pops,
		PeerCertificate:       PeerCertificateFromHTTP(r),
	}
	if challengeErr := authorizationHeaderOnly(r, parts); challengeErr != nil {
		return httpRequestParts{}, challengeErr
	}
	return parts, nil
}

// authorizationHeaderOnly refuses a request that tried to authenticate
// with the Authorization header (client_secret_basic, say) and carries
// none of the credentials this server authenticates clients by — a
// client assertion, client attestation headers, a TLS client certificate
// — so it can only fail as invalid_client. RFC 6749 §5.2: "If the client
// attempted to authenticate via the "Authorization" request header
// field, the authorization server MUST respond with an HTTP 401 (Unauthorized)
// status code and include the WWW-Authenticate response header field
// matching the authentication scheme used by the client." A request that
// also carries one of those credentials is authenticated by it as before.
func authorizationHeaderOnly(r *http.Request, parts httpRequestParts) *Error {
	header := r.Header.Get("Authorization")
	if header == "" || parts.PeerCertificate != nil || len(parts.ClientAttestations) > 0 || len(parts.ClientAttestationPoPs) > 0 {
		return nil
	}
	for _, p := range parts.HTTP.Parameters {
		if p.Name == "client_assertion" || p.Name == "client_assertion_type" {
			return nil
		}
	}
	scheme, _, _ := strings.Cut(header, " ")
	if !isAuthScheme(scheme) {
		scheme = "Basic"
	}
	err := newError(ErrorInvalidClient, http.StatusUnauthorized, "client authentication with the Authorization header is not supported", nil)
	err.challenge = scheme + ` realm="oauth", error="invalid_client"`
	return err
}

// isAuthScheme reports whether s is an HTTP authentication scheme name:
// an RFC 9110 §5.6.2 token.
func isAuthScheme(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !isTokenChar(c) {
			return false
		}
	}
	return true
}

// isTokenChar reports whether c is an RFC 9110 §5.6.2 tchar.
func isTokenChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)
}

// PushAuthorizationRequestFromHTTP builds a PushAuthorizationRequest
// from a pushed authorization request's *http.Request: its form
// (FormRequestFromHTTP), DPoP proofs (DPoPProofsFromHTTP), client
// attestation headers (ClientAttestationHeadersFromHTTP) and TLS client
// certificate (PeerCertificateFromHTTP). Filling the struct field by
// field compiles just as well with a field left out, and then fails only
// for the clients that need it — typically those using mTLS or
// attestation-based client authentication. The form is held to
// FormRequestFromHTTP's bounds — at most 1 MiB and 100 parameters —
// and one it refuses is an invalid_request *Error (400), returned before
// anything else is checked: even for a request that authenticates only
// with the Authorization header, which is otherwise refused with 401.
//
// Behind a proxy that terminates TLS, r carries no client certificate:
// set PeerCertificate afterwards from however the proxy forwards it —
// fapihttp.ForwardedClientCertificate reads RFC 9440's Client-Cert
// header, only from a request that came from the proxy.
// A certificate is public — the client presents it in every handshake,
// and a self-signed one is published in its registered JWKS — so having
// one proves nothing; only the TLS handshake proves the client holds its
// private key. Trust a forwarded certificate only from your own proxy,
// over a hop the client can't reach or forge (a private network or an
// authenticated connection), and have the proxy remove any copy of its
// forwarding header the client sent. Otherwise anyone can claim any
// client's certificate, authenticating as that client and presenting its
// certificate-bound tokens.
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
// take the matching typed request. It prints and logs as the typed
// requests do (see FormRequest), without its code, tokens or
// credentials, and has no exported field: fmt's reflection fallback (a
// TokenEndpointRequest in an unexported field, or under %p, %w or a verb
// fmt rejects) prints only an address.
type TokenEndpointRequest struct {
	parts heldParts
}

// heldParts holds a request's parts behind a pointer to a pointer, so
// that fmt's reflection fallback prints an address, never a value. One
// pointer isn't enough: under a verb fmt rejects for a pointer it
// reaches by reflection (s, q, f and most others), it prints that
// pointer again as if it were the operand itself, showing what a pointer
// to a struct points to, but not what a pointer to a pointer does.
type heldParts struct {
	// The zero-size array of funcs keeps TokenEndpointRequest
	// non-comparable, as the slices in the parts it held made it.
	_ [0]func()

	p **httpRequestParts
}

// holdParts is a heldParts holding parts.
func holdParts(parts httpRequestParts) heldParts {
	p := &parts
	return heldParts{p: &p}
}

// get is the parts h holds: the zero parts for the zero heldParts, which
// the zero TokenEndpointRequest holds.
func (h heldParts) get() httpRequestParts {
	if h.p == nil {
		return httpRequestParts{}
	}
	return **h.p
}

// TokenEndpointRequestFromHTTP reads a token endpoint request the way
// PushAuthorizationRequestFromHTTP reads a pushed authorization request
// — see it for what's read and for TLS-terminating proxies
// (SetPeerCertificate here).
func TokenEndpointRequestFromHTTP(r *http.Request) (TokenEndpointRequest, error) {
	parts, err := readHTTPRequestParts(r)
	return TokenEndpointRequest{parts: holdParts(parts)}, err
}

// GrantType is the request's grant_type parameter: "authorization_code",
// "refresh_token", "client_credentials" or CIBAGrantType for the grants
// this package implements.
func (t TokenEndpointRequest) GrantType() string { return t.parts.get().HTTP.Get("grant_type") }

// SetEndpointRoute sets the public route the request was received at
// (FormRequest.EndpointRoute), which decides the URL its DPoP proof must
// name: needed at the token endpoint's mTLS alias, unless the listener
// there is wrapped in WithEndpointRoute, which TokenEndpointRequestFromHTTP
// takes it from. Set it from the listener or
// trusted proxy route, never from anything the client sends.
func (t *TokenEndpointRequest) SetEndpointRoute(route EndpointRoute) {
	parts := t.parts.get()
	parts.HTTP.EndpointRoute = route
	// A holder of its own, as SetPeerCertificate makes.
	t.parts = holdParts(parts)
}

// SetPeerCertificate sets the TLS client certificate, for a server
// behind a proxy that terminates TLS and forwards the certificate itself.
// Set it only from your own proxy's forwarding, never from anything the
// client can send directly (fapihttp.ForwardedClientCertificate) — see
// PushAuthorizationRequestFromHTTP.
func (t *TokenEndpointRequest) SetPeerCertificate(cert *x509.Certificate) {
	parts := t.parts.get()
	parts.PeerCertificate = cert
	// A holder of its own, so a copy of t made before keeps the
	// certificate it had, as it did when t held its parts by value.
	t.parts = holdParts(parts)
}

// AuthorizationCodeExchange is the request for ExchangeAuthorizationCode.
func (t TokenEndpointRequest) AuthorizationCodeExchange() AuthorizationCodeExchangeRequest {
	return AuthorizationCodeExchangeRequest(t.parts.get())
}

// RefreshToken is the request for RefreshAccessToken.
func (t TokenEndpointRequest) RefreshToken() RefreshTokenRequest {
	return RefreshTokenRequest(t.parts.get())
}

// ClientCredentials is the request for RequestClientCredentialsToken.
func (t TokenEndpointRequest) ClientCredentials() ClientCredentialsTokenRequest {
	return ClientCredentialsTokenRequest(t.parts.get())
}

// BackchannelTokenExchange is the request for
// ExchangeBackchannelAuthentication.
func (t TokenEndpointRequest) BackchannelTokenExchange() BackchannelTokenExchangeRequest {
	return BackchannelTokenExchangeRequest(t.parts.get())
}

// BeginAuthorizationRequestFromHTTP reads the authorization endpoint's
// request from r: the client_id and request_uri a client sends the
// browser with after a pushed authorization request (RFC 9126 §4), and
// any request parameter (BeginAuthorizationRequest.Request). OIDC
// Core §3.1.2.1 has an authorization server "support the use of the HTTP
// GET and POST methods": a POST is read from its
// application/x-www-form-urlencoded body, as FormRequestFromHTTP reads
// one (and only from it), any other method from the query string.
// r.URL.Query().Get would silently take the first of a repeated
// parameter; RFC 6749 §3.1 says one "MUST NOT be included more than
// once", so a repeated client_id, request_uri or request, a malformed
// query or body, a query or body of more than 100 parameters (counted
// as it is parsed, as FormRequestFromHTTP counts them), or a POST that
// isn't form-encoded, is an invalid_request *Error. Render it locally:
// an authorization endpoint never redirects for a request it can't
// attribute to a client's registered redirect URI. A missing value is
// left empty for BeginAuthorization to answer, as it does any
// request_uri or client_id it doesn't accept. The values are copies,
// sharing no memory with r's query or body, so keeping one doesn't
// keep the whole request alive.
func BeginAuthorizationRequestFromHTTP(r *http.Request) (BeginAuthorizationRequest, error) {
	params, err := authorizationEndpointParameters(r)
	if err != nil {
		return BeginAuthorizationRequest{}, err
	}
	for _, name := range []string{"client_id", "request_uri", "request"} {
		if len(params[name]) > 1 {
			return BeginAuthorizationRequest{}, newError(ErrorInvalidRequest, 400, name+" is included more than once", nil)
		}
	}
	return BeginAuthorizationRequest{
		RequestURI: params.Get("request_uri"),
		ClientID:   fapi.ClientID(params.Get("client_id")),
		Request:    params.Get("request"),
	}, nil
}

// authorizationEndpointParameters is an authorization request's
// parameters: a POST's form body, or any other request's query string.
func authorizationEndpointParameters(r *http.Request) (url.Values, error) {
	var form FormRequest
	var err error
	if r.Method == http.MethodPost {
		form, err = FormRequestFromHTTP(r)
	} else {
		form.Parameters, err = authorizationQueryParameters(r.URL.RawQuery)
	}
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	for _, p := range form.Parameters {
		params.Add(p.Name, p.Value)
	}
	return params, nil
}

// authorizationQueryParameters decodes an authorization request's query
// as FormRequestFromHTTP decodes a body: counted as it is parsed, with
// the same bound, and copied out of query. As in url.ParseQuery, a
// semicolon isn't a separator but makes the query malformed, so this
// server can't split it one way and a proxy in front of it another.
func authorizationQueryParameters(query string) ([]FormParameter, error) {
	if strings.Contains(query, ";") {
		return nil, newError(ErrorInvalidRequest, 400, "the authorization request's query is malformed", errors.New("invalid semicolon separator in query"))
	}
	return decodeFormParameters(query, "the authorization request's query")
}
