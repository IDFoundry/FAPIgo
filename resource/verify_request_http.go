package resource

import (
	"net/http"
)

// VerifyRequestFromHTTP builds the VerifyRequest for r, an incoming
// request to the protected resource: its method, its escaped path,
// Authorization header, every DPoP header (DPoPProofsFromHTTP) and TLS
// client certificate (PeerCertificateFromHTTP). A request with more
// than one Authorization header is marked for Verify to refuse as
// invalid_request, as it refuses more than one DPoP header. Filling the
// struct field by field compiles just as well with a field left out, and
// then fails only for the clients that need it — a missing
// PeerCertificate refuses every mTLS-bound token, a missing DPoPProofs
// every DPoP-bound one.
//
// The URL a DPoP proof's htu must name is not taken from r: Verify
// builds it from Config.ResourceURLs and r.URL.EscapedPath(), never from
// r's Host header, which the client controls, nor from the decoded
// r.URL.Path, under which /accounts/a%2Fb would be /accounts/a/b. A
// handler mounted on a path outside every ResourceURLs prefix has each
// request refused.
//
// Behind a proxy that terminates TLS, r carries no client certificate:
// set PeerCertificate afterwards from however the proxy forwards it. A
// proxy that rewrites the path it forwards (stripping a prefix, say)
// leaves r with a path the client didn't call: give Verify the URL the
// client called in VerifyRequest.URL instead.
func VerifyRequestFromHTTP(r *http.Request) VerifyRequest {
	return VerifyRequest{
		Method:          r.Method,
		Authorization:   r.Header.Get("Authorization"),
		DPoPProofs:      DPoPProofsFromHTTP(r),
		PeerCertificate: PeerCertificateFromHTTP(r),

		requestPath:           r.URL.EscapedPath(),
		repeatedAuthorization: len(r.Header.Values("Authorization")) > 1,
	}
}
