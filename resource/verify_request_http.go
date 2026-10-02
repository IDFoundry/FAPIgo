package resource

import (
	"net/http"
	"net/url"
)

// VerifyRequestFromHTTP builds the VerifyRequest for r, an incoming
// request to the protected resource whose external URL is target: its
// method, Authorization header, every DPoP header (DPoPProofsFromHTTP)
// and TLS client certificate (PeerCertificateFromHTTP). A request with
// more than one Authorization header is marked for Verify to refuse as
// invalid_request, as it refuses more than one DPoP header. Filling the
// struct field by field compiles just as well with a field left out, and
// then fails only for the clients that need it — a missing
// PeerCertificate refuses every mTLS-bound token, a missing DPoPProofs
// every DPoP-bound one.
//
// target is this endpoint's own fixed, externally visible URL — what a
// DPoP proof's htu names — never one built from r's Host header, which
// the client controls. For a route with path parameters, copy a fixed
// origin and set its Path from r.URL.Path. target is copied, never
// modified.
//
// Behind a proxy that terminates TLS, r carries no client certificate:
// set PeerCertificate afterwards from however the proxy forwards it.
func VerifyRequestFromHTTP(r *http.Request, target *url.URL) VerifyRequest {
	var u *url.URL
	if target != nil {
		copied := *target
		u = &copied
	}
	return VerifyRequest{
		Method:          r.Method,
		URL:             u,
		Authorization:   r.Header.Get("Authorization"),
		DPoPProofs:      DPoPProofsFromHTTP(r),
		PeerCertificate: PeerCertificateFromHTTP(r),

		repeatedAuthorization: len(r.Header.Values("Authorization")) > 1,
	}
}
