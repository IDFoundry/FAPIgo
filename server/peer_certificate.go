package server

import (
	"crypto/x509"
	"net/http"
)

// PeerCertificateFromHTTP returns the first TLS client certificate
// presented on r's own connection, or nil if none was — either because
// the connection isn't TLS at all, or because the client didn't
// present one (this package's own mTLS listener may request but not
// require one — RFC 8705's optional-presentation model, mirroring
// DPoP's own no-registration model). An optional convenience for a
// caller that already uses net/http, the same "no reason for every
// adapter to reimplement it" precedent as FormRequestFromHTTP — nothing
// here validates the certificate's trust chain; this package never
// terminates TLS itself, so chain trust is entirely the caller's own
// concern, whether that's the net/http server's own tls.Config
// (ClientCAs set, and ClientAuth: RequireAndVerifyClientCert or
// VerifyClientCertIfGiven — not a mode that merely requests a
// certificate without verifying it) or Dependencies.ClientCertificateTrust
// when mTLS is terminated somewhere this server can't configure directly
// (e.g. a gateway forwarding the presented certificate). Get neither
// right and a ClientAuthMethodTLSClientAuth/SAN*-registered client
// accepts any self-signed certificate whose subject an attacker chose
// to match — see storage.ClientAuthMethodTLSClientAuth's own doc
// comment.
func PeerCertificateFromHTTP(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}
