package server

import (
	"crypto/x509"
	"errors"
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
//
// A PeerCertificate set some other way must carry its DER encoding in
// Raw, as one x509.ParseCertificate returns does: the RFC 8705 §3.1
// thumbprint is taken over it, and a request whose certificate has
// none fails with server_error rather than being bound to, or
// authenticated by, the digest of nothing.
func PeerCertificateFromHTTP(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// checkCertificateEncoding refuses a PeerCertificate without its DER
// encoding (an x509.Certificate built field by field rather than
// parsed): its thumbprint would be the digest of nothing, the same for
// every such certificate, and certificate checks read fields Raw
// should have been parsed into. It is the caller's mistake, not the
// client's, so it is a server_error.
func checkCertificateEncoding(cert *x509.Certificate) *Error {
	if len(cert.Raw) == 0 {
		return newError(ErrorServerError, 500, "failed to read the client certificate", errors.New("server: PeerCertificate has no DER encoding: set it to a certificate x509.ParseCertificate returned"))
	}
	return nil
}
