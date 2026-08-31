package resource

import (
	"crypto/x509"
	"net/http"
)

// PeerCertificateFromHTTP returns the first TLS client certificate
// presented on r's own connection, or nil if none was — either because
// the connection isn't TLS at all, or because the client didn't
// present one. An optional convenience for a caller that already uses
// net/http, the same "no reason for every adapter to reimplement it"
// precedent as server.FormRequestFromHTTP — nothing here validates the
// certificate's trust chain; this package never terminates TLS itself,
// so chain trust is entirely the caller's own tls.Config.ClientCAs
// concern (see VerifyRequest.PeerCertificate's own doc comment).
//
// Identical in shape to server.PeerCertificateFromHTTP, deliberately
// duplicated rather than shared — server and resource never import
// each other (ARCHITECTURE.md design rule 14), and this is small
// enough that a shared package would cost more than it saves.
func PeerCertificateFromHTTP(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}
