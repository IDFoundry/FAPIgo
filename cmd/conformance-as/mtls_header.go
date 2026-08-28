package main

import (
	"crypto/x509"
	"net/http"
)

// peerCertificate returns the first TLS client certificate presented
// on r's connection, or nil if none was — either because the
// connection isn't TLS at all, or because the client didn't present
// one. This binary's -mtls listener requests but never requires a
// certificate (tls.RequestClientCert), mirroring DPoP's own
// no-registration model: any certificate is acceptable, only its
// thumbprint matters, and only for a client actually registered
// storage.SenderConstrainMTLS — server/resource reject a missing or
// mismatched one themselves.
func peerCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}
