package mtls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// Thumbprint returns cert's RFC 8705 §3.1 "x5t#S256" confirmation
// value: the base64url-encoded (no padding) SHA-256 digest of the
// certificate's DER encoding (cert.Raw) — the exact bytes a TLS
// handshake's PeerCertificates entry already carries, so no
// re-parsing or re-encoding is needed.
func Thumbprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
