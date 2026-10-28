package mtls

import (
	"crypto"
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

// PublicKeyThumbprint returns the base64url-encoded (no padding)
// SHA-256 digest of pub's DER SubjectPublicKeyInfo, as
// x509.MarshalPKIXPublicKey encodes it — so a key from a JWK Set and
// the same key in a certificate (x509.Certificate.PublicKey) give the
// same value however the certificate itself encoded it.
func PublicKeyThumbprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
