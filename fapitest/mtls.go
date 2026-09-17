package fapitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// SelfSignedClientCert generates a throwaway ECDSA P-256 self-signed
// client certificate — no IP SAN needed, since nothing validates this
// certificate's identity — RFC 8705 §3 sender-constraining only cares
// about its thumbprint, presented by the same connection on every
// call. Exported so a caller writing its own mTLS-sender-constrained
// or RFC 8705 §2 client-authenticated integration test doesn't have to
// reimplement this exact x509 boilerplate itself; this harness's own
// Config.SenderConstrain storage.SenderConstrainMTLS support uses it
// the same way.
func SelfSignedClientCert(commonName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// SelfSignedServerCert generates a throwaway ECDSA P-256 self-signed
// TLS server certificate — the server-cert mirror of
// SelfSignedClientCert (ExtKeyUsageServerAuth instead of
// ExtKeyUsageClientAuth, plus a Subject Alternative Name list: unlike a
// client certificate, a server's own peer generally does verify the
// hostname it dialed). commonName and "localhost" are always included
// as DNS SANs, 127.0.0.1 as an IP SAN, and any additional sans are
// appended — a caller stitching together a local multi-service
// integration test (one FAPIgo-based binary reaching another over TLS,
// with no shared CA to issue from) can name every hostname a peer
// might dial it as in one call.
func SelfSignedServerCert(commonName string, sans ...string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string{commonName, "localhost"}, sans...),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
