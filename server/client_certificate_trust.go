package server

import "crypto/x509"

// ClientCertificateTrust decides how chain-of-trust for a client
// certificate presented under ClientAuthMethodTLSClientAuth or one of
// its SAN* siblings is established. There is no implicit default —
// New rejects a nil Dependencies.ClientCertificateTrust the same way
// it rejects a nil Dependencies.Revocation, for the same reason:
// declining this package's own chain check must be a conscious,
// visible line of code (NoClientCertificateChainTrust{}), never a
// silently-forgotten field. ClientAuthMethodSelfSignedTLSClientAuth is
// unaffected either way: its thumbprint match already cryptographically
// binds the exact certificate, so it needs no chain trust to begin
// with.
type ClientCertificateTrust interface {
	verifyChain(cert *x509.Certificate) bool
}

// TrustedClientCAs has this package verify a presented client
// certificate against Roots itself (crypto/x509.Certificate.Verify,
// ExtKeyUsageClientAuth). Roots only, no Intermediates pool — this
// server only ever sees the single leaf certificate a caller extracted
// (e.g. via PeerCertificateFromHTTP), never the full chain a real TLS
// handshake presented, so a PKI whose client certificates are issued
// through an intermediate CA should include that intermediate directly
// in Roots rather than only its ultimate root.
type TrustedClientCAs struct {
	Roots *x509.CertPool
}

func (t TrustedClientCAs) verifyChain(cert *x509.Certificate) bool {
	return verifiesAgainstRoots(cert, t.Roots)
}

// NoClientCertificateChainTrust explicitly declines this package's own
// chain-of-trust check for a presented client certificate. There are
// two legitimate reasons to pass it, and this type intentionally
// doesn't distinguish between them: (1) chain trust is already
// established before this package ever sees the certificate — the
// deployment's own TLS termination (tls.Config.ClientCAs and
// ClientAuth: RequireAndVerifyClientCert/VerifyClientCertIfGiven), or
// mTLS terminated by a gateway that independently verified the chain;
// or (2) the deployment has deliberately accepted the risk of running
// without chain trust — e.g. a conformance or development binary with
// no CA trust store of its own. Passing this when neither is actually
// true is a security-relevant mistake this package cannot detect: any
// self-signed certificate whose subject/SAN an attacker chose to match
// a registered value is accepted. Exists so that mistake requires a
// conscious, visible line of code, the same reason NoRevocation
// exists.
type NoClientCertificateChainTrust struct{}

func (NoClientCertificateChainTrust) verifyChain(*x509.Certificate) bool { return true }
