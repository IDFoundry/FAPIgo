package server

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

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
//
// Its implementations are TrustedClientCAs, NoPKIClientAuthentication
// and NoClientCertificateChainTrust. A server with no client using
// ClientAuthMethodTLSClientAuth or a SAN* sibling passes
// NoPKIClientAuthentication{}.
type ClientCertificateTrust interface {
	verifyChain(ctx context.Context, cert *x509.Certificate, now time.Time) *Error
	validate() error
}

// TrustedClientCAs has this package verify a presented client
// certificate against Roots itself (crypto/x509.Certificate.Verify,
// ExtKeyUsageClientAuth), at Dependencies.Clock's current time, then
// ask Revocation whether it has been revoked. This server only ever
// sees the single leaf certificate a caller extracted (e.g. via
// PeerCertificateFromHTTP), never the full chain a TLS handshake
// presented, so it builds the chain from Intermediates and Roots.
//
// A certificate in Roots is a trust anchor: chain building stops at it,
// and nothing checks whether it has been revoked — revoking one means
// removing it from Roots. For a PKI whose client certificates are
// issued by an intermediate CA, put its root in Roots and the
// intermediate in Intermediates, so the intermediate is part of the
// verified chain and Revocation checks it too. A leaf certificate put
// directly in Roots is its own trust anchor, never checked for
// revocation at all.
type TrustedClientCAs struct {
	// Roots is required. A nil pool would have crypto/x509 fall back to
	// the system roots, trusting every public CA to issue client
	// certificates, so New rejects it.
	Roots *x509.CertPool

	// Intermediates are CA certificates chains may pass through to
	// reach Roots, without being trusted on their own. Optional.
	Intermediates *x509.CertPool

	// Revocation is required, with no default: pass
	// ClientCertificateCRLs{...}, your own ClientCertificateRevocation
	// (OCSP, for example), or NoClientCertificateRevocationCheck{} to
	// explicitly decline. A certificate's validity period alone can't
	// stop a compromised key before it expires; that's what revocation
	// is for. It's checked whenever a client authenticates with a
	// certificate. An access token already bound to that certificate
	// stays usable at a resource server (resource.Verifier checks the
	// binding, not revocation) until it expires, so keep
	// Limits.AccessTokenLifetime short.
	Revocation ClientCertificateRevocation
}

func (t TrustedClientCAs) verifyChain(ctx context.Context, cert *x509.Certificate, now time.Time) *Error {
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         t.Roots,
		Intermediates: t.Intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return newError(ErrorInvalidClient, 401, "client certificate does not chain to a trusted root", err)
	}
	check := ClientCertificateRevocationCheck{Chain: chains[0], Now: now}
	if err := t.Revocation.CheckRevocation(ctx, check); err != nil {
		return newError(ErrorInvalidClient, 401, "client certificate is revoked or its revocation status is unknown", err)
	}
	return nil
}

func (t TrustedClientCAs) validate() error {
	if t.Roots == nil {
		return errors.New("trusted client CAs: roots is required")
	}
	if t.Revocation == nil {
		return errors.New("trusted client CAs: revocation is required (pass ClientCertificateCRLs{...} or NoClientCertificateRevocationCheck{} to explicitly decline)")
	}
	if v, ok := t.Revocation.(interface{ validate() error }); ok {
		if err := v.validate(); err != nil {
			return fmt.Errorf("trusted client CAs: %w", err)
		}
	}
	return nil
}

// NoPKIClientAuthentication declares that no client authenticates with a
// CA-issued certificate: ClientAuthMethodTLSClientAuth and its SAN*
// siblings (RFC 8705 §2.1) are refused with invalid_client, whatever a
// client's registration says, and automatic registration (OpenID
// Federation) never registers them, even for a Relying Party that lists
// them in its metadata. ClientAuthMethodSelfSignedTLSClientAuth still
// works: its thumbprint binds the exact certificate, needing no chain
// trust.
//
// It's the right choice for a server with no PKI-authenticated client.
// NoClientCertificateChainTrust would accept such a client's
// certificate unverified: anyone could then present a self-signed
// certificate naming a registered subject or SAN — for an
// automatically registered Relying Party, the one its public metadata
// publishes — and authenticate as that client.
type NoPKIClientAuthentication struct{}

func (NoPKIClientAuthentication) verifyChain(context.Context, *x509.Certificate, time.Time) *Error {
	return newError(ErrorInvalidClient, 401, "this server accepts no CA-issued client certificate (tls_client_auth)", nil)
}

func (NoPKIClientAuthentication) validate() error { return nil }

// NoClientCertificateChainTrust explicitly declines this package's own
// chain-of-trust check for a presented client certificate, while still
// accepting ClientAuthMethodTLSClientAuth and its SAN* siblings. A
// server with no such client passes NoPKIClientAuthentication{}
// instead. There are two legitimate reasons to pass this, and this
// type intentionally doesn't distinguish between them: (1) chain trust
// is already established before this package ever sees the certificate
// — the deployment's own TLS termination (tls.Config.ClientCAs and
// ClientAuth: RequireAndVerifyClientCert/VerifyClientCertIfGiven, never
// RequestClientCert or RequireAnyClientCert, which don't verify), or
// mTLS terminated by a gateway that independently verified the chain;
// or (2) the deployment has deliberately accepted the risk of running
// without chain trust — e.g. a conformance or development binary with
// no CA trust store of its own. Passing this when neither is actually
// true is a security-relevant mistake this package cannot detect: any
// self-signed certificate whose subject/SAN an attacker chose to match
// a registered value is accepted. Automatic registration (OpenID
// Federation) registers those methods under it only when
// AutomaticRegistrationConfig.AllowedClientAuthMethods names them, since
// a Relying Party's subject or SAN is public in its metadata: naming one
// says your TLS termination verifies the chain. Exists so that mistake
// requires a conscious, visible
// line of code, the same reason NoRevocation exists. Whoever
// establishes chain trust in case (1) also owns checking revocation.
type NoClientCertificateChainTrust struct{}

func (NoClientCertificateChainTrust) verifyChain(context.Context, *x509.Certificate, time.Time) *Error {
	return nil
}

func (NoClientCertificateChainTrust) validate() error { return nil }

// ClientCertificateRevocation decides whether a client certificate that
// TrustedClientCAs has already verified the chain of has been revoked.
// Implement it for a revocation source this package doesn't bundle
// (OCSP, a revocation service of your own); ClientCertificateCRLs
// covers Certificate Revocation Lists.
type ClientCertificateRevocation interface {
	// CheckRevocation returns nil when no certificate in check.Chain
	// below its trust anchor has been revoked. Any error rejects the
	// client with invalid_client: this package fails closed, so an
	// implementation that would rather accept a certificate whose
	// status it can't currently determine (soft-fail) returns nil
	// itself. It runs on every certificate-authenticated request, so
	// cache whatever it fetches.
	CheckRevocation(ctx context.Context, check ClientCertificateRevocationCheck) error
}

// ClientCertificateRevocationCheck is what ClientCertificateRevocation
// checks.
type ClientCertificateRevocationCheck struct {
	// Chain is the chain crypto/x509 verified, leaf first, through any
	// of TrustedClientCAs.Intermediates, and ending at the trust anchor
	// from TrustedClientCAs.Roots, so Chain[i+1] issued Chain[i]. When
	// more than one chain verifies, it is the first one crypto/x509
	// returns.
	Chain []*x509.Certificate
	// Now is Dependencies.Clock's current time, the time the chain was
	// verified at.
	Now time.Time
}

// NoClientCertificateRevocationCheck explicitly declines checking
// whether a client certificate has been revoked: a certificate stays
// accepted until it expires, even if its key is compromised. Right for
// a development or test deployment, or a PKI whose certificates are so
// short-lived that expiry stands in for revocation. Exists so declining
// is a conscious, visible line of code, the same reason
// NoClientCertificateChainTrust exists.
type NoClientCertificateRevocationCheck struct{}

// CheckRevocation implements ClientCertificateRevocation by accepting
// every certificate.
func (NoClientCertificateRevocationCheck) CheckRevocation(context.Context, ClientCertificateRevocationCheck) error {
	return nil
}
