package server

import (
	"context"
	"crypto/x509"
	"net"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/storage"
)

// matchesRegisteredThumbprint reports whether cert's RFC 8705 §3.1
// x5t#S256 thumbprint equals a client's registered
// ExpectedCertificateThumbprint (ClientAuthMethodSelfSignedTLSClientAuth,
// RFC 8705 §2.2).
func matchesRegisteredThumbprint(cert *x509.Certificate, expected string) bool {
	return expected != "" && mtls.Thumbprint(cert) == expected
}

// matchesRegisteredSubjectDN reports whether cert's subject, serialized
// via crypto/x509.Certificate.Subject.String() (Go's own RFC 2253-ish
// serialization), exactly equals a client's registered ExpectedSubjectDN
// (ClientAuthMethodTLSClientAuth, RFC 8705 §2.1's
// "tls_client_auth_subject_dn"). See
// storage.RegisteredClientConfig.ExpectedSubjectDN's own doc comment for
// the case-sensitivity/attribute-ordering limitation this implies.
func matchesRegisteredSubjectDN(cert *x509.Certificate, expected string) bool {
	return expected != "" && cert.Subject.String() == expected
}

// matchesRegisteredSANDNS reports whether one of cert's subjectAltName
// dNSName entries exactly equals a client's registered ExpectedSANDNS
// (ClientAuthMethodTLSClientAuthSANDNS, RFC 8705 §2.1's
// "tls_client_auth_san_dns"). No explicit empty-expected guard: expected
// is always client.ExpectedSANDNS() for a client whose ClientAuthMethod
// is this exact value, and storage.RegisteredClient — an opaque type
// with no exported fields, constructible only through the validating
// NewRegisteredClient — structurally guarantees that's never empty; an
// empty comparand also could never spuriously match a real certificate's
// own (never-empty) dNSName entries regardless.
func matchesRegisteredSANDNS(cert *x509.Certificate, expected string) bool {
	for _, name := range cert.DNSNames {
		if name == expected {
			return true
		}
	}
	return false
}

// matchesRegisteredSANURI reports whether one of cert's subjectAltName
// uniformResourceIdentifier entries, serialized via *url.URL.String(),
// exactly equals a client's registered ExpectedSANURI
// (ClientAuthMethodTLSClientAuthSANURI, RFC 8705 §2.1's
// "tls_client_auth_san_uri"). See matchesRegisteredSANDNS's own doc
// comment for why no explicit empty-expected guard is needed.
func matchesRegisteredSANURI(cert *x509.Certificate, expected string) bool {
	for _, u := range cert.URIs {
		if u.String() == expected {
			return true
		}
	}
	return false
}

// matchesRegisteredSANIP reports whether one of cert's subjectAltName
// iPAddress entries equals a client's registered ExpectedSANIP
// (ClientAuthMethodTLSClientAuthSANIP, RFC 8705 §2.1's
// "tls_client_auth_san_ip") — compared as parsed net.IP values, so
// equivalent representations of the same address (e.g. an IPv4 address
// written in its IPv4-in-IPv6 form) still match. No explicit
// parse-failure guard: NewRegisteredClient already validated expected
// parses (and, like matchesRegisteredSANDNS's own doc comment explains,
// guarantees it's never empty either); even if net.ParseIP somehow
// returned nil here, net.IP.Equal against a nil operand returns false
// for every real (non-nil) entry in cert.IPAddresses, the same
// fail-closed outcome an explicit guard would produce.
func matchesRegisteredSANIP(cert *x509.Certificate, expected string) bool {
	expectedIP := net.ParseIP(expected)
	for _, ip := range cert.IPAddresses {
		if ip.Equal(expectedIP) {
			return true
		}
	}
	return false
}

// matchesRegisteredSANEmail reports whether one of cert's
// subjectAltName rfc822Name entries exactly equals a client's
// registered ExpectedSANEmail (ClientAuthMethodTLSClientAuthSANEmail,
// RFC 8705 §2.1's "tls_client_auth_san_email"). See
// matchesRegisteredSANDNS's own doc comment for why no explicit
// empty-expected guard is needed.
func matchesRegisteredSANEmail(cert *x509.Certificate, expected string) bool {
	for _, email := range cert.EmailAddresses {
		if email == expected {
			return true
		}
	}
	return false
}

// authenticateClientViaCertificate authenticates a client identified by a
// plain client_id form parameter (no client_assertion — the TLS client
// certificate itself is the credential) against its registered
// ClientAuthMethodSelfSignedTLSClientAuth/ClientAuthMethodTLSClientAuth
// identity. Returns a synthesized VerifiedAssertion (zero ExpiresAt)
// rather than a real one, since there is no assertion to verify — every
// authenticateClient call site already discards this return value.
func (s *Server) authenticateClientViaCertificate(ctx context.Context, clientID fapi.ClientID, peerCert *x509.Certificate) (storage.RegisteredClient, clientassertion.VerifiedAssertion, *Error) {
	client, err := s.deps.Clients.ResolveClient(ctx, clientID)
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "unknown client", err)
	}
	if peerCert == nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "a client certificate is required for client authentication", nil)
	}

	switch client.ClientAuthMethod() {
	case storage.ClientAuthMethodSelfSignedTLSClientAuth:
		if !matchesRegisteredThumbprint(peerCert, client.ExpectedCertificateThumbprint()) {
			return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
				newError(ErrorInvalidClient, 401, "client certificate does not match the registered thumbprint", nil)
		}
	case storage.ClientAuthMethodTLSClientAuth:
		if !matchesRegisteredSubjectDN(peerCert, client.ExpectedSubjectDN()) {
			return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
				newError(ErrorInvalidClient, 401, "client certificate subject does not match the registered subject", nil)
		}
	case storage.ClientAuthMethodTLSClientAuthSANDNS:
		if !matchesRegisteredSANDNS(peerCert, client.ExpectedSANDNS()) {
			return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
				newError(ErrorInvalidClient, 401, "client certificate subject does not match the registered subject", nil)
		}
	case storage.ClientAuthMethodTLSClientAuthSANURI:
		if !matchesRegisteredSANURI(peerCert, client.ExpectedSANURI()) {
			return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
				newError(ErrorInvalidClient, 401, "client certificate subject does not match the registered subject", nil)
		}
	case storage.ClientAuthMethodTLSClientAuthSANIP:
		if !matchesRegisteredSANIP(peerCert, client.ExpectedSANIP()) {
			return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
				newError(ErrorInvalidClient, 401, "client certificate subject does not match the registered subject", nil)
		}
	case storage.ClientAuthMethodTLSClientAuthSANEmail:
		if !matchesRegisteredSANEmail(peerCert, client.ExpectedSANEmail()) {
			return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
				newError(ErrorInvalidClient, 401, "client certificate subject does not match the registered subject", nil)
		}
	default:
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client is not registered for certificate-based client authentication", nil)
	}

	return client, clientassertion.VerifiedAssertion{ClientID: clientID.String()}, nil
}
