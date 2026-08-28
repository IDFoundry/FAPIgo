package server

import (
	"context"
	"crypto/x509"

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
	default:
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client is not registered for certificate-based client authentication", nil)
	}

	return client, clientassertion.VerifiedAssertion{ClientID: clientID.String()}, nil
}
