// This file adds an mTLS-sender-constrained variant of the CIBA RP
// driver (ciba.go): -profile=ciba -mtls presents a throwaway client
// certificate on every token/backchannel-authenticate call instead of
// a DPoP proof, targeting the same fapi-ciba-id1-client-test-plan.
//
// This exists because AbstractFAPICIBAClientTest.handleHttp's own
// routing hardcodes the token endpoint to require mTLS unconditionally
// (see ARCHITECTURE.md's Conformance strategy section, and
// conformance/client/scripts/README.md's own CIBA section, both
// written from the DPoP attempt's live run) — every module that
// reaches token exchange failed for that one reason. This is the
// genuine re-attempt promised there: not guaranteed to fully pass,
// documented with the same rigor either way.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/client"
)

// selfSignedClientCert generates a throwaway ECDSA P-256 self-signed
// client certificate, entirely in-memory — the client-side mirror of
// cmd/conformance-as's own selfSignedCert test helper (swap
// ExtKeyUsageServerAuth for ExtKeyUsageClientAuth; no IP SAN needed,
// since nothing here validates this certificate's identity — RFC 8705
// §3 sender-constraining only cares about its thumbprint, presented by
// the same connection on every call).
func selfSignedClientCert(commonName string) (tls.Certificate, error) {
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

// mtlsSuiteHTTPClient is insecureSuiteHTTPClient plus cert presented on
// every outbound connection — the transport-level half of
// SenderConstrainMTLS; client itself never handles certificate
// material directly (see client.Config.SenderConstrain's own doc
// comment), only Dependencies.HTTP does. Built by mutating
// insecureSuiteHTTPClient's own Transport rather than constructing a
// second InsecureSkipVerify: true site — the suite's self-signed dev
// cert is untrusted for the same one documented reason either way (see
// insecureSuiteHTTPClient's own doc comment), and CodeQL's
// go/disabled-certificate-check only needs to see that reasoning once.
func mtlsSuiteHTTPClient(cert tls.Certificate) *http.Client {
	client := insecureSuiteHTTPClient()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
	return client
}

// applyMTLSEndpointAliases overrides cfg's Token/BackchannelAuthentication
// endpoints with discovered's mtls_endpoint_aliases (RFC 8705 §5), when
// the issuer advertised one — the suite's own mock AS listens for an
// mTLS-sender-constrained client's calls on a second, alias-only origin
// ("base_mtls_url" in its own terms). Returns an error string (not
// awaitVerdict itself, so callers keep their own message prefix) when
// no alias was advertised at all, since a SenderConstrainMTLS client
// has nowhere else to send these calls.
func applyMTLSEndpointAliases(cfg *client.Config, discovered client.DiscoveredMetadata) error {
	if discovered.MTLSEndpointAliases == nil {
		return fmt.Errorf("issuer does not advertise mtls_endpoint_aliases")
	}
	if !discovered.MTLSEndpointAliases.Token.IsZero() {
		cfg.Endpoints.Token = discovered.MTLSEndpointAliases.Token
	}
	if !discovered.MTLSEndpointAliases.BackchannelAuthentication.IsZero() {
		cfg.Endpoints.BackchannelAuthentication = discovered.MTLSEndpointAliases.BackchannelAuthentication
	}
	return nil
}

// applyMTLSEndpointAliasesForClientAuth is applyMTLSEndpointAliases' own
// counterpart for RFC 8705 §2 client authentication (main.go's
// -client-auth-mtls): covers PushedAuthorizationRequest instead of
// BackchannelAuthentication, since a certificate-authenticated client
// (unlike an mTLS-sender-constrained one) must present its certificate
// at PAR too, not just at the token endpoint — the same asymmetry
// server/par.go's own authenticateClient enforces on the AS side.
func applyMTLSEndpointAliasesForClientAuth(cfg *client.Config, discovered client.DiscoveredMetadata) error {
	if discovered.MTLSEndpointAliases == nil {
		return fmt.Errorf("issuer does not advertise mtls_endpoint_aliases")
	}
	if !discovered.MTLSEndpointAliases.Token.IsZero() {
		cfg.Endpoints.Token = discovered.MTLSEndpointAliases.Token
	}
	if !discovered.MTLSEndpointAliases.PushedAuthorizationRequest.IsZero() {
		cfg.Endpoints.PushedAuthorizationRequest = discovered.MTLSEndpointAliases.PushedAuthorizationRequest
	}
	return nil
}
