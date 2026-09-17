package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

// peerTLSConfig builds a *tls.Config for this binary's own outbound
// federation peer fetches: ordinary certificate verification against
// pool (this binary's own shared self-signed cert — see wiring.go's
// own peerHTTPClient construction) for every host, except one named in
// unverifiedHosts, which is accepted without any certificate check at
// all.
//
// unverifiedHosts exists for exactly one real case:
// -federation-trust-anchor-admin's own reason for being
// (dynamicFederationClients' own doc comment) is reaching the OIDF
// conformance suite's own self-hosted Trust Anchor and Relying
// Party — a completely separate TLS endpoint, under a completely
// separate self-signed cert this binary has no access to. An operator
// naming that host's own entity_id via POST /internal/federation/
// trust-anchors is already an explicit "I trust this federation
// identity" decision (the same one fapihttp.Config.AllowedPrivateHosts
// already represents for the SSRF side of reaching it) — accepting
// whatever certificate that same, already-named host happens to
// present is the identical trust decision, not a new, broader one.
// dynamicFederationClients.rebuild passes exactly its own current
// allowedPrivateHosts here, so this list changes in lockstep with that
// one, never wider. A loopback-address heuristic was tried first and
// rejected: from inside this binary's own docker-compose network, the
// suite's own hostname resolves to a private (not loopback) address
// via that network's own DNS alias, confirmed live — so "resolves to
// loopback" doesn't actually identify the suite's endpoint from here,
// unlike conformance/server/scripts/_sslutil.py's own identically-named
// check, which runs from the host instead.
//
// Every host not in unverifiedHosts still gets full certificate
// verification against pool; this is not a blanket bypass.
func peerTLSConfig(pool *x509.CertPool, unverifiedHosts []string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// VerifyConnection below does the real verification work —
		// InsecureSkipVerify alone would accept anything; Go's own
		// tls.Config doc guarantees VerifyConnection still runs
		// alongside it.
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection performs real verification below
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, h := range unverifiedHosts {
				if strings.EqualFold(cs.ServerName, h) {
					return nil
				}
			}
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("peer presented no certificates")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				DNSName: cs.ServerName, Roots: pool, Intermediates: intermediates,
			})
			return err
		},
	}
}
