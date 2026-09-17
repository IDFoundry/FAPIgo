package fapitest

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

// PeerTLSConfig builds a *tls.Config for a test harness's own outbound
// calls to a mix of peers: ordinary certificate verification against
// pool (a trusted root this harness controls — see SelfSignedServerCert)
// for every host, except one named in unverifiedHosts, accepted without
// any certificate check at all.
//
// This exists for exactly one recurring shape of local multi-service
// integration test: a harness that trusts its *own* self-signed
// certificate (issued for its own services, verifiable against pool)
// but also needs to reach a handful of *other* peers under a
// completely separate self-signed cert it has no access to — a
// third-party test fixture the harness doesn't control, or another
// harness-managed service that happens to mint its own certificate
// independently. Naming a host in unverifiedHosts is meant to be an
// explicit, narrow trust decision made by the caller (e.g. because that
// exact host was already named in some other out-of-band trust
// decision, like an SSRF allow-list) — every host not listed there
// still gets full certificate verification against pool; this is not a
// blanket bypass, and unverifiedHosts should track the caller's own
// already-established trust boundary, never grow wider than it.
//
// A loopback-address heuristic ("trust anything resolving to
// 127.0.0.1") is deliberately not built in here: confirmed live in this
// repo's own conformance tooling that from inside a Docker network, a
// hostname can resolve to a private (not loopback) address via that
// network's own DNS alias, so "resolves to loopback" doesn't reliably
// identify a same-machine peer from inside a container the way it does
// from the host. Name the exact hosts instead.
func PeerTLSConfig(pool *x509.CertPool, unverifiedHosts []string) *tls.Config {
	return &tls.Config{ // NOSONAR: go:S4830 -- see InsecureSkipVerify's own trailing comment below: VerifyConnection performs real verification, this isn't a blind bypass
		MinVersion: tls.VersionTLS12,
		// VerifyConnection below does the real verification work —
		// InsecureSkipVerify alone would accept anything; Go's own
		// tls.Config doc guarantees VerifyConnection still runs
		// alongside it.
		// codeql[go/disabled-certificate-check] -- VerifyConnection below performs real chain+hostname verification for every host except unverifiedHosts (see its own doc comment); not a blind bypass
		InsecureSkipVerify: true, //nolint:gosec
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
