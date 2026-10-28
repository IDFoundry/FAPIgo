package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// crossCertifiedPKI is a PKI with two paths from every leaf to a trust
// anchor: one intermediate (one key, one name) certified by two roots.
type crossCertifiedPKI struct {
	rootA, rootB                 testCert
	intermediateA, intermediateB testCert
}

func newCrossCertifiedPKI(t *testing.T) crossCertifiedPKI {
	t.Helper()
	p := crossCertifiedPKI{
		rootA: newTestCert(t, "root A", certOptions{isCA: true}),
		rootB: newTestCert(t, "root B", certOptions{isCA: true}),
	}
	key := generateKey(t)
	p.intermediateA = newTestCert(t, "intermediate", certOptions{parent: &p.rootA, isCA: true, key: key})
	p.intermediateB = newTestCert(t, "intermediate", certOptions{parent: &p.rootB, isCA: true, key: key})
	return p
}

// revokingCertificates reports a chain revoked when it carries any of
// revoked, and undecided when it carries any of undecided.
type revokingCertificates struct {
	revoked, undecided []*x509.Certificate
}

func (r revokingCertificates) CheckRevocation(_ context.Context, check server.ClientCertificateRevocationCheck) error {
	carries := func(list []*x509.Certificate) bool {
		return slices.ContainsFunc(check.Chain, func(c *x509.Certificate) bool {
			return slices.ContainsFunc(list, c.Equal)
		})
	}
	switch {
	case carries(r.revoked):
		return server.ErrCertificateRevoked
	case carries(r.undecided):
		return errors.New("no current CRL")
	}
	return nil
}

// alternativePathCases are the revocation outcomes for a leaf of p with
// two verified chains: accepted when either path has nothing revoked,
// refused when both do or the leaf itself is revoked, and server_error
// when no path passed and one couldn't be decided.
func alternativePathCases(p crossCertifiedPKI, leaf *x509.Certificate) map[string]struct {
	revocation server.ClientCertificateRevocation
	want       server.ErrorCode // "" accepts
} {
	return map[string]struct {
		revocation server.ClientCertificateRevocation
		want       server.ErrorCode
	}{
		"path through A revoked":     {revokingCertificates{revoked: []*x509.Certificate{p.intermediateA.cert}}, ""},
		"path through B revoked":     {revokingCertificates{revoked: []*x509.Certificate{p.intermediateB.cert}}, ""},
		"both paths revoked":         {revokingCertificates{revoked: []*x509.Certificate{p.intermediateA.cert, p.intermediateB.cert}}, server.ErrorInvalidClient},
		"leaf revoked":               {revokingCertificates{revoked: []*x509.Certificate{leaf}}, server.ErrorInvalidClient},
		"one revoked, one undecided": {revokingCertificates{revoked: []*x509.Certificate{p.intermediateA.cert}, undecided: []*x509.Certificate{p.intermediateB.cert}}, server.ErrorServerError},
		"path through A undecided":   {revokingCertificates{undecided: []*x509.Certificate{p.intermediateA.cert}}, ""},
	}
}

func wantRevocationOutcome(t *testing.T, err error, want server.ErrorCode) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("refused a certificate with an unrevoked path to a trust anchor: %v", err)
		}
		return
	}
	if code := serverErrorCode(t, err); code != want {
		t.Fatalf("error code = %q, want %q (err %v)", code, want, err)
	}
}

// TestTLSClientAuthRevocationAcceptsAnUnrevokedPath: a client
// certificate with more than one verified chain is checked on each, and
// accepted when any path to a trust anchor has nothing revoked, not
// judged on whichever chain crypto/x509 happened to return first.
func TestTLSClientAuthRevocationAcceptsAnUnrevokedPath(t *testing.T) {
	p := newCrossCertifiedPKI(t)
	leaf := caSignedTestClientCertWithSAN(t, p.intermediateA.cert, p.intermediateA.key.(*ecdsa.PrivateKey), func(*x509.Certificate) {})
	for name, tc := range alternativePathCases(p, leaf) {
		t.Run(name, func(t *testing.T) {
			trust := server.TrustedClientCAs{
				Roots:         poolOf(p.rootA, p.rootB),
				Intermediates: poolOf(p.intermediateA, p.intermediateB),
				Revocation:    tc.revocation,
			}
			wantRevocationOutcome(t, pushWithCertificate(t, leaf, trust, time.Now()), tc.want)
		})
	}
}

// TestX5CAttesterChainRevocationAcceptsAnUnrevokedPath is
// TestTLSClientAuthRevocationAcceptsAnUnrevokedPath for an attester's
// signing certificate.
func TestX5CAttesterChainRevocationAcceptsAnUnrevokedPath(t *testing.T) {
	p := newCrossCertifiedPKI(t)
	leaf := newTestCert(t, "attester", certOptions{parent: &p.intermediateA})
	for name, tc := range alternativePathCases(p, leaf.cert) {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{
				Revocation:    tc.revocation,
				TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(p.rootA, p.rootB)},
				IssuerBinding: server.AttesterIssuerByTrustAnchors,
			})
			instanceKey := generateKey(t)
			attestation := createX5CAttestation(t, leaf.key, x5cOf(leaf, p.intermediateA, p.intermediateB), "", &instanceKey.PublicKey, h.now)
			wantRevocationOutcome(t, requestWithAttestation(t, h, attestation, instanceKey), tc.want)
		})
	}
}
