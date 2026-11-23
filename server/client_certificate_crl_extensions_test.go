package server_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// rawTBSCRL is RFC 5280 §5.1's TBSCertList, marshaled by hand so a test
// can mark any extension critical: crypto/x509 always writes the
// authority key identifier, CRL number and reason code non-critical.
type rawTBSCRL struct {
	Version    int
	Signature  pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	ThisUpdate time.Time
	NextUpdate time.Time
	Revoked    []rawCRLEntry    `asn1:"optional,omitempty"`
	Extensions []pkix.Extension `asn1:"tag:0,optional,explicit,omitempty"`
}

// rawCRLEntry is one revokedCertificates entry of a rawTBSCRL.
type rawCRLEntry struct {
	Serial     *big.Int
	RevokedAt  time.Time
	Extensions []pkix.Extension `asn1:"optional,omitempty"`
}

// rawCRL is RFC 5280 §5.1's CertificateList.
type rawCRL struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

var (
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	// A private extension, as a CA's own would be.
	oidPrivateCRLExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}
)

// signCRL signs a CRL from issuer, an ECDSA CA, over [thisUpdate,
// nextUpdate] with list extensions extensions and entries entries, and
// parses it.
func signCRL(t *testing.T, issuer *x509.Certificate, key crypto.Signer, thisUpdate, nextUpdate time.Time, extensions []pkix.Extension, entries ...rawCRLEntry) *x509.RevocationList {
	t.Helper()
	algorithm := pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
	tbs, err := asn1.Marshal(rawTBSCRL{
		Version: 1, Signature: algorithm, Issuer: asn1.RawValue{FullBytes: issuer.RawSubject},
		ThisUpdate: thisUpdate.UTC(), NextUpdate: nextUpdate.UTC(),
		Revoked: entries, Extensions: extensions,
	})
	if err != nil {
		t.Fatalf("marshal TBSCertList: %v", err)
	}
	digest := sha256.Sum256(tbs)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign CRL: %v", err)
	}
	der, err := asn1.Marshal(rawCRL{
		TBS: asn1.RawValue{FullBytes: tbs}, Algorithm: algorithm,
		Signature: asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
	if err != nil {
		t.Fatalf("marshal CertificateList: %v", err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	return list
}

// crlExtension is an extension identified by oid, with value as its DER
// value and critical as its criticality.
func crlExtension(t *testing.T, oid asn1.ObjectIdentifier, critical bool, value any) pkix.Extension {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal extension %v: %v", oid, err)
	}
	return pkix.Extension{Id: oid, Critical: critical, Value: der}
}

// authorityKeyID is a non-critical authority key identifier naming
// issuer's key.
func authorityKeyID(t *testing.T, issuer *x509.Certificate) pkix.Extension {
	t.Helper()
	return crlExtension(t, asn1.ObjectIdentifier{2, 5, 29, 35}, false, struct {
		ID []byte `asn1:"optional,tag:0"`
	}{issuer.SubjectKeyId})
}

// crlNumber is a CRL number extension.
func crlNumber(t *testing.T, critical bool) pkix.Extension {
	t.Helper()
	return crlExtension(t, asn1.ObjectIdentifier{2, 5, 29, 20}, critical, big.NewInt(7))
}

// standardCRLExtensions are the two extensions RFC 5280 has every CRL
// carry, non-critical, as crypto/x509 writes them.
func standardCRLExtensions(t *testing.T, issuer *x509.Certificate) []pkix.Extension {
	t.Helper()
	return []pkix.Extension{authorityKeyID(t, issuer), crlNumber(t, false)}
}

// entryFor lists cert, with extensions on its entry.
func entryFor(cert *x509.Certificate, revokedAt time.Time, extensions ...pkix.Extension) rawCRLEntry {
	return rawCRLEntry{Serial: cert.SerialNumber, RevokedAt: revokedAt.UTC(), Extensions: extensions}
}

// crlExtensionCase is a CRL of crlExtensionCases: its list extensions
// beyond the standard two, which of them replace those, and its entries.
type crlExtensionCase struct {
	name string
	// extensions are the list's extensions; nil means the standard two.
	extensions []pkix.Extension
	// entryExtensions mark the list's first entry.
	entryExtensions []pkix.Extension
	// laterEntryExtensions, if set, mark a second entry, after the first
	// and naming a third certificate.
	laterEntryExtensions []pkix.Extension
	// listsCert has the first entry name the certificate checked, not
	// another.
	listsCert bool
	// want is "" (not revoked), "revoked", or "undecided".
	want string
	// mark, if set, changes the parsed list.
	mark func(*x509.RevocationList)
}

// list is tc's CRL, signed by ca and current at now, its first entry
// naming listed and its later one, if any, third.
func (tc crlExtensionCase) list(t *testing.T, ca revocationCA, listed, third *x509.Certificate, now time.Time) *x509.RevocationList {
	t.Helper()
	extensions := tc.extensions
	if extensions == nil {
		extensions = standardCRLExtensions(t, ca.cert)
	}
	entries := []rawCRLEntry{entryFor(listed, now.Add(-time.Minute), tc.entryExtensions...)}
	if tc.laterEntryExtensions != nil {
		entries = append(entries, entryFor(third, now.Add(-time.Minute), tc.laterEntryExtensions...))
	}
	list := signCRL(t, ca.cert, ca.key, now.Add(-time.Minute), now.Add(time.Hour), extensions, entries...)
	if tc.mark != nil {
		tc.mark(list)
	}
	return list
}

// markAuthorityKeyIDCritical marks list's authority key identifier
// critical. crypto/x509 refuses to parse a CRL whose authority key
// identifier is critical, so only a list of Lists' own making carries
// one.
func markAuthorityKeyIDCritical(list *x509.RevocationList) {
	for i, ext := range list.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) {
			list.Extensions[i].Critical = true
		}
	}
}

// crlExtensionCases are CRLs whose extensions, by RFC 5280 §5.2 and
// §5.3, either a reader must process or may ignore, or that make the
// list one a reader that can't process them mustn't use: each extension
// RFC 5280 defines for a list or an entry, critical and not, and a
// private one.
func crlExtensionCases(t *testing.T, issuer *x509.Certificate, now time.Time) []crlExtensionCase {
	t.Helper()
	// extension is the extension oid with value, critical or not.
	extension := func(oid asn1.ObjectIdentifier, value any) func(critical bool) pkix.Extension {
		return func(critical bool) pkix.Extension { return crlExtension(t, oid, critical, value) }
	}
	with := func(extra ...pkix.Extension) []pkix.Extension {
		return append(standardCRLExtensions(t, issuer), extra...)
	}
	invalidAt, err := asn1.MarshalWithParams(now.Add(-time.Hour).UTC(), "generalized")
	if err != nil {
		t.Fatalf("marshal invalidity date: %v", err)
	}
	unknown := extension(oidPrivateCRLExtension, asn1.NullRawValue)
	issuerAltName := extension(asn1.ObjectIdentifier{2, 5, 29, 18}, []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("ca.example")}})
	deltaCRLIndicator := extension(asn1.ObjectIdentifier{2, 5, 29, 27}, big.NewInt(1))
	issuingDistributionPoint := extension(asn1.ObjectIdentifier{2, 5, 29, 28}, []asn1.RawValue{})
	freshestCRL := extension(asn1.ObjectIdentifier{2, 5, 29, 46}, asn1.NullRawValue)
	authorityInfoAccess := extension(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, asn1.NullRawValue)
	reasonCode := extension(asn1.ObjectIdentifier{2, 5, 29, 21}, asn1.Enumerated(1))
	invalidityDate := func(critical bool) pkix.Extension {
		return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 24}, Critical: critical, Value: invalidAt}
	}
	certificateIssuer := extension(asn1.ObjectIdentifier{2, 5, 29, 29}, []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("other-ca.example")}})
	return []crlExtensionCase{
		// Processed, critical or not.
		{name: "standard, another certificate listed"},
		{name: "standard, listed", listsCert: true, want: "revoked"},
		{name: "critical authority key identifier", listsCert: true, want: "revoked", mark: markAuthorityKeyIDCritical},
		{name: "critical CRL number", extensions: []pkix.Extension{authorityKeyID(t, issuer), crlNumber(t, true)}, listsCert: true, want: "revoked"},
		{name: "critical reason code", entryExtensions: []pkix.Extension{reasonCode(true)}, listsCert: true, want: "revoked"},
		{name: "non-critical reason code", entryExtensions: []pkix.Extension{reasonCode(false)}, listsCert: true, want: "revoked"},
		{name: "critical invalidity date", entryExtensions: []pkix.Extension{invalidityDate(true)}, listsCert: true, want: "revoked"},
		{name: "non-critical invalidity date", entryExtensions: []pkix.Extension{invalidityDate(false)}, listsCert: true, want: "revoked"},
		// Ignored when not critical.
		{name: "non-critical issuer alternative name", extensions: with(issuerAltName(false)), listsCert: true, want: "revoked"},
		{name: "non-critical freshest CRL", extensions: with(freshestCRL(false)), listsCert: true, want: "revoked"},
		{name: "non-critical authority information access", extensions: with(authorityInfoAccess(false)), listsCert: true, want: "revoked"},
		{name: "non-critical private extension", extensions: with(unknown(false)), listsCert: true, want: "revoked"},
		{name: "non-critical certificate issuer entry extension", entryExtensions: []pkix.Extension{certificateIssuer(false)}, listsCert: true, want: "revoked"},
		{name: "non-critical private entry extension", entryExtensions: []pkix.Extension{unknown(false)}, listsCert: true, want: "revoked"},
		// Unreadable when critical, whichever entry carries it.
		{name: "critical issuer alternative name", extensions: with(issuerAltName(true)), want: "undecided"},
		{name: "critical freshest CRL", extensions: with(freshestCRL(true)), want: "undecided"},
		{name: "critical authority information access", extensions: with(authorityInfoAccess(true)), want: "undecided"},
		{name: "critical private extension", extensions: with(unknown(true)), want: "undecided"},
		{name: "critical private extension, listed", extensions: with(unknown(true)), listsCert: true, want: "undecided"},
		{name: "critical certificate issuer entry extension", entryExtensions: []pkix.Extension{certificateIssuer(true)}, want: "undecided"},
		{name: "critical private entry extension", entryExtensions: []pkix.Extension{unknown(true)}, want: "undecided"},
		{name: "critical certificate issuer on a later entry", laterEntryExtensions: []pkix.Extension{certificateIssuer(true)}, want: "undecided"},
		{name: "critical private extension on a later entry", laterEntryExtensions: []pkix.Extension{unknown(true)}, want: "undecided"},
		// Not complete, critical or not.
		{name: "critical delta CRL indicator", extensions: with(deltaCRLIndicator(true)), want: "undecided"},
		{name: "non-critical delta CRL indicator", extensions: with(deltaCRLIndicator(false)), want: "undecided"},
		{name: "critical issuing distribution point", extensions: with(issuingDistributionPoint(true)), want: "undecided"},
		{name: "non-critical issuing distribution point", extensions: with(issuingDistributionPoint(false)), want: "undecided"},
	}
}

// requireRevocationOutcome fails t unless err is CheckRevocation's
// outcome want: "" accepts, "revoked" wraps ErrCertificateRevoked, and
// "undecided" is the error of an issuer with no usable CRL.
func requireRevocationOutcome(t *testing.T, err error, want string) {
	t.Helper()
	switch want {
	case "":
		if err != nil {
			t.Fatalf("CheckRevocation = %v, want nil", err)
		}
	case "revoked":
		if !errors.Is(err, server.ErrCertificateRevoked) {
			t.Fatalf("CheckRevocation = %v, want an error wrapping ErrCertificateRevoked", err)
		}
	default:
		if err == nil || errors.Is(err, server.ErrCertificateRevoked) || !strings.Contains(err.Error(), "no current CRL") {
			t.Fatalf("CheckRevocation = %v, want the issuer to have no usable CRL", err)
		}
	}
}

// TestClientCertificateCRLsCriticalExtensions: a CRL is used only when
// ClientCertificateCRLs processes every critical extension it, or one of
// its entries, carries (RFC 5280 §5.2, §5.3): the authority key
// identifier and CRL number on the list, the reason code and invalidity
// date on an entry. Any other critical extension leaves the certificate
// undecided, even one the list names, whichever entry carries it; a
// non-critical one is ignored. A delta CRL, or one with an issuing
// distribution point, leaves it undecided whether the extension is
// critical or not.
func TestClientCertificateCRLsCriticalExtensions(t *testing.T) {
	now := time.Now()
	ca := newRevocationCA(t, "crl-ca", now.Add(-time.Hour), now.Add(time.Hour))
	cert := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	other := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	third := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	check := server.ClientCertificateRevocationCheck{Chain: []*x509.Certificate{cert, ca.cert}, Now: now}
	for _, tc := range crlExtensionCases(t, ca.cert, now) {
		t.Run(tc.name, func(t *testing.T) {
			listed := other
			if tc.listsCert {
				listed = cert
			}
			list := tc.list(t, ca, listed, third, now)
			requireRevocationOutcome(t, staticCRLs(list).CheckRevocation(context.Background(), check), tc.want)
		})
	}
}

// TestClientCertificateCRLsUsableListBesideUnreadableOne: a CRL that
// can't be read is skipped, not fatal: a readable list from the same
// issuer still decides, whichever order Lists returns them in, and what
// the unreadable one lists counts for nothing.
func TestClientCertificateCRLsUsableListBesideUnreadableOne(t *testing.T) {
	now := time.Now()
	ca := newRevocationCA(t, "crl-ca", now.Add(-time.Hour), now.Add(time.Hour))
	cert := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	other := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	check := server.ClientCertificateRevocationCheck{Chain: []*x509.Certificate{cert, ca.cert}, Now: now}
	private := crlExtension(t, oidPrivateCRLExtension, true, asn1.NullRawValue)
	list := func(listed *x509.Certificate, extra ...pkix.Extension) *x509.RevocationList {
		return signCRL(t, ca.cert, ca.key, now.Add(-time.Minute), now.Add(time.Hour), append(standardCRLExtensions(t, ca.cert), extra...), entryFor(listed, now.Add(-time.Minute)))
	}
	for name, tc := range map[string]struct {
		lists []*x509.RevocationList
		want  string
	}{
		"unreadable list names it, readable one doesn't":     {[]*x509.RevocationList{list(cert, private), list(other)}, ""},
		"readable list doesn't name it, unreadable one does": {[]*x509.RevocationList{list(other), list(cert, private)}, ""},
		"readable list names it":                             {[]*x509.RevocationList{list(other, private), list(cert)}, "revoked"},
		"readable list names it, before an unreadable one":   {[]*x509.RevocationList{list(cert), list(other, private)}, "revoked"},
	} {
		t.Run(name, func(t *testing.T) {
			requireRevocationOutcome(t, staticCRLs(tc.lists...).CheckRevocation(context.Background(), check), tc.want)
		})
	}
}

// TestTLSClientAuthRefusesUnreadableCRL: a client certificate whose CA's
// only current CRL carries a critical extension ClientCertificateCRLs
// doesn't process can't be decided, so the pushed authorization request
// is refused with server_error, even though the list doesn't name it;
// with a readable list from the CA as well, the client authenticates.
func TestTLSClientAuthRefusesUnreadableCRL(t *testing.T) {
	now := time.Now()
	ca := newRevocationCA(t, "crl-ca", now.Add(-time.Hour), now.Add(time.Hour))
	cert := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	other := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	unreadable := signCRL(t, ca.cert, ca.key, now.Add(-time.Minute), now.Add(time.Hour),
		append(standardCRLExtensions(t, ca.cert), crlExtension(t, oidPrivateCRLExtension, true, asn1.NullRawValue)), entryFor(other, now.Add(-time.Minute)))
	unreadableEntry := signCRL(t, ca.cert, ca.key, now.Add(-time.Minute), now.Add(time.Hour),
		standardCRLExtensions(t, ca.cert), entryFor(other, now.Add(-time.Minute), crlExtension(t, oidPrivateCRLExtension, true, asn1.NullRawValue)))
	trust := func(lists ...*x509.RevocationList) server.TrustedClientCAs {
		return server.TrustedClientCAs{Roots: ca.pool, Revocation: staticCRLs(lists...)}
	}

	t.Run("critical list extension", func(t *testing.T) {
		requireErrorStatus(t, pushWithCertificate(t, cert, trust(unreadable), now), server.ErrorServerError, 500)
	})
	t.Run("critical entry extension", func(t *testing.T) {
		requireErrorStatus(t, pushWithCertificate(t, cert, trust(unreadableEntry), now), server.ErrorServerError, 500)
	})
	readable := ca.crl(t, now.Add(-time.Minute), now.Add(time.Hour), nil, other)
	if err := pushWithCertificate(t, cert, trust(unreadable, readable), now); err != nil {
		t.Fatalf("PushAuthorizationRequest with a readable CRL as well: %v", err)
	}
}

// TestX5CAttesterChainRevocationRefusesUnreadableCRL is
// TestTLSClientAuthRefusesUnreadableCRL for an attester's signing
// certificate under X5CAttesterChain: the attestation-authenticated
// client is refused with server_error while the issuing CA's only CRL
// can't be read, and accepted once a readable one is there too.
func TestX5CAttesterChainRevocationRefusesUnreadableCRL(t *testing.T) {
	serverNow := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	root := newTestCert(t, "root", certOptions{isCA: true, keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
	intermediate := newTestCert(t, "intermediate", certOptions{parent: &root, isCA: true, keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
	leaf := newTestCert(t, "attester", certOptions{parent: &intermediate})
	other := newTestCert(t, "other attester", certOptions{parent: &intermediate})
	thisUpdate, nextUpdate := serverNow.Add(-time.Hour), serverNow.Add(time.Hour)
	rootCRL := testCertCRL(t, root, thisUpdate, nextUpdate)
	unreadable := signCRL(t, intermediate.cert, intermediate.key, thisUpdate, nextUpdate,
		append(standardCRLExtensions(t, intermediate.cert), crlExtension(t, oidPrivateCRLExtension, true, asn1.NullRawValue)), entryFor(other.cert, thisUpdate))
	run := func(t *testing.T, lists ...*x509.RevocationList) error {
		t.Helper()
		h := newHarnessWithAttesterTrustAt(t, serverNow, nil, server.X5CAttesterChain{
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
			IssuerBinding: server.AttesterIssuerByTrustAnchors,
			Revocation:    staticCRLs(lists...),
		})
		instanceKey := generateKey(t)
		return requestWithAttestation(t, h, createX5CAttestation(t, leaf.key, x5cOf(leaf, intermediate), "", &instanceKey.PublicKey, h.now), instanceKey)
	}

	requireErrorStatus(t, run(t, rootCRL, unreadable), server.ErrorServerError, 500)
	if err := run(t, rootCRL, unreadable, testCertCRL(t, intermediate, thisUpdate, nextUpdate, other)); err != nil {
		t.Fatalf("RequestClientCredentialsToken with a readable CRL as well: %v", err)
	}
}
