package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"
	"time"
)

// fuzzBytes hands out a fuzz input's bytes one at a time, then zeros.
type fuzzBytes []byte

func (b *fuzzBytes) next() byte {
	if len(*b) == 0 {
		return 0
	}
	c := (*b)[0]
	*b = (*b)[1:]
	return c
}

// fuzzEKUOIDs are the UnknownExtKeyUsage OIDs FuzzAttesterLeafPolicy
// draws from: both ISO/IEC 18013-5 roles, OIDs one arc either side of
// them, and an ecosystem's own purpose.
var fuzzEKUOIDs = []asn1.ObjectIdentifier{
	{1, 0, 18013, 5, 1, 2},
	{1, 0, 18013, 5, 1, 6},
	{1, 0, 18013, 5, 1},
	{1, 0, 18013, 5, 1, 2, 1},
	{1, 0, 18013, 5, 1, 7},
	{1, 3, 6, 1, 4, 1, 99999, 1},
}

// fuzzAttesterCert is a certificate struct (never DER: the policy reads
// only parsed fields) with extended key usages drawn from b.
func fuzzAttesterCert(b *fuzzBytes, i int) *x509.Certificate {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: string(rune('a' + i))}, Raw: []byte{b.next() % 4}}
	for range b.next() % 4 {
		// 0 is anyExtendedKeyUsage; values past crypto/x509's named ones
		// are refused like any other non-Any purpose.
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsage(b.next()%16))
	}
	for range b.next() % 3 {
		cert.UnknownExtKeyUsage = append(cert.UnknownExtKeyUsage, fuzzEKUOIDs[int(b.next())%len(fuzzEKUOIDs)])
	}
	return cert
}

// isISO18013RoleOracle is isISO18013Role written out by dotted form.
func isISO18013RoleOracle(oid asn1.ObjectIdentifier) bool {
	s := oid.String()
	return s == "1.0.18013.5.1.2" || s == "1.0.18013.5.1.6"
}

// attesterChainRefusedOracle is DefaultAttesterLeafPolicy's documented
// rule, independently: refuse an empty chain, a signing certificate
// listing any purpose but anyExtendedKeyUsage or an ISO/IEC 18013-5
// role, and a chain through a CA whose extended key usage is present
// and lists neither anyExtendedKeyUsage nor a purpose other than those.
func attesterChainRefusedOracle(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return true
	}
	leaf := chain[0]
	if slices.ContainsFunc(leaf.ExtKeyUsage, func(e x509.ExtKeyUsage) bool { return e != x509.ExtKeyUsageAny }) ||
		slices.ContainsFunc(leaf.UnknownExtKeyUsage, isISO18013RoleOracle) {
		return true
	}
	for _, ca := range chain[1:] {
		listsAny := slices.Contains(ca.ExtKeyUsage, x509.ExtKeyUsageAny)
		listsOwnPurpose := slices.ContainsFunc(ca.UnknownExtKeyUsage, func(o asn1.ObjectIdentifier) bool { return !isISO18013RoleOracle(o) })
		listsSome := len(ca.ExtKeyUsage)+len(ca.UnknownExtKeyUsage) > 0
		if listsSome && !listsAny && !listsOwnPurpose {
			return true
		}
	}
	return false
}

// FuzzAttesterLeafPolicy checks DefaultAttesterLeafPolicy and
// checkX5CExcludesAnchors on chains of certificates whose extended key
// usages, and shapes, come from the fuzzer. Beyond never panicking on
// an empty or odd chain:
//
//   - DefaultAttesterLeafPolicy refuses exactly the chains its
//     documented rule (attesterChainRefusedOracle) refuses;
//   - approvedAttesterChains keeps exactly the chains the policy
//     accepts, in order, and fails closed when it keeps none;
//   - checkX5CExcludesAnchors refuses exactly when an x5c certificate
//     below the leaf equals the last certificate of some chain.
func FuzzAttesterLeafPolicy(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0})
	f.Add([]byte{2, 0, 1, 0, 0, 0, 1, 1, 0})
	f.Add([]byte{3, 0, 0, 1, 5, 0, 2, 1, 1, 0, 1, 0})
	f.Add([]byte{2, 0, 2, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		b := fuzzBytes(data)
		var chains [][]*x509.Certificate
		for range b.next()%3 + 1 {
			chain := make([]*x509.Certificate, b.next()%5)
			for i := range chain {
				chain[i] = fuzzAttesterCert(&b, i)
			}
			chains = append(chains, chain)
		}
		checkLeafPolicy(t, chains)
		var extra []*x509.Certificate
		for i := range b.next() % 4 {
			extra = append(extra, fuzzAttesterCert(&b, int(i)))
		}
		checkX5CAnchorRule(t, extra, chains)
	})
}

func checkLeafPolicy(t *testing.T, chains [][]*x509.Certificate) {
	t.Helper()
	var want [][]*x509.Certificate
	for _, chain := range chains {
		err := DefaultAttesterLeafPolicy{}.CheckAttesterChain(chain)
		if refused := attesterChainRefusedOracle(chain); (err != nil) != refused {
			t.Fatalf("CheckAttesterChain(%s) = %v, documented rule refuses: %v", describeChain(chain), err, refused)
		}
		if err == nil {
			want = append(want, chain)
		}
		if (AnyAttesterLeaf{}).CheckAttesterChain(chain) != nil {
			t.Fatal("AnyAttesterLeaf refused a chain")
		}
	}
	approved, err := approvedAttesterChains(nil, chains)
	if (err != nil) != (len(want) == 0) || len(approved) != len(want) {
		t.Fatalf("approvedAttesterChains kept %d chains (%v), want %d", len(approved), err, len(want))
	}
	for i := range approved {
		if !slices.Equal(approved[i], want[i]) {
			t.Fatalf("approvedAttesterChains changed chain %d or the order", i)
		}
	}
}

func checkX5CAnchorRule(t *testing.T, extra []*x509.Certificate, chains [][]*x509.Certificate) {
	t.Helper()
	var nonEmpty [][]*x509.Certificate
	for _, c := range chains {
		// x509.Certificate.Verify never returns an empty chain.
		if len(c) > 0 {
			nonEmpty = append(nonEmpty, c)
		}
	}
	want := false
	for _, c := range nonEmpty {
		want = want || slices.ContainsFunc(extra, func(e *x509.Certificate) bool { return bytes.Equal(e.Raw, c[len(c)-1].Raw) })
	}
	if err := checkX5CExcludesAnchors(extra, nonEmpty); (err != nil) != want {
		t.Fatalf("checkX5CExcludesAnchors = %v, want refusal %v", err, want)
	}
}

func describeChain(chain []*x509.Certificate) string {
	var buf bytes.Buffer
	for _, c := range chain {
		buf.WriteString("[eku ")
		for _, e := range c.ExtKeyUsage {
			buf.WriteString(extKeyUsageName(e) + ";")
		}
		for _, o := range c.UnknownExtKeyUsage {
			buf.WriteString(o.String() + ";")
		}
		buf.WriteString("]")
	}
	return buf.String()
}

// attesterPool is a set of real certificates FuzzVerifyAttesterChain
// assembles x5c chains and anchor sets from.
type attesterPool struct {
	ders  [][]byte
	certs []*x509.Certificate // nil for the entry that isn't a certificate
}

// Indices into attesterPool.
const (
	poolRoot = iota
	poolIntermediate
	poolSubIntermediate
	poolLeaf
	poolLeafUnderRoot
	poolSelfSignedLeaf
	poolCALeaf
	poolCertSignOnlyLeaf
	poolOtherRoot
	poolLeafUnderSub
	poolGarbage
	poolSize
)

var attesterPoolNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newAttesterPool(f *testing.F) attesterPool {
	f.Helper()
	p := attesterPool{ders: make([][]byte, poolSize), certs: make([]*x509.Certificate, poolSize)}
	keys := make([]*ecdsa.PrivateKey, poolSize)
	issue := func(i, parent int, isCA bool, ku x509.KeyUsage) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			f.Fatal(err)
		}
		keys[i] = key
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "pool " + string(rune('a'+i))},
			NotBefore: attesterPoolNow.Add(-time.Hour), NotAfter: attesterPoolNow.Add(time.Hour),
			IsCA: isCA, BasicConstraintsValid: true, KeyUsage: ku,
		}
		parentCert, parentKey := tmpl, key
		if parent >= 0 {
			parentCert, parentKey = p.certs[parent], keys[parent]
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
		if err != nil {
			f.Fatal(err)
		}
		if p.certs[i], err = x509.ParseCertificate(der); err != nil {
			f.Fatal(err)
		}
		p.ders[i] = der
	}
	caKU := x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	issue(poolRoot, -1, true, caKU)
	issue(poolIntermediate, poolRoot, true, caKU)
	issue(poolSubIntermediate, poolIntermediate, true, caKU)
	issue(poolLeaf, poolIntermediate, false, x509.KeyUsageDigitalSignature)
	issue(poolLeafUnderRoot, poolRoot, false, 0)
	issue(poolSelfSignedLeaf, -1, false, x509.KeyUsageDigitalSignature)
	issue(poolCALeaf, poolIntermediate, true, caKU)
	issue(poolCertSignOnlyLeaf, poolIntermediate, false, x509.KeyUsageCertSign)
	issue(poolOtherRoot, -1, true, caKU)
	issue(poolLeafUnderSub, poolSubIntermediate, false, x509.KeyUsageDigitalSignature)
	p.ders[poolGarbage] = []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	return p
}

// FuzzVerifyAttesterChain checks verifyAttesterChain on x5c arrays and
// anchor sets assembled, in any order and with repeats, from a pool of
// real certificates: roots, intermediates, an intermediate below
// another, leaves under each, a self-signed leaf, a CA as the leaf, a
// leaf whose key usage excludes signatures, an unrelated root and a
// value that isn't a certificate. Beyond never panicking, what it
// accepts has:
//
//   - a signing certificate that is x5c's first, not self-signed, not a
//     CA, and whose key usage, if any, allows digital signatures;
//   - no self-signed certificate, and nothing that isn't a certificate,
//     anywhere in x5c;
//   - chains that each start at that certificate and end at one of the
//     configured anchors, none of which x5c carries below the leaf.
func FuzzVerifyAttesterChain(f *testing.F) {
	pool := newAttesterPool(f)
	f.Add([]byte{poolLeaf, poolIntermediate}, uint8(1<<poolRoot))
	f.Add([]byte{poolLeaf, poolIntermediate}, uint8(1<<poolRoot|1<<poolIntermediate))
	f.Add([]byte{poolLeaf, poolIntermediate, poolRoot}, uint8(1<<poolRoot))
	f.Add([]byte{poolLeafUnderSub, poolSubIntermediate, poolIntermediate}, uint8(1<<poolRoot|1<<poolSubIntermediate))
	f.Add([]byte{poolSelfSignedLeaf}, uint8(1<<poolRoot))
	f.Add([]byte{poolCALeaf, poolIntermediate}, uint8(1<<poolRoot))
	f.Add([]byte{poolLeafUnderRoot, poolIntermediate}, uint8(1<<poolRoot|1<<poolIntermediate))
	f.Add([]byte{poolGarbage}, uint8(0))
	f.Fuzz(func(t *testing.T, shape []byte, anchorMask uint8) {
		if len(shape) > 6 {
			shape = shape[:6]
		}
		ders := make([][]byte, len(shape))
		for i, s := range shape {
			ders[i] = pool.ders[int(s)%poolSize]
		}
		roots := x509.NewCertPool()
		var anchors []*x509.Certificate
		// Bits pick the root, the intermediates and the unrelated root.
		for bit, idx := range []int{poolRoot, poolIntermediate, poolSubIntermediate, poolOtherRoot} {
			if anchorMask&(1<<bit) != 0 {
				roots.AddCert(pool.certs[idx])
				anchors = append(anchors, pool.certs[idx])
			}
		}
		leaf, chains, err := verifyAttesterChain(ders, roots, attesterPoolNow)
		if err != nil {
			return
		}
		checkVerifiedAttesterChain(t, pool, shape, anchors, leaf, chains)
	})
}

func checkVerifiedAttesterChain(t *testing.T, pool attesterPool, shape []byte, anchors []*x509.Certificate, leaf *x509.Certificate, chains [][]*x509.Certificate) {
	t.Helper()
	switch first := int(shape[0]) % poolSize; first {
	case poolSelfSignedLeaf, poolCALeaf, poolCertSignOnlyLeaf, poolRoot, poolOtherRoot, poolIntermediate, poolSubIntermediate, poolGarbage:
		t.Fatalf("accepted x5c %v, whose signing certificate is pool entry %d", shape, first)
	}
	if !leaf.Equal(pool.certs[int(shape[0])%poolSize]) {
		t.Fatalf("x5c %v: the returned signing certificate isn't x5c's first", shape)
	}
	for _, s := range shape[1:] {
		if i := int(s) % poolSize; i == poolGarbage || i == poolRoot || i == poolOtherRoot || i == poolSelfSignedLeaf {
			t.Fatalf("accepted x5c %v, which carries pool entry %d", shape, i)
		}
	}
	if len(chains) == 0 {
		t.Fatalf("accepted x5c %v with no verified chain", shape)
	}
	for _, chain := range chains {
		checkVerifiedChainAnchor(t, pool, shape, anchors, leaf, chain)
	}
}

// checkVerifiedChainAnchor checks chain runs from leaf to one of
// anchors, which x5c (shape) doesn't carry.
func checkVerifiedChainAnchor(t *testing.T, pool attesterPool, shape []byte, anchors []*x509.Certificate, leaf *x509.Certificate, chain []*x509.Certificate) {
	t.Helper()
	anchor := chain[len(chain)-1]
	if !chain[0].Equal(leaf) || !slices.ContainsFunc(anchors, anchor.Equal) {
		t.Fatalf("x5c %v: a chain doesn't run from the signing certificate to a configured anchor", shape)
	}
	for _, s := range shape[1:] {
		if pool.certs[int(s)%poolSize].Equal(anchor) {
			t.Fatalf("accepted x5c %v, which carries anchor %q", shape, anchor.Subject)
		}
	}
}
