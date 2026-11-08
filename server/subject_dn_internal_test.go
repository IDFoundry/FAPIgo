package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
)

func subjectCert(t *testing.T, rdns pkix.RDNSequence) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), RawSubject: raw}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		if hasNonStringValue(rdns) {
			// Go before 1.27 refuses such a certificate outright, so on
			// this toolchain the case can't reach the matcher at all.
			t.Skipf("this Go's x509 refuses a subject with a non-string attribute value: %v", err)
		}
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func hasNonStringValue(rdns pkix.RDNSequence) bool {
	for _, rdn := range rdns {
		for _, atv := range rdn {
			if _, ok := atv.Value.(string); !ok {
				return true
			}
		}
	}
	return false
}

func dnAttr(oid asn1.ObjectIdentifier, value string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: oid, Value: value}
}

var (
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
)

// intAttr is an attribute whose value is an INTEGER rather than a string.
func intAttr(oid asn1.ObjectIdentifier, value int) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: oid, Value: value}
}

func TestMatchesRegisteredSubjectDN(t *testing.T) {
	cases := []struct {
		name     string
		rdns     pkix.RDNSequence
		expected string
		want     bool
	}{
		{"Go form, canonical order", pkix.RDNSequence{{dnAttr(oidOrganization, "Bank")}, {dnAttr(oidCommonName, "client")}}, "CN=client,O=Bank", true},
		{"exact form, canonical order", pkix.RDNSequence{{dnAttr(oidOrganization, "Bank")}, {dnAttr(oidCommonName, "client")}}, "CN=client,O=Bank", true},
		// Encoded CN first: Go's form reorders it, the exact form keeps
		// it; both are registrations of this certificate.
		{"Go form, other encoded order", pkix.RDNSequence{{dnAttr(oidCommonName, "client")}, {dnAttr(oidOrganization, "Bank")}}, "CN=client,O=Bank", true},
		{"exact form, other encoded order", pkix.RDNSequence{{dnAttr(oidCommonName, "client")}, {dnAttr(oidOrganization, "Bank")}}, "O=Bank,CN=client", true},
		// A second CN: Go's form keeps only the last one, so it would
		// render exactly as the registered DN.
		{"second CN hidden by Go form", pkix.RDNSequence{{dnAttr(oidOrganization, "Bank")}, {dnAttr(oidCommonName, "attacker")}, {dnAttr(oidCommonName, "client")}}, "CN=client,O=Bank", false},
		{"second CN, exact form", pkix.RDNSequence{{dnAttr(oidOrganization, "Bank")}, {dnAttr(oidCommonName, "attacker")}, {dnAttr(oidCommonName, "client")}}, "CN=client,CN=attacker,O=Bank", true},
		{"second serialNumber hidden by Go form", pkix.RDNSequence{{dnAttr(oidSerialNumber, "1")}, {dnAttr(oidSerialNumber, "2")}, {dnAttr(oidCommonName, "client")}}, "SERIALNUMBER=2,CN=client", false},
		// An OU whose value isn't a string: pkix.Name skips it, so Go's
		// form would render exactly as the registered DN.
		{"non-string attribute hidden by Go form", pkix.RDNSequence{{dnAttr(oidOrganization, "Bank")}, {intAttr(oidOrganizationalUnit, 7)}, {dnAttr(oidCommonName, "client")}}, "CN=client,O=Bank", false},
		{"non-string attribute, exact form", pkix.RDNSequence{{dnAttr(oidOrganization, "Bank")}, {intAttr(oidOrganizationalUnit, 7)}, {dnAttr(oidCommonName, "client")}}, "CN=client,OU=7,O=Bank", true},
		{"different CN", pkix.RDNSequence{{dnAttr(oidOrganization, "Bank")}, {dnAttr(oidCommonName, "other")}}, "CN=client,O=Bank", false},
		{"empty registration", pkix.RDNSequence{{dnAttr(oidCommonName, "client")}}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesRegisteredSubjectDN(subjectCert(t, tc.rdns), tc.expected); got != tc.want {
				t.Fatalf("matchesRegisteredSubjectDN(%q) = %v, want %v", tc.expected, got, tc.want)
			}
		})
	}
}

// TestMatchesRegisteredSubjectDNNonStringValueAnyToolchain covers the
// non-string-attribute cases above without x509.ParseCertificate, which
// Go before 1.27 refuses for such a subject (so subjectCert skips them
// there): the certificate is assembled as a parser that accepts it
// would fill it, RawSubject as encoded and Subject from the same RDN
// sequence, so Go's form drops the INTEGER OU.
func TestMatchesRegisteredSubjectDNNonStringValueAnyToolchain(t *testing.T) {
	rdns := pkix.RDNSequence{{dnAttr(oidOrganization, "Bank")}, {intAttr(oidOrganizationalUnit, 7)}, {dnAttr(oidCommonName, "client")}}
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var parsed pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &parsed); err != nil || len(rest) != 0 {
		t.Fatalf("Unmarshal: %v (rest %d bytes)", err, len(rest))
	}
	cert := &x509.Certificate{RawSubject: raw}
	cert.Subject.FillFromRDNSequence(&parsed)
	if got := cert.Subject.String(); got != "CN=client,O=Bank" {
		t.Fatalf("Subject.String() = %q, want the OU dropped", got)
	}

	for expected, want := range map[string]bool{
		"CN=client,O=Bank":      false, // Go's form, which hides the OU
		"CN=client,OU=7,O=Bank": true,  // the exact form
	} {
		if got := matchesRegisteredSubjectDN(cert, expected); got != want {
			t.Errorf("matchesRegisteredSubjectDN(%q) = %v, want %v", expected, got, want)
		}
	}
}
