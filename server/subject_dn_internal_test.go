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
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func dnAttr(oid asn1.ObjectIdentifier, value string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: oid, Value: value}
}

var oidOrganization = asn1.ObjectIdentifier{2, 5, 4, 10}

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
