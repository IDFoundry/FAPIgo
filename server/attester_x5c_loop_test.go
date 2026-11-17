package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The chain an attacker builds to run crypto/x509's path builder to its
// limit of signature checks: CA certificates under two names that
// certify each other, each with its own SAN so the builder treats them
// as distinct, none self-signed. With one key, every signature verifies
// and every path is explored; with a key each, every candidate is still
// tried. It must be refused on its shape, before path building starts.
func TestVerifyAttesterChainRefusesCertificationLoopsBeforePathBuilding(t *testing.T) {
	for name, tc := range map[string]struct {
		oneKey bool
		want   string
	}{
		"one key":    {true, "same public key"},
		"a key each": {false, "same subject"},
	} {
		t.Run(name, func(t *testing.T) {
			ders := certificationLoop(t, tc.oneKey)
			_, _, err := verifyAttesterChain(ders, x509.NewCertPool(), time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verifyAttesterChain(a certification loop) = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// certificationLoop returns a leaf certified by "A", then nine CA
// certificates alternating "A" and "B", each certified by the other.
func certificationLoop(t *testing.T, oneKey bool) [][]byte {
	t.Helper()
	shared, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issue := func(serial int64, subject, issuer string, isCA bool) []byte {
		t.Helper()
		key := shared
		if !oneKey {
			if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
				t.Fatal(err)
			}
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			IsCA: isCA, BasicConstraintsValid: true, DNSNames: []string{fmt.Sprintf("c%d.example", serial)},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, &x509.Certificate{Subject: pkix.Name{CommonName: issuer}}, &key.PublicKey, shared)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	ders := [][]byte{issue(1, "leaf", "A", false)}
	names := []string{"A", "B"}
	for i := range 9 {
		ders = append(ders, issue(int64(i+2), names[i%2], names[(i+1)%2], true))
	}
	return ders
}
