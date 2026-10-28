package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/mtls"
)

func selfSignedTestCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
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
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestThumbprintMatchesManualComputation(t *testing.T) {
	cert := selfSignedTestCert(t, "test-client")
	digest := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(digest[:])

	if got := mtls.Thumbprint(cert); got != want {
		t.Errorf("Thumbprint() = %q, want %q", got, want)
	}
}

func TestThumbprintIsDeterministic(t *testing.T) {
	cert := selfSignedTestCert(t, "test-client")
	first := mtls.Thumbprint(cert)
	second := mtls.Thumbprint(cert)
	if first != second {
		t.Errorf("Thumbprint() is not deterministic for the same certificate: %q != %q", first, second)
	}
}

func TestThumbprintDiffersForDifferentCertificates(t *testing.T) {
	a := selfSignedTestCert(t, "client-a")
	b := selfSignedTestCert(t, "client-b")
	if mtls.Thumbprint(a) == mtls.Thumbprint(b) {
		t.Errorf("Thumbprint() collided for two distinct certificates")
	}
}

// TestPublicKeyThumbprintMatchesCertificateKey checks a key hashes the
// same on its own as inside a certificate, and differently from another
// key.
func TestPublicKeyThumbprintMatchesCertificateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "k"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fromKey, err := mtls.PublicKeyThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fromCert, err := mtls.PublicKeyThumbprint(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if fromKey != fromCert || fromKey != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Errorf("PublicKeyThumbprint: key %q, certificate %q, want both the SPKI hash", fromKey, fromCert)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if t2, _ := mtls.PublicKeyThumbprint(&other.PublicKey); t2 == fromKey {
		t.Error("two keys have the same PublicKeyThumbprint")
	}
	if _, err := mtls.PublicKeyThumbprint("not a key"); err == nil {
		t.Error("PublicKeyThumbprint(not a key) = nil error")
	}
}
