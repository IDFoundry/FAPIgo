package demokit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func selfSignedClientCertificate(t *testing.T, name string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestClientCertificates checks that only the hosts ServerTLS names ask
// for a client certificate, and that ClientWithCertificate presents
// whichever certificate its function returns at the time.
func TestClientCertificates(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n, err := New(listener.Addr().String(), []string{"plain.localhost", "mutual.localhost"}, "", "Test CA")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) == 0 {
				_, _ = fmt.Fprint(w, "none")
				return
			}
			_, _ = fmt.Fprint(w, r.TLS.PeerCertificates[0].Subject.CommonName)
		}),
		TLSConfig: n.ServerTLS("mutual.localhost"), ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	current := selfSignedClientCertificate(t, "first")
	c := n.ClientWithCertificate("client", func() *tls.Certificate { return current })
	presented := func(host string) string {
		t.Helper()
		res, err := c.Get("https://" + host + "/")
		if err != nil {
			t.Fatalf("GET %s: %v", host, err)
		}
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	if got := presented("mutual.localhost"); got != "first" {
		t.Errorf("mutual host saw %q, want first", got)
	}
	if got := presented("plain.localhost"); got != "none" {
		t.Errorf("plain host saw %q, want none: it never asks", got)
	}
	current = selfSignedClientCertificate(t, "second")
	if got := presented("mutual.localhost"); got != "second" {
		t.Errorf("after switching certificates, mutual host saw %q, want second", got)
	}
	current = nil
	if got := presented("mutual.localhost"); got != "none" {
		t.Errorf("with no certificate, mutual host saw %q, want none", got)
	}
}
