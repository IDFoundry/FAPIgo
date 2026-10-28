package fapihttp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
)

// proxy trusts the reverse proxy's address in these tests.
var proxy = fapihttp.RemoteAddrIn(netip.MustParsePrefix("10.0.0.5/32"))

// forwardedTestCert is a self-signed client certificate and its DER.
func forwardedTestCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "payroll"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

// forwardedRequest is a request from remoteAddr carrying values in the
// Client-Cert header.
func forwardedRequest(remoteAddr string, values ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", nil)
	r.RemoteAddr = remoteAddr
	for _, v := range values {
		r.Header.Add(fapihttp.ClientCertHeader, v)
	}
	return r
}

// TestForwardedClientCertificateRefusesAHeaderFromTheClient: a client
// that reaches the server directly, setting the header itself to a
// victim's public certificate, gets ErrUntrustedForwarder rather than
// the victim's identity; the same header from the proxy is the
// certificate.
func TestForwardedClientCertificateRefusesAHeaderFromTheClient(t *testing.T) {
	cert, der := forwardedTestCert(t)
	value := ":" + base64.StdEncoding.EncodeToString(der) + ":"

	_, err := fapihttp.ForwardedClientCertificate(forwardedRequest("203.0.113.9:4711", value), "", proxy)
	if !errors.Is(err, fapihttp.ErrUntrustedForwarder) {
		t.Fatalf("a header from the client: err = %v, want ErrUntrustedForwarder", err)
	}
	if _, err := fapihttp.ForwardedClientCertificate(forwardedRequest("10.0.0.5:4711", value), "", nil); !errors.Is(err, fapihttp.ErrUntrustedForwarder) {
		t.Fatalf("a nil trusted: err = %v, want ErrUntrustedForwarder", err)
	}
	got, err := fapihttp.ForwardedClientCertificate(forwardedRequest("10.0.0.5:4711", value), "", proxy)
	if err != nil {
		t.Fatalf("from the proxy: %v", err)
	}
	if !got.Equal(cert) {
		t.Fatal("from the proxy: a different certificate")
	}
}

// TestForwardedClientCertificateAbsent: from the proxy, no header means
// the client presented no certificate.
func TestForwardedClientCertificateAbsent(t *testing.T) {
	got, err := fapihttp.ForwardedClientCertificate(forwardedRequest("10.0.0.5:4711"), "", proxy)
	if err != nil || got != nil {
		t.Fatalf("got %v, %v; want nil, nil", got, err)
	}
}

// TestForwardedClientCertificateEncodings covers RFC 9440 §2.1's Byte
// Sequence and what isn't one.
func TestForwardedClientCertificateEncodings(t *testing.T) {
	_, der := forwardedTestCert(t)
	b64 := base64.StdEncoding.EncodeToString(der)
	raw := base64.RawStdEncoding.EncodeToString(der)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for name, tc := range map[string]struct {
		values []string
		ok     bool
	}{
		"byte sequence":              {[]string{":" + b64 + ":"}, true},
		"surrounding spaces":         {[]string{"  :" + b64 + ": "}, true},
		"padding missing":            {[]string{":" + raw + ":"}, true},
		"twice":                      {[]string{":" + b64 + ":", ":" + b64 + ":"}, false},
		"a list":                     {[]string{":" + b64 + ":, :" + b64 + ":"}, false},
		"parameters":                 {[]string{":" + b64 + ":;a=1"}, false},
		"no colons":                  {[]string{b64}, false},
		"one colon":                  {[]string{":" + b64}, false},
		"empty":                      {[]string{"::"}, false},
		"PEM":                        {[]string{pemText}, false},
		"URL-encoded PEM":            {[]string{url.QueryEscape(pemText)}, false},
		"base64url":                  {[]string{":" + base64.URLEncoding.EncodeToString(der) + ":"}, !strings.ContainsAny(b64, "+/")},
		"line breaks":                {[]string{":" + b64[:64] + "\n" + b64[64:] + ":"}, false},
		"padding inside":             {[]string{":AA==" + b64 + ":"}, false},
		"three padding characters":   {[]string{":" + strings.TrimRight(b64, "=") + "===:"}, false},
		"not a certificate":          {[]string{":" + base64.StdEncoding.EncodeToString([]byte("not a certificate")) + ":"}, false},
		"a certificate and more":     {[]string{":" + base64.StdEncoding.EncodeToString(append(bytes.Clone(der), 0)) + ":"}, false},
		"longer than the limit":      {[]string{":" + strings.Repeat("A", fapihttp.MaxForwardedCertificateBytes) + ":"}, false},
		"empty value from the proxy": {[]string{""}, false},
		"a colon-wrapped space":      {[]string{": :"}, false},
		"two byte sequences":         {[]string{":" + b64[:8] + "::" + b64[8:] + ":"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := fapihttp.ForwardedClientCertificate(forwardedRequest("10.0.0.5:4711", tc.values...), "", proxy)
			if tc.ok {
				if err != nil || got == nil {
					t.Fatalf("got %v, %v; want the certificate", got, err)
				}
				return
			}
			if !errors.Is(err, fapihttp.ErrMalformedForwardedCertificate) {
				t.Fatalf("err = %v, want ErrMalformedForwardedCertificate", err)
			}
		})
	}
}

// TestForwardedClientCertificateNamedHeader reads the header the caller
// names, and only that one.
func TestForwardedClientCertificateNamedHeader(t *testing.T) {
	cert, der := forwardedTestCert(t)
	r := forwardedRequest("10.0.0.5:4711")
	r.Header.Set("X-Proxy-Client-Cert", ":"+base64.StdEncoding.EncodeToString(der)+":")
	got, err := fapihttp.ForwardedClientCertificate(r, "X-Proxy-Client-Cert", proxy)
	if err != nil || !got.Equal(cert) {
		t.Fatalf("got %v, %v; want the certificate", got, err)
	}
	if got, err := fapihttp.ForwardedClientCertificate(r, "", proxy); err != nil || got != nil {
		t.Fatalf("Client-Cert: got %v, %v; want nil, nil", got, err)
	}
}

// TestRemoteAddrIn compares r.RemoteAddr, and nothing else, with the
// prefixes.
func TestRemoteAddrIn(t *testing.T) {
	trusted := fapihttp.RemoteAddrIn(netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("fd00::/64"))
	for addr, want := range map[string]bool{
		"10.0.0.7:443":           true,
		"[::ffff:10.0.0.7]:443":  true,
		"[fd00::1]:443":          true,
		"10.0.1.7:443":           false,
		"[fd00:0:0:1::1]:443":    false,
		"10.0.0.7":               false,
		"":                       false,
		"proxy.example.com:443":  false,
		"[fe80::1%eth0]:443":     false,
		"203.0.113.9:4711":       false,
		"[2001:db8::10.0.0.7]:1": false,
	} {
		r := forwardedRequest(addr)
		r.Header.Set("X-Forwarded-For", "10.0.0.7")
		if got := trusted(r); got != want {
			t.Errorf("RemoteAddr %q: trusted = %v, want %v", addr, got, want)
		}
	}
	if fapihttp.RemoteAddrIn()(forwardedRequest("10.0.0.7:443")) {
		t.Error("no prefixes trusted an address")
	}
}
