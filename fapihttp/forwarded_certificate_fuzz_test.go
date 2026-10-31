package fapihttp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// FuzzParseByteSequence checks parseByteSequence, which reads the RFC
// 9440 Client-Cert header a proxy forwards, against an independent
// reading of RFC 8941 §3.3.5/§4.2.7: beyond never panicking,
//
//   - it accepts exactly a value that, once leading and trailing spaces
//     are dropped, is ":", base64 characters, at most two "=" at the
//     end, ":", within MaxForwardedCertificateBytes, whose base64 decodes
//     to at least one byte;
//   - what it accepts re-encodes, canonically padded, to a Byte Sequence
//     it reads back to the same bytes, whose base64 is the input's own
//     up to pad bits.
func FuzzParseByteSequence(f *testing.F) {
	for _, seed := range []string{
		":AQID:", " :AQID: ", ":AQI=:", ":AQ==:", ":AQ:", ":AR==:", ":=:", ":==:", "::", ":", "",
		":AQ===:", ":A=Q=:", ":AQ\nID:", ":AQ-_:", "AQID", ":AQID:;p=1", "\t:AQID:", ":A:",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		der, err := parseByteSequence(value)
		want := byteSequenceOracle(value)
		if (err == nil) != want {
			t.Fatalf("parseByteSequence(%q) error = %v, independent reading accepts = %v", value, err, want)
		}
		if err != nil {
			return
		}
		checkByteSequenceRoundTrip(t, value, der)
	})
}

// byteSequenceOracle is RFC 8941's Byte Sequence grammar as
// parseByteSequence documents it, written without its code.
func byteSequenceOracle(value string) bool {
	if len(value) > MaxForwardedCertificateBytes {
		return false
	}
	v := strings.Trim(value, " ")
	if !strings.HasPrefix(v, ":") || !strings.HasSuffix(v, ":") || len(v) < 2 {
		return false
	}
	body := v[1 : len(v)-1]
	pad := len(body) - len(strings.TrimRight(body, "="))
	chars := body[:len(body)-pad]
	if pad > 2 {
		return false
	}
	for _, c := range []byte(chars) {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", rune(c)) {
			return false
		}
	}
	// n base64 characters carry 6n bits: a whole byte needs two, and one
	// left over after whole groups of four carries no byte at all.
	return len(chars) >= 2 && len(chars)%4 != 1
}

// checkByteSequenceRoundTrip checks what parseByteSequence read from
// value re-encodes and reads back unchanged.
func checkByteSequenceRoundTrip(t *testing.T, value string, der []byte) {
	t.Helper()
	if len(der) == 0 {
		t.Fatalf("parseByteSequence(%q) accepted an empty byte sequence", value)
	}
	canonical := ":" + base64.StdEncoding.EncodeToString(der) + ":"
	again, err := parseByteSequence(canonical)
	if err != nil || !bytes.Equal(again, der) {
		t.Fatalf("parseByteSequence(%q) = %x, but its canonical form %q reads back as %x, %v", value, der, canonical, again, err)
	}
	body := strings.TrimRight(strings.Trim(strings.Trim(value, " "), ":"), "=")
	reencoded := base64.RawStdEncoding.EncodeToString(der)
	// Only the last character may differ, in pad bits RFC 8941 §4.2.7
	// asks a parser to ignore.
	if len(body) != len(reencoded) || body[:len(body)-1] != reencoded[:len(reencoded)-1] {
		t.Fatalf("parseByteSequence(%q) = %x, which re-encodes as %q", value, der, reencoded)
	}
}

// FuzzForwardedClientCertificate checks ForwardedClientCertificate on a
// trusted request whose Client-Cert header holds a real certificate's
// Byte Sequence with fuzzed surroundings (spaces, padding, parameters,
// a second header line) or a fuzzed value of its own: it never panics,
// refuses only with ErrMalformedForwardedCertificate, and what it
// accepts is the one header line, read as the certificate whose DER the
// header carried.
func FuzzForwardedClientCertificate(f *testing.F) {
	der := fuzzForwardedCertificateDER(f)
	f.Add("", "", false, false, "")
	f.Add("  ", " ", true, false, "")
	f.Add("", ";a=1", false, false, "")
	f.Add("", "", false, true, "")
	f.Add("", "", false, false, ":AQID:")
	f.Fuzz(func(t *testing.T, lead, trail string, unpadded, twice bool, raw string) {
		encoded := base64.StdEncoding.EncodeToString(der)
		if unpadded {
			encoded = strings.TrimRight(encoded, "=")
		}
		value := lead + ":" + encoded + ":" + trail
		if raw != "" {
			value = raw
		}
		r := &http.Request{Header: http.Header{}}
		r.Header.Add(ClientCertHeader, value)
		if twice {
			r.Header.Add(ClientCertHeader, value)
		}
		cert, err := ForwardedClientCertificate(r, "", func(*http.Request) bool { return true })
		if err != nil {
			if !errors.Is(err, ErrMalformedForwardedCertificate) || cert != nil {
				t.Fatalf("ForwardedClientCertificate(%q) = %v, %v; want only ErrMalformedForwardedCertificate", value, cert, err)
			}
			return
		}
		checkForwardedCertificate(t, value, twice, cert)
	})
}

// checkForwardedCertificate checks a certificate ForwardedClientCertificate
// accepted from value is the one value's Byte Sequence carries.
func checkForwardedCertificate(t *testing.T, value string, twice bool, cert *x509.Certificate) {
	t.Helper()
	if twice || cert == nil {
		t.Fatalf("ForwardedClientCertificate(%q, twice %v) = %v, nil; want a refusal", value, twice, cert)
	}
	carried, err := parseByteSequence(value)
	if err != nil {
		t.Fatalf("ForwardedClientCertificate accepted %q, which isn't a Byte Sequence: %v", value, err)
	}
	if !bytes.Equal(cert.Raw, carried) {
		t.Fatalf("ForwardedClientCertificate(%q) returned a certificate that isn't the one the header carries", value)
	}
}

// fuzzForwardedCertificateDER is a self-signed certificate's DER.
func fuzzForwardedCertificateDER(f *testing.F) []byte {
	f.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fuzz"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}
	return der
}
