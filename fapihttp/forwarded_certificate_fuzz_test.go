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
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzParseByteSequence checks parseByteSequence, which reads the RFC
// 9440 Client-Cert header a proxy forwards, against an independent
// reading of RFC 9651 §3.3.5/§4.2.3/§4.2.7: beyond never panicking,
//
//   - it accepts exactly a value that, once leading and trailing spaces
//     are dropped, is ":", base64 characters, at most two "=" at the
//     end, ":", then zero or more RFC 9651 Parameters, within
//     MaxForwardedCertificateBytes, whose base64 decodes to at least one
//     byte;
//   - what it accepts re-encodes, canonically padded, to a Byte Sequence
//     it reads back to the same bytes, whose base64 is the input's own
//     up to pad bits.
func FuzzParseByteSequence(f *testing.F) {
	for _, seed := range []string{
		":AQID:", " :AQID: ", ":AQI=:", ":AQ==:", ":AQ:", ":AR==:", ":=:", ":==:", "::", ":", "",
		":AQ===:", ":A=Q=:", ":AQ\nID:", ":AQ-_:", "AQID", ":AQID:;p=1", "\t:AQID:", ":A:",
		":AQID:;a", ":AQID:; a=?1;b=-12.5", `:AQID:;a="q\"";b=%"%c3%a9"`, ":AQID:;a=@-1;b=t:/x",
		":AQID: ;a", ":AQID:;A", ":AQID:;a=1.", ":AQID:;a=%\"%c3\"", ":AQID:;a=:A=:", ":AQID:;",
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

// sfParameter is one RFC 9651 §4.2.3.2 parameter as a regular
// expression: ";", optional spaces, a key (§4.2.3.3), and optionally "="
// and a bare item: a Decimal or Integer (§4.2.4), a String (§4.2.5), a
// Token (§4.2.6), a Byte Sequence (§4.2.7), a Boolean (§4.2.8), a Date
// (§4.2.9) or a Display String (§4.2.10), whose escaped content is the
// one submatch, for parametersOracle to check it decodes to UTF-8.
var sfParameter = regexp.MustCompile(`^; *[a-z*][a-z0-9_\-.*]*(?:=(?:` +
	`-?[0-9]{1,12}\.[0-9]{1,3}|-?[0-9]{1,15}|` +
	`"(?:[\x20\x21\x23-\x5b\x5d-\x7e]|\\["\\])*"|` +
	"[A-Za-z*][!#$%&'*+\\-.^_`|~0-9A-Za-z:/]*|" +
	`:[A-Za-z0-9+/=]*:|\?[01]|@-?[0-9]{1,15}|` +
	`%"((?:[\x20\x21\x23\x24\x26-\x7e]|%[0-9a-f]{2})*)"))?`)

// parametersOracle reports whether s is RFC 9651 Parameters: zero or
// more of sfParameter, and nothing else.
func parametersOracle(s string) bool {
	for s != "" {
		m := sfParameter.FindStringSubmatchIndex(s)
		if m == nil {
			return false
		}
		if m[2] >= 0 {
			decoded, err := url.PathUnescape(s[m[2]:m[3]])
			if err != nil || !utf8.ValidString(decoded) {
				return false
			}
		}
		s = s[m[1]:]
	}
	return true
}

// byteSequenceOracle is RFC 9651's Byte Sequence Item grammar as
// parseByteSequence documents it, written without its code.
func byteSequenceOracle(value string) bool {
	if len(value) > MaxForwardedCertificateBytes {
		return false
	}
	v := strings.Trim(value, " ")
	if !strings.HasPrefix(v, ":") {
		return false
	}
	body, params, closed := strings.Cut(v[1:], ":")
	if !closed || !parametersOracle(params) {
		return false
	}
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
	body, _, _ := strings.Cut(strings.TrimPrefix(strings.Trim(value, " "), ":"), ":")
	body = strings.TrimRight(body, "=")
	reencoded := base64.RawStdEncoding.EncodeToString(der)
	// Only the last character may differ, in pad bits RFC 9651 §4.2.7
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
