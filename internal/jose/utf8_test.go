package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// lossyJSON are JSON texts encoding/json would decode with U+FFFD in
// place of what was signed: RFC 8725 §3.7 and RFC 7519 §7.2 have a JWT
// with such a header or claims set refused.
var lossyJSON = map[string]string{
	"raw 0xff byte":       "{\"sub\":\"\xffalice\"}",
	"overlong encoding":   "{\"sub\":\"\xc0\xafalice\"}",
	"lone high surrogate": `{"sub":"\ud800alice"}`,
	"lone low surrogate":  `{"sub":"\udc00alice"}`,
	"reversed pair":       `{"sub":"\udc00\ud800"}`,
	"invalid in a key":    "{\"s\xffb\":\"alice\"}",
}

func compactOf(header, payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(payload)) + "." + enc(make([]byte, 64))
}

func TestParseCompactRefusesLossyPayload(t *testing.T) {
	for name, payload := range lossyJSON {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCompact(compactOf(`{"alg":"ES256"}`, payload)); !errors.Is(err, ErrMalformed) {
				t.Errorf("ParseCompact = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestParseCompactRefusesLossyHeader(t *testing.T) {
	for name, header := range map[string]string{
		"raw 0xff in kid":         "{\"alg\":\"ES256\",\"kid\":\"k\xff\"}",
		"lone surrogate in kid":   `{"alg":"ES256","kid":"k\ud800"}`,
		"lone surrogate in a key": `{"alg":"ES256","\udc00":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCompact(compactOf(header, `{}`)); err == nil {
				t.Error("ParseCompact = nil error, want refusal")
			}
		})
	}
}

// TestParseCompactKeepsValidUnicode: escapes that decode as written,
// a surrogate pair among them, and raw multi-byte UTF-8 still parse.
func TestParseCompactKeepsValidUnicode(t *testing.T) {
	for _, payload := range []string{`{"sub":"é"}`, `{"sub":"😀"}`, `{"sub":"\\ud800"}`, `{"sub":"é😀"}`, `{"sub":"�"}`} {
		c, err := ParseCompact(compactOf(`{"alg":"ES256","kid":"é"}`, payload))
		if err != nil {
			t.Errorf("ParseCompact(%s) = %v", payload, err)
			continue
		}
		if string(c.Payload) != payload {
			t.Errorf("Payload = %s, want %s", c.Payload, payload)
		}
	}
}

// TestSignRefusesLossyPayload: Sign won't produce a JWS ParseCompact
// would refuse.
func TestSignRefusesLossyPayload(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range lossyJSON {
		if _, err := Sign(key, Header{Algorithm: fapi.ES256}, []byte(payload)); err == nil {
			t.Errorf("%s: Sign = nil error, want refusal", name)
		}
	}
}
