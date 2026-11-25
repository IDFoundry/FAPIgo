package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestParseJWKSetHonoursKeyOps: a verification key set keeps an entry
// whose key_ops lists "verify", or that has none or an empty one, and
// skips, with the reason, one whose key_ops lists other operations
// only: a key its publisher marked for encryption isn't verified with.
func TestParseJWKSetHonoursKeyOps(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(kid string, ops any) []byte {
		return rawKeySetEntry(t, jwk.WithKeyID(kid), map[string]any{"use": nil, "key_ops": ops})
	}
	body := jwkSetBody(t,
		entry("verify", []string{"verify"}),
		entry("verify-and-sign", []string{"sign", "verify"}),
		entry("none", nil),
		entry("empty", []string{}),
		entry("encrypt", []string{"encrypt", "wrapKey"}),
		entry("sign", []string{"sign"}),
	)
	keys, skipped, err := ParseJWKSetWithSkips(body)
	if err != nil {
		t.Fatalf("ParseJWKSetWithSkips: %v", err)
	}
	var kept []string
	for _, k := range keys {
		kept = append(kept, k.KeyID)
	}
	if got, want := strings.Join(kept, ","), "verify,verify-and-sign,none,empty"; got != want {
		t.Errorf("kept %s, want %s", got, want)
	}
	if len(skipped) != 2 || skipped[0].KeyID != "encrypt" || skipped[1].KeyID != "sign" {
		t.Fatalf("skipped = %+v, want the encrypt and sign entries", skipped)
	}
	if reason := skipped[0].Reason.Error(); !strings.Contains(reason, `key_ops ["encrypt" "wrapKey"] lists none of ["verify"]`) {
		t.Errorf("skip reason = %q, want it to name the key_ops and the operation", reason)
	}
}

// TestParseJWKSetRefusesMalformedKeyOps: key_ops is an array of strings
// (RFC 7517 §4.3); an entry with another shape is skipped, with the
// reason, rather than read as having no restriction.
func TestParseJWKSetRefusesMalformedKeyOps(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	body := jwkSetBody(t, rawKeySetEntry(t, jwk.WithKeyID("k"), map[string]any{"key_ops": "verify"}))
	keys, skipped, err := ParseJWKSetWithSkips(body)
	if err != nil {
		t.Fatalf("ParseJWKSetWithSkips: %v", err)
	}
	if len(keys) != 0 || len(skipped) != 1 {
		t.Fatalf("keys = %+v, skipped = %+v; want the entry skipped", keys, skipped)
	}
}

// TestParseEncryptionJWKSetHonoursKeyOps: an encryption key set keeps
// an entry whose key_ops lists an operation encrypting to it uses
// ("encrypt", "wrapKey", "deriveKey" or "deriveBits"), or has none or
// an empty one, and skips one whose key_ops lists only others.
func TestParseEncryptionJWKSetHonoursKeyOps(t *testing.T) {
	rsaKey := testRSAKey(t, 2048)
	ecKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaEntry := func(kid string, ops any) []byte {
		return rawKeySetEntry(t, encryptionJWK(t, &rsaKey.PublicKey, fapi.RSAOAEP256, kid), map[string]any{"key_ops": ops})
	}
	ecEntry := func(kid string, ops any) []byte {
		return rawKeySetEntry(t, encryptionJWK(t, ecKey.PublicKey(), fapi.ECDHESA256KW, kid), map[string]any{"key_ops": ops})
	}
	body := jwkSetBody(t,
		rsaEntry("wrap", []string{"wrapKey"}),
		rsaEntry("encrypt", []string{"encrypt"}),
		ecEntry("derive", []string{"deriveKey"}),
		ecEntry("bits", []string{"deriveBits"}),
		ecEntry("empty", []string{}),
		rsaEntry("none", nil),
		rsaEntry("verify", []string{"verify"}),
		ecEntry("sign", []string{"sign", "verify"}),
		rsaEntry("malformed", "wrapKey"),
	)
	keys, err := ParseEncryptionJWKSet(body)
	if err != nil {
		t.Fatalf("ParseEncryptionJWKSet: %v", err)
	}
	var kept []string
	for _, k := range keys {
		kept = append(kept, k.KeyID)
	}
	if got, want := strings.Join(kept, ","), "wrap,encrypt,derive,bits,empty,none"; got != want {
		t.Errorf("kept %s, want %s", got, want)
	}
}

// TestKeyOpsReasonIsBounded: the skip reason quotes at most
// maxQuotedKeyOps of an entry's key_ops, each cut like a kid, since the
// set's publisher chooses them.
func TestKeyOpsReasonIsBounded(t *testing.T) {
	ops := []string{strings.Repeat("x", 200), "b", "c", "d", "e", "f"}
	err := checkKeyOps(ops, keyOpVerify)
	if err == nil {
		t.Fatal("checkKeyOps accepted key_ops without verify")
	}
	if msg := err.Error(); strings.Contains(msg, strings.Repeat("x", maxQuotedKeyIDBytes+1)) || !strings.Contains(msg, "and 2 more") || strings.Contains(msg, `"e"`) {
		t.Errorf("reason = %q, want it bounded", msg)
	}
}
