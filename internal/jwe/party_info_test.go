package jwe

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// gojoseVectors is testdata/gojose_ecdh_es_a256kw.json: ECDH-ES+A256KW
// JWEs for one P-256 recipient key. "go-jose-encrypter" is go-jose
// v4.1.4's own Encrypt output (no apu/apv); the others were built with
// go-jose's own Concat KDF (josecipher.DeriveECDHES) and AES key wrap
// over headers carrying "apu"/"apv", and go-jose decrypts every one —
// so they are independent of this package's KDF.
type gojoseVectors struct {
	// RecipientScalar is the test-only recipient P-256 private scalar,
	// hex-encoded.
	RecipientScalar string `json:"recipient_p256_scalar_hex"`
	Vectors         []struct {
		Name    string `json:"name"`
		Compact string `json:"compact"`
	} `json:"vectors"`
}

func loadGoJoseVectors(t *testing.T) (*ecdh.PrivateKey, gojoseVectors) {
	t.Helper()
	b, err := os.ReadFile("testdata/gojose_ecdh_es_a256kw.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v gojoseVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	d, err := hex.DecodeString(v.RecipientScalar)
	if err != nil {
		t.Fatalf("decode recipient scalar: %v", err)
	}
	priv, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		t.Fatalf("recipient key: %v", err)
	}
	return priv, v
}

// TestDecryptInteropGoJosePartyInfo decrypts JWEs whose senders set
// "apu"/"apv". RFC 7518 §4.6.2 makes both part of the Concat KDF's
// OtherInfo, so a recipient that ignores them derives the wrong
// key-encryption key and fails every such JWE.
func TestDecryptInteropGoJosePartyInfo(t *testing.T) {
	priv, v := loadGoJoseVectors(t)
	if len(v.Vectors) < 4 {
		t.Fatalf("got %d vectors, want at least 4", len(v.Vectors))
	}
	for _, vec := range v.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			res, err := Decrypt(context.Background(), DecryptRequest{
				Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: vec.Compact,
			})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(res.Plaintext) != `{"sub":"alice"}` {
				t.Fatalf("Plaintext = %q", res.Plaintext)
			}
		})
	}
}

// TestDecryptInteropGoJosePartyInfoViaUnwrapper is the same interop
// check through the Unwrapper path a keys.Decrypter takes, which must
// receive apu/apv in the header it's handed.
func TestDecryptInteropGoJosePartyInfoViaUnwrapper(t *testing.T) {
	priv, v := loadGoJoseVectors(t)
	for _, vec := range v.Vectors {
		u := &fakeUnwrapper{alg: fapi.ECDHESA256KW, key: priv}
		if _, err := Decrypt(context.Background(), DecryptRequest{
			Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: u, Compact: vec.Compact,
		}); err != nil {
			t.Fatalf("%s: Decrypt via Unwrapper: %v", vec.Name, err)
		}
	}
}

// TestConcatKDFAppendixCKnownAnswer is RFC 7518 Appendix C's ECDH-ES
// worked example: Bob's static key, Alice's ephemeral key, apu "Alice"
// and apv "Bob" (as base64url header values) derive the 128-bit A128GCM
// key "VqqN6vgjbSBcIijNcacQGg".
func TestConcatKDFAppendixCKnownAnswer(t *testing.T) {
	b64 := base64.RawURLEncoding
	bobD, _ := b64.DecodeString("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw")
	bob, err := ecdh.P256().NewPrivateKey(bobD)
	if err != nil {
		t.Fatalf("bob key: %v", err)
	}
	epk, err := parseEPK(&rawEPK{
		Kty: "EC", Crv: "P-256",
		X: "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
		Y: "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
	})
	if err != nil {
		t.Fatalf("alice epk: %v", err)
	}
	z, err := bob.ECDH(epk)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	apu, err := decodePartyInfo("QWxpY2U")
	if err != nil {
		t.Fatalf("apu: %v", err)
	}
	apv, err := decodePartyInfo("Qm9i")
	if err != nil {
		t.Fatalf("apv: %v", err)
	}
	info, err := otherInfo("A128GCM", apu, apv, 128)
	if err != nil {
		t.Fatalf("otherInfo: %v", err)
	}
	if got := b64.EncodeToString(concatKDF(z, 128, info)); got != "VqqN6vgjbSBcIijNcacQGg" {
		t.Fatalf("derived key = %s, want VqqN6vgjbSBcIijNcacQGg", got)
	}
}

func TestEncryptDecryptRoundTripWithPartyInfo(t *testing.T) {
	priv := generateECDHKey(t)
	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv.PublicKey(),
		AgreementPartyUInfo: []byte("Alice"), AgreementPartyVInfo: []byte("Bob"), Plaintext: []byte("secret"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	res, err := Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: compact,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(res.Header.AgreementPartyUInfo, []byte("Alice")) || !bytes.Equal(res.Header.AgreementPartyVInfo, []byte("Bob")) {
		t.Fatalf("apu/apv = %q/%q, want Alice/Bob", res.Header.AgreementPartyUInfo, res.Header.AgreementPartyVInfo)
	}
}

// TestEncryptOmitsAbsentPartyInfo keeps the header this module emits
// unchanged when no apu/apv are requested.
func TestEncryptOmitsAbsentPartyInfo(t *testing.T) {
	headerJSON, err := marshalHeader(Header{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM})
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	if bytes.Contains(headerJSON, []byte("apu")) || bytes.Contains(headerJSON, []byte("apv")) {
		t.Fatalf("header = %s, want no apu/apv", headerJSON)
	}
}

func TestEncryptRejectsPartyInfoForRSA(t *testing.T) {
	priv := generateRSAKey(t)
	if _, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey,
		AgreementPartyUInfo: []byte("Alice"), Plaintext: []byte("secret"),
	}); err == nil {
		t.Fatal("Encrypt(RSAOAEP256 with apu) = nil error, want error")
	}
}

func TestParseHeaderRejectsMalformedPartyInfo(t *testing.T) {
	for name, header := range map[string]string{
		"padded apu":       `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","apu":"QWxpY2U="}`,
		"std alphabet apv": `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","apv":"+/8"}`,
		"non-string apu":   `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","apu":5}`,
		"case variant apu": `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","APU":"QWxpY2U"}`,
	} {
		if _, err := parseHeader([]byte(header)); err == nil {
			t.Errorf("%s: parseHeader = nil error, want error", name)
		}
	}
}
