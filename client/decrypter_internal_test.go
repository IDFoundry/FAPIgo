package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
)

type recordingDecrypter struct {
	keys.Decrypter
	got keys.UnwrapRequest
}

func (d *recordingDecrypter) UnwrapContentEncryptionKey(_ context.Context, req keys.UnwrapRequest) ([]byte, error) {
	d.got = req
	return []byte("cek"), nil
}

// TestDecrypterUnwrapperForwardsHeader confirms every header input of
// the ECDH-ES key derivation, "apu"/"apv" included (RFC 7518 §4.6.2),
// reaches the configured keys.Decrypter.
func TestDecrypterUnwrapperForwardsHeader(t *testing.T) {
	epk, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingDecrypter{}
	u := decrypterUnwrapper{decrypter: rec, purpose: keys.IDTokenDecryption}
	header := jwe.Header{
		Algorithm: fapi.ECDHESA256KW, KeyID: "k1", EphemeralPublicKey: epk.PublicKey(),
		AgreementPartyUInfo: []byte("Alice"), AgreementPartyVInfo: []byte("Bob"),
	}
	if _, err := u.UnwrapCEK(context.Background(), header, []byte("wrapped")); err != nil {
		t.Fatalf("UnwrapCEK: %v", err)
	}
	got := rec.got
	if got.Purpose != keys.IDTokenDecryption || got.Algorithm != fapi.ECDHESA256KW || got.KeyID != "k1" ||
		!bytes.Equal(got.EncryptedKey, []byte("wrapped")) || got.EphemeralPublicKey != header.EphemeralPublicKey {
		t.Fatalf("UnwrapRequest = %+v", got)
	}
	if string(got.AgreementPartyUInfo) != "Alice" || string(got.AgreementPartyVInfo) != "Bob" {
		t.Fatalf("apu/apv = %q/%q, want Alice/Bob", got.AgreementPartyUInfo, got.AgreementPartyVInfo)
	}
}
