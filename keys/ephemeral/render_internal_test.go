package ephemeral

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/rendertest"
	"github.com/idfoundry/fapigo/keys"
)

// TestKeyManagerPrintsNoKey: a KeyManager prints each purpose's kid,
// and [REDACTED] for its key, under every rendering the matrix makes,
// fmt's reflection fallback included: an ed25519.PrivateKey is a byte
// slice, which fmt would otherwise print byte by byte.
func TestKeyManagerPrintsNoKey(t *testing.T) {
	m, err := NewKeyManagerWithDecryption(
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.JARMSigning: fapi.EdDSA},
		map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{keys.IDTokenDecryption: fapi.ECDHESA256KW})
	if err != nil {
		t.Fatal(err)
	}
	signing, ok := m.keys[keys.JARMSigning].signer.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("the EdDSA key is a %T", m.keys[keys.JARMSigning].signer)
	}
	decryption, ok := m.decryption.keys[keys.IDTokenDecryption].(*ecdh.PrivateKey)
	if !ok {
		t.Fatalf("the ECDH-ES key is a %T", m.decryption.keys[keys.IDTokenDecryption])
	}
	rendertest.Check(t, m, []string{string(signing.Seed()), string(decryption.Bytes())})

	const want = "{Keys:map[jarm_signing:{Key:[REDACTED] KeyID:ephemeral-1-EdDSA}] Decryption:map[1:{Key:[REDACTED] KeyID:ephemeral-dec-1-ECDH-ES+A256KW}]}"
	if got := fmt.Sprintf("%+v", m); got != want {
		t.Errorf("%%+v = %q, want %q", got, want)
	}
	if got := fmt.Sprintf("%#v", m); !strings.HasPrefix(got, "ephemeral.KeyManager{") {
		t.Errorf("%%#v = %q, want an ephemeral.KeyManager", got)
	}
	if got := fmt.Sprintf("%v", &KeyManager{kid: map[keys.SigningPurpose]string{}}); strings.Contains(got, "REDACTED") {
		t.Errorf("%%v of a KeyManager without keys = %q, want no placeholder", got)
	}
}

// TestKeyManagerLogsNoKey: log/slog's JSON handler logs each purpose's
// kid, and [REDACTED] for its key.
func TestKeyManagerLogsNoKey(t *testing.T) {
	m, err := NewKeyManagerWithDecryption(
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.JARMSigning: fapi.EdDSA},
		map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{keys.IDTokenDecryption: fapi.RSAOAEP256})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("km", "v", m)
	const want = `"v":{"Keys":{"jarm_signing":{"Key":"[REDACTED]","KeyID":"ephemeral-1-EdDSA"}},"Decryption":{"1":{"Key":"[REDACTED]","KeyID":"ephemeral-dec-1-RSA-OAEP-256"}}}`
	if got := buf.String(); !strings.Contains(got, want) {
		t.Errorf("slog JSON logged %s, want it to hold %s", got, want)
	}
}
