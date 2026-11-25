package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

func ed25519TestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestSignerKeyManagerPrintsNoKey: the KeyManager
// NewKeyManagerFromSigners builds, custody declared or not, prints
// [REDACTED] for an ed25519.PrivateKey signer, which fmt would
// otherwise print byte by byte, under every rendering the matrix makes,
// its reflection fallback included.
func TestSignerKeyManagerPrintsNoKey(t *testing.T) {
	key := ed25519TestKey(t)
	specs := []SignerSpec{{Purpose: JARMSigning, Algorithm: fapi.EdDSA, Signer: key, KeyID: "k1"}}
	plain, err := NewKeyManagerFromSigners(specs)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewKeyManagerFromSigners(specs, DeclareCustody(KeyCustody{Durable: true}))
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{string(key.Seed())}
	rendertest.Check(t, plain, secrets)
	rendertest.Check(t, custody, secrets)

	const backends = "Backends:map[jarm_signing:{Signer:[REDACTED] Algorithm:EdDSA KeyID:k1 Previous:[]}]"
	if got, want := fmt.Sprintf("%+v", plain), "{"+backends+"}"; got != want {
		t.Errorf("%%+v = %q, want %q", got, want)
	}
	if got, want := fmt.Sprintf("%+v", custody), "{"+backends+" Custody:{Durable:true CrossInstanceConsistent:false}}"; got != want {
		t.Errorf("%%+v with custody = %q, want %q", got, want)
	}
	if got := fmt.Sprintf("%#v", plain); !strings.HasPrefix(got, "keys.signerKeyManager{") || !strings.Contains(got, "keys.signerBackend{") || strings.Contains(got, "Shadow") {
		t.Errorf("%%#v = %q, want the real type names", got)
	}
	if got := fmt.Sprintf("%#v", custody); !strings.HasPrefix(got, "keys.custodyKeyManager{") {
		t.Errorf("%%#v with custody = %q, want keys.custodyKeyManager", got)
	}
	if got := fmt.Sprintf("%v", custodyKeyManager{}); strings.Contains(got, "REDACTED") {
		t.Errorf("%%v of a custodyKeyManager without signers = %q, want no placeholder", got)
	}
}

// TestSignerKeyManagerLogsNoKey: log/slog's handlers log each purpose's
// algorithm and kid, and [REDACTED] for its signer.
func TestSignerKeyManagerLogsNoKey(t *testing.T) {
	key := ed25519TestKey(t)
	km, err := NewKeyManagerFromSigners([]SignerSpec{{Purpose: JARMSigning, Algorithm: fapi.EdDSA, Signer: key, KeyID: "k1"}}, DeclareCustody(KeyCustody{Durable: true}))
	if err != nil {
		t.Fatal(err)
	}
	plain := custodyKeyManagerOf(t, km).signerKeyManager
	for v, want := range map[any]string{
		plain: `{"Backends":{"jarm_signing":{"Signer":"[REDACTED]","Algorithm":"EdDSA","KeyID":"k1","Previous":[]}}}`,
		km:    `{"Backends":{"jarm_signing":{"Signer":"[REDACTED]","Algorithm":"EdDSA","KeyID":"k1","Previous":[]}},"Custody":{"Durable":true,"CrossInstanceConsistent":false}}`,
	} {
		if got := jsonLogged(v); got != want {
			t.Errorf("slog JSON logged %s, want %s", got, want)
		}
	}
}

func custodyKeyManagerOf(t *testing.T, km KeyManager) custodyKeyManager {
	t.Helper()
	c, ok := km.(custodyKeyManager)
	if !ok {
		t.Fatalf("NewKeyManagerFromSigners with custody returned %T", km)
	}
	return c
}

// jsonLogged is what log/slog's JSON handler logs of v, as the value of
// an attribute.
func jsonLogged(v any) string {
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key != "v" {
			return slog.Attr{}
		}
		return a
	}})).Info("", "v", v)
	out := strings.TrimSpace(buf.String())
	return strings.TrimSuffix(strings.TrimPrefix(out, `{"v":`), "}")
}

// TestInMemoryKeysPrintNoKey: NewInMemoryECDH's and NewInMemoryRSA's
// backends print their kid, and [REDACTED] for the private key, under
// every rendering, %s and %q among them, which would otherwise make
// fmt print what an *ecdh.PrivateKey points to.
func TestInMemoryKeysPrintNoKey(t *testing.T) {
	ec, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agreer, err := NewInMemoryECDH(ec, "e1")
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := NewInMemoryRSA(rk, "r1")
	if err != nil {
		t.Fatal(err)
	}
	rendertest.Check(t, agreer, []string{string(ec.Bytes())})
	rendertest.Check(t, decrypter, []string{string(rk.D.Bytes()), rk.D.String(), rk.Primes[0].String()})

	for v, want := range map[any]string{agreer: "{Priv:[REDACTED] KeyID:e1}", decrypter: "{Priv:[REDACTED] KeyID:r1}"} {
		if got := fmt.Sprintf("%+v", v); got != want {
			t.Errorf("%%+v = %q, want %q", got, want)
		}
		if got, want := jsonLogged(v), `{"Priv":"[REDACTED]","KeyID":"`+want[len(want)-3:len(want)-1]+`"}`; got != want {
			t.Errorf("slog JSON logged %s, want %s", got, want)
		}
	}
	if got := fmt.Sprintf("%#v", agreer); got != `keys.inMemoryECDH{Priv:"[REDACTED]", KeyID:"e1"}` {
		t.Errorf("%%#v = %q", got)
	}
	if got := fmt.Sprintf("%#v", decrypter); got != `keys.inMemoryRSA{Priv:"[REDACTED]", KeyID:"r1"}` {
		t.Errorf("%%#v = %q", got)
	}
	if got := fmt.Sprintf("%v", inMemoryECDH{kid: "e1"}); got != "{ e1}" {
		t.Errorf("%%v of a backend without a key = %q, want no placeholder", got)
	}
}
