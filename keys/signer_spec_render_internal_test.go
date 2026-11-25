package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"reflect"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

// TestSignerSpecPrintsNoKey: a SignerSpec prints [REDACTED] for its
// Signer, which is often the private key itself, whatever prints it
// through the spec's own methods. fmt's reflection fallback and the
// encoders see Signer as the exported field it is, so they're allowed:
// an *ecdsa.PrivateKey sits behind a pointer the fallback prints as an
// address, but an ed25519.PrivateKey is a byte slice it prints whole.
func TestSignerSpecPrintsNoKey(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := SignerSpec{Purpose: IDTokenSigning, Algorithm: fapi.ES256, Signer: ec, KeyID: "kid-1"}
	rendertest.Check(t, spec, []string{string(ec.D.Bytes())}, rendertest.Allow(rendertest.Encoding))

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSpec := SignerSpec{Purpose: IDTokenSigning, Algorithm: fapi.EdDSA, Signer: ed}
	rendertest.Check(t, edSpec, []string{string(ed.Seed())}, rendertest.Allow(rendertest.Fallback, rendertest.Encoding))

	if got, want := fmt.Sprintf("%+v", spec), "{Purpose:id_token_signing Algorithm:ES256 Signer:[REDACTED] KeyID:kid-1 Previous:[]}"; got != want {
		t.Errorf("%%+v = %q, want %q", got, want)
	}
	if got := fmt.Sprintf("%#v", spec); !strings.HasPrefix(got, "keys.SignerSpec{") || !strings.Contains(got, `Signer:"[REDACTED]"`) {
		t.Errorf("%%#v = %q, want a keys.SignerSpec with a redacted Signer", got)
	}
	if got := fmt.Sprintf("%v", SignerSpec{}); strings.Contains(got, "REDACTED") {
		t.Errorf("%%v of a SignerSpec without a Signer = %q, want no placeholder", got)
	}
}

// TestSignerSpecShadowMatches keeps SignerSpec's shadow in step with it.
func TestSignerSpecShadowMatches(t *testing.T) {
	rendertest.CheckShadow(t, reflect.TypeFor[SignerSpec](), reflect.TypeFor[signerSpecShadow]())
}
