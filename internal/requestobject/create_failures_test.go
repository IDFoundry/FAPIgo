package requestobject

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// failingReader fails every read, as an exhausted randomness source would.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

// failingSigner holds a key but fails every signature.
type failingSigner struct{ crypto.Signer }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signer unavailable")
}

// TestCreateReportsWhatStopsIt: Create refuses a nil signer and an
// invalid algorithm, and reports a randomness source and a signer that
// fail, rather than producing an object.
func TestCreateReportsWhatStopsIt(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := CreateParams{
		Signer: key, Algorithm: fapi.ES256, ClientID: "client-123", Audience: "https://as.example",
		Now: time.Now(), Lifetime: time.Minute, Parameters: testParameters(t),
	}
	for name, change := range map[string]func(*CreateParams){
		"nil signer":         func(p *CreateParams) { p.Signer = nil },
		"invalid algorithm":  func(p *CreateParams) { p.Algorithm = 0 },
		"failing randomness": func(p *CreateParams) { p.Random = failingReader{} },
		"failing signer":     func(p *CreateParams) { p.Signer = failingSigner{key} },
	} {
		p := valid
		change(&p)
		if token, err := Create(p); err == nil {
			t.Errorf("%s: Create = %q, nil error, want an error", name, token)
		}
	}
	if _, err := Create(valid); err != nil {
		t.Fatalf("Create with valid parameters: %v", err)
	}
}
