package dpop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// Non-ASCII letters whose Unicode case mapping lands on, or comes from,
// an ASCII one. net/http dials a host containing any of them through
// IDNA, as a DNS name other than its ASCII look-alike ("İbank.example"
// is "xn--ibank-7fd.example").
const (
	dottedCapitalI = "İ" // "İ": strings.ToLower gives "i"
	kelvinSign     = "K" // "K": strings.ToLower gives "k"
	fullwidthB     = "Ｂ" // "Ｂ"
)

// verifyHTUAt signs a proof for GET with htu written verbatim, as
// another client library would for the URL it is requesting, and
// verifies it at target.
func verifyHTUAt(t *testing.T, htu, target string) error {
	t.Helper()
	key := generateKey(t)
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	payload, err := json.Marshal(map[string]any{"jti": "j1", "htm": "GET", "htu": htu, "iat": now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType, JWK: &jwk}, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "GET", URL: mustURL(t, target), Now: now, MaxProofAge: time.Minute,
	})
	return err
}

// TestVerifyComparesHTUHostInASCIIOnly: a proof whose htu names a
// non-ASCII host never verifies, not even at the ASCII host Unicode case
// mapping folds it onto, and no proof verifies at a non-ASCII target;
// an htu differing from the target in ASCII case alone still does.
func TestVerifyComparesHTUHostInASCIIOnly(t *testing.T) {
	cases := []struct {
		htu, target string
		ok          bool
	}{
		{"https://IBank.EXAMPLE/accounts", "https://ibank.example/accounts", true},
		{"https://xn--ibank-7fd.example/accounts", "https://XN--IBANK-7FD.example/accounts", true},
		{"https://" + dottedCapitalI + "bank.example/accounts", "https://ibank.example/accounts", false},
		{"https://%C4%B0bank.example/accounts", "https://ibank.example/accounts", false},
		{"https://" + kelvinSign + "ey.example/accounts", "https://key.example/accounts", false},
		{"https://" + fullwidthB + "ank.example/accounts", "https://bank.example/accounts", false},
		{"https://" + dottedCapitalI + "bank.example/accounts", "https://" + dottedCapitalI + "bank.example/accounts", false},
		{"https://ibank.example/accounts", "https://" + dottedCapitalI + "bank.example/accounts", false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s at %s", c.htu, c.target), func(t *testing.T) {
			err := verifyHTUAt(t, c.htu, c.target)
			if c.ok && err != nil {
				t.Fatalf("Verify = %v, want nil", err)
			}
			if !c.ok && !errors.Is(err, ErrURIMismatch) {
				t.Fatalf("Verify = %v, want ErrURIMismatch", err)
			}
		})
	}
}

// TestCreateProofRefusesANonASCIIHost: CreateProof won't write an htu
// for a non-ASCII host, which before would have named the ASCII host
// Unicode case mapping folds it onto rather than the one net/http
// dials; a mixed-case ASCII host still gets a lowercased htu.
func TestCreateProofRefusesANonASCIIHost(t *testing.T) {
	key := generateKey(t)
	for _, raw := range []string{
		"https://" + dottedCapitalI + "bank.example/accounts",
		"https://%C4%B0bank.example/accounts",
		"https://" + kelvinSign + "ey.example/accounts",
		"https://" + fullwidthB + "ank.example/accounts",
	} {
		_, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "GET", URL: mustURL(t, raw), Now: time.Now()})
		if !errors.Is(err, ErrURLHostNotASCII) {
			t.Errorf("CreateProof(%q) = %v, want ErrURLHostNotASCII", raw, err)
		}
	}
	proof, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "GET", URL: mustURL(t, "https://IBank.Example/accounts"), Now: time.Now()})
	if err != nil {
		t.Fatalf("CreateProof(mixed-case ASCII host) = %v", err)
	}
	if got := proofHTU(t, proof); got != "https://ibank.example/accounts" {
		t.Fatalf("htu = %q, want https://ibank.example/accounts", got)
	}
}

func proofHTU(t *testing.T, proof string) string {
	t.Helper()
	parsed, err := jose.ParseCompact(proof)
	if err != nil {
		t.Fatal(err)
	}
	var c claims
	if err := json.Unmarshal(parsed.Payload, &c); err != nil {
		t.Fatal(err)
	}
	return c.HTU
}
