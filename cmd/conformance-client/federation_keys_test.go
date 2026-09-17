package main

import (
	"encoding/base64"
	"math/big"
	"testing"
)

func TestGenerateFederationJWKRoundTrip(t *testing.T) {
	priv, set, err := generateFederationJWK("test-kid")
	if err != nil {
		t.Fatalf("generateFederationJWK() error = %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("len(set.Keys) = %d, want 1", len(set.Keys))
	}
	jwk := set.Keys[0]
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		t.Errorf("kty/crv = %q/%q, want EC/P-256", jwk.Kty, jwk.Crv)
	}
	if jwk.Kid != "test-kid" {
		t.Errorf("kid = %q, want %q", jwk.Kid, "test-kid")
	}
	if jwk.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", jwk.Alg)
	}
	if jwk.Use != "" {
		t.Errorf("use = %q, want empty — see generateFederationJWK's own doc comment for why", jwk.Use)
	}
	if jwk.D == "" {
		t.Fatal("d is empty — generateFederationJWK must return the private key")
	}

	x := decodeCoordinate(t, jwk.X)
	y := decodeCoordinate(t, jwk.Y)
	d := decodeCoordinate(t, jwk.D)
	if x.Cmp(priv.X) != 0 || y.Cmp(priv.Y) != 0 || d.Cmp(priv.D) != 0 {
		t.Error("encoded jwk does not match the returned private key")
	}
}

func TestGenerateFederationJWKCoordinatesAreFixedWidth(t *testing.T) {
	// leftPad matters precisely when a coordinate's big.Int
	// representation would otherwise be shorter than 32 bytes — run
	// enough times that a short (leading-zero-byte) coordinate is
	// overwhelmingly likely to come up at least once, and confirm every
	// one still decodes to exactly 32 bytes.
	for i := 0; i < 64; i++ {
		_, set, err := generateFederationJWK("kid")
		if err != nil {
			t.Fatalf("generateFederationJWK() error = %v", err)
		}
		jwk := set.Keys[0]
		for name, v := range map[string]string{"x": jwk.X, "y": jwk.Y, "d": jwk.D} {
			b, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil {
				t.Fatalf("decode %s: %v", name, err)
			}
			if len(b) != 32 {
				t.Fatalf("len(%s) = %d, want 32 (iteration %d)", name, len(b), i)
			}
		}
	}
}

func TestPublicJWKSStripsPrivateComponent(t *testing.T) {
	_, priv, err := generateFederationJWK("kid")
	if err != nil {
		t.Fatalf("generateFederationJWK() error = %v", err)
	}
	pub := publicJWKS(priv)
	if len(pub.Keys) != 1 {
		t.Fatalf("len(pub.Keys) = %d, want 1", len(pub.Keys))
	}
	if pub.Keys[0].D != "" {
		t.Errorf("public jwks still carries \"d\" = %q", pub.Keys[0].D)
	}
	if pub.Keys[0].X != priv.Keys[0].X || pub.Keys[0].Y != priv.Keys[0].Y {
		t.Error("public jwks lost x/y")
	}
	if pub.Keys[0].Alg != priv.Keys[0].Alg || pub.Keys[0].Kid != priv.Keys[0].Kid {
		t.Error("public jwks lost alg/kid")
	}
}

func TestLeftPad(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		size int
		want []byte
	}{
		{"already exact size", []byte{1, 2, 3}, 3, []byte{1, 2, 3}},
		{"needs padding", []byte{1, 2}, 4, []byte{0, 0, 1, 2}},
		{"empty input", []byte{}, 2, []byte{0, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := leftPad(c.in, c.size)
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d", len(got), len(c.want))
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("leftPad(%v, %d) = %v, want %v", c.in, c.size, got, c.want)
				}
			}
		})
	}
}

func decodeCoordinate(t *testing.T, s string) *big.Int {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode coordinate: %v", err)
	}
	return new(big.Int).SetBytes(b)
}
