package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func TestValidateCallerKeys(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rsaOf := func(bits, e int) *rsa.PublicKey {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		return &rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: e}
	}
	verification := []struct {
		name    string
		pub     any
		alg     fapi.SignatureAlgorithm
		wantErr error
		ok      bool
	}{
		{name: "ES256", pub: &ec.PublicKey, alg: fapi.ES256, ok: true},
		{name: "PS256 4096", pub: rsaOf(4096, rsaPublicExponent), alg: fapi.PS256, ok: true},
		{name: "PS256 over the caller ceiling", pub: rsaOf(4097, rsaPublicExponent), alg: fapi.PS256, wantErr: ErrRSAKeyTooLarge},
		{name: "PS256 exponent 3", pub: rsaOf(2048, 3), alg: fapi.PS256, wantErr: ErrUnsupportedRSAExponent},
		{name: "empty RSA key", pub: &rsa.PublicKey{}, alg: fapi.PS256},
		{name: "empty ECDSA key", pub: &ecdsa.PublicKey{}, alg: fapi.ES256},
		{name: "ECDSA point off the curve", pub: &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, alg: fapi.ES256},
	}
	for _, c := range verification {
		err := ValidateCallerVerificationKey(c.pub, c.alg)
		checkValidation(t, c.name, err, c.ok, c.wantErr)
	}
	checkValidation(t, "RSAOAEP256 over the caller ceiling", ValidateCallerEncryptionKey(rsaOf(8192, rsaPublicExponent), fapi.RSAOAEP256), false, ErrRSAKeyTooLarge)
	checkValidation(t, "ECDHESA256KW", ValidateCallerEncryptionKey(ecdhKey.PublicKey(), fapi.ECDHESA256KW), true, nil)
}

func checkValidation(t *testing.T, name string, err error, ok bool, wantErr error) {
	t.Helper()
	switch {
	case ok && err != nil:
		t.Errorf("%s: %v, want no error", name, err)
	case !ok && err == nil:
		t.Errorf("%s: no error", name)
	case wantErr != nil && !errors.Is(err, wantErr):
		t.Errorf("%s: %v, want %v", name, err, wantErr)
	}
}
