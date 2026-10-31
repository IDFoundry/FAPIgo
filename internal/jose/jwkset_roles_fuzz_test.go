package jose

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzJWKSetRoles checks ParseJWKSet, ParseTrustedJWKSet and
// ParseEncryptionJWKSet against each other and against per-key rules
// read independently of their code, where FuzzParseJWKSet only checks
// ParseJWKSet doesn't panic. For any body:
//
//   - the three accept or refuse the set as a whole together;
//   - each set's keys are exactly those of its entries parsed one at a
//     time, in order: an entry never affects another's reading;
//   - no entry is both a signature and an encryption key;
//   - an accepted signature entry has no private members and isn't
//     "use":"enc", and its key fits its algorithm: P-256 for ES256, an
//     RSA key of 2048 to 4096 bits for PS256, Ed25519 for EdDSA;
//   - ParseTrustedJWKSet reads every entry ParseJWKSet does identically,
//     and differs only by also accepting RSA keys of up to 8192 bits;
//   - an accepted encryption entry has no private members and isn't
//     "use":"sig", and its key fits its algorithm: an RSA key of 2048
//     to 4096 bits for RSA-OAEP-256, P-256 ECDH for ECDH-ES+A256KW.
func FuzzJWKSetRoles(f *testing.F) {
	for _, seed := range jwkSetRoleSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		sig, sigErr := ParseJWKSet(body)
		trusted, trustedErr := ParseTrustedJWKSet(body)
		enc, encErr := ParseEncryptionJWKSet(body)
		if (sigErr == nil) != (trustedErr == nil) || (sigErr == nil) != (encErr == nil) {
			t.Fatalf("set-level verdicts differ: ParseJWKSet %v, ParseTrustedJWKSet %v, ParseEncryptionJWKSet %v", sigErr, trustedErr, encErr)
		}
		if sigErr != nil {
			return
		}
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(body, &set); err != nil {
			t.Fatalf("all three accepted %q, which doesn't decode: %v", body, err)
		}
		var gotSig, gotTrusted []ParsedJWK
		var gotEnc []ParsedEncryptionJWK
		for _, entry := range set.Keys {
			s, tr, e := checkJWKSetEntry(t, entry)
			gotSig, gotTrusted, gotEnc = append(gotSig, s...), append(gotTrusted, tr...), append(gotEnc, e...)
		}
		if !sameParsedJWKs(sig, gotSig) || !sameParsedJWKs(trusted, gotTrusted) || !sameEncryptionJWKs(enc, gotEnc) {
			t.Fatalf("a set's keys differ from its entries' parsed one at a time: %q", body)
		}
	})
}

// checkJWKSetEntry parses entry alone as each kind of set, checks the
// per-key rules, and returns what each read from it.
func checkJWKSetEntry(t *testing.T, entry json.RawMessage) ([]ParsedJWK, []ParsedJWK, []ParsedEncryptionJWK) {
	t.Helper()
	single, _ := json.Marshal(map[string][]json.RawMessage{"keys": {entry}})
	sig, err1 := ParseJWKSet(single)
	trusted, err2 := ParseTrustedJWKSet(single)
	enc, err3 := ParseEncryptionJWKSet(single)
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("a one-entry set of %q is refused: %v, %v, %v", entry, err1, err2, err3)
	}
	if len(sig) > len(trusted) || len(trusted) > 1 || len(enc) > 1 || len(trusted)+len(enc) > 1 {
		t.Fatalf("entry %q read as %d signature, %d trusted and %d encryption keys", entry, len(sig), len(trusted), len(enc))
	}
	members := map[string]json.RawMessage{}
	_ = json.Unmarshal(entry, &members)
	if len(trusted) == 1 {
		checkSignatureEntry(t, entry, members, sig, trusted[0])
	}
	if len(enc) == 1 {
		checkEncryptionEntry(t, entry, members, enc[0])
	}
	return sig, trusted, enc
}

func checkSignatureEntry(t *testing.T, entry json.RawMessage, members map[string]json.RawMessage, sig []ParsedJWK, trusted ParsedJWK) {
	t.Helper()
	checkNoPrivateMembers(t, entry, members)
	if string(members["use"]) == `"enc"` {
		t.Fatalf("entry %q, for encryption, read as a signature key", entry)
	}
	maxBits := maxCallerRSAModulusBits
	if len(sig) == 0 {
		// Only the RSA ceiling may separate the two readings.
		rsaKey, ok := trusted.PublicKey.(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() <= maxCallerRSAModulusBits {
			t.Fatalf("entry %q is a trusted signature key but not a caller's", entry)
		}
		maxBits = maxRSAModulusBits
	} else if !reflect.DeepEqual(sig[0], trusted) {
		t.Fatalf("entry %q reads differently as a trusted key", entry)
	}
	if !signatureKeyFits(trusted.PublicKey, trusted.Algorithm, maxBits) {
		t.Fatalf("entry %q read as a %T key for %v", entry, trusted.PublicKey, trusted.Algorithm)
	}
}

func checkEncryptionEntry(t *testing.T, entry json.RawMessage, members map[string]json.RawMessage, key ParsedEncryptionJWK) {
	t.Helper()
	checkNoPrivateMembers(t, entry, members)
	if string(members["use"]) == `"sig"` {
		t.Fatalf("entry %q, for signatures, read as an encryption key", entry)
	}
	ok := false
	switch pub := key.PublicKey.(type) {
	case *rsa.PublicKey:
		ok = key.Algorithm == fapi.RSAOAEP256 && pub.N.BitLen() >= 2048 && pub.N.BitLen() <= maxCallerRSAModulusBits
	case *ecdh.PublicKey:
		ok = key.Algorithm == fapi.ECDHESA256KW && pub.Curve() == ecdh.P256()
	}
	if !ok {
		t.Fatalf("entry %q read as a %T key for %v", entry, key.PublicKey, key.Algorithm)
	}
}

func checkNoPrivateMembers(t *testing.T, entry json.RawMessage, members map[string]json.RawMessage) {
	t.Helper()
	for _, name := range []string{"d", "k", "p", "q", "dp", "dq", "qi"} {
		if _, ok := members[name]; ok {
			t.Fatalf("entry %q has private member %q but was read as a public key", entry, name)
		}
	}
}

func signatureKeyFits(pub crypto.PublicKey, alg fapi.SignatureAlgorithm, maxRSABits int) bool {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return alg == fapi.ES256 && key.Curve == elliptic.P256()
	case *rsa.PublicKey:
		return alg == fapi.PS256 && key.N.BitLen() >= 2048 && key.N.BitLen() <= maxRSABits
	case ed25519.PublicKey:
		return alg == fapi.EdDSA && len(key) == ed25519.PublicKeySize
	}
	return false
}

func sameParsedJWKs(a, b []ParsedJWK) bool {
	return len(a) == len(b) && (len(a) == 0 || reflect.DeepEqual(a, b))
}

func sameEncryptionJWKs(a, b []ParsedEncryptionJWK) bool {
	return len(a) == len(b) && (len(a) == 0 || reflect.DeepEqual(a, b))
}

// jwkSetRoleSeeds are sets mixing signature and encryption keys of each
// supported type, private members, use and alg mismatches, and RSA keys
// either side of the caller and trusted ceilings.
func jwkSetRoleSeeds(f *testing.F) [][]byte {
	f.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	modulus := func(bits int) string {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		return b64(n.Or(n, big.NewInt(1)).Bytes())
	}
	x, y := b64(ec.X.FillBytes(make([]byte, 32))), b64(ec.Y.FillBytes(make([]byte, 32)))
	entries := []map[string]any{
		{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "sig-ec"},
		{"kty": "EC", "crv": "P-256", "x": x, "y": y, "use": "enc", "kid": "enc-ec"},
		{"kty": "EC", "crv": "P-256", "x": x, "y": y, "alg": "ECDH-ES+A256KW"},
		{"kty": "EC", "crv": "P-256", "x": x, "y": y, "alg": "ES256", "use": "enc"},
		{"kty": "EC", "crv": "P-256", "x": x, "y": y, "d": x},
		{"kty": "OKP", "crv": "Ed25519", "x": b64(edPub)},
		{"kty": "RSA", "n": modulus(2048), "e": "AQAB", "use": "enc"},
		{"kty": "RSA", "n": modulus(2048), "e": "AQAB", "alg": "RSA-OAEP-256", "use": "sig"},
		{"kty": "RSA", "n": modulus(4608), "e": "AQAB", "alg": "PS256"},
		{"kty": "RSA", "n": modulus(8200), "e": "AQAB"},
		{"kty": "RSA", "n": modulus(2048), "e": "AQAB", "x5c": []string{"AQID", "!!"}},
	}
	all, _ := json.Marshal(map[string]any{"keys": entries})
	seeds := [][]byte{all, []byte(`{"keys":[]}`), []byte(`{"keys":[null,1,"x",{}]}`), []byte(`{"KEYS":[]}`)}
	for _, e := range entries {
		one, _ := json.Marshal(map[string]any{"keys": []any{e}})
		seeds = append(seeds, one)
	}
	return seeds
}
