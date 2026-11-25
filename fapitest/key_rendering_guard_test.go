package fapitest_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/rendertest"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/server"
)

// This file is the rendering matrix for key material, beside the
// redaction guard's for the values a flow hands its caller: every
// struct field of the guarded packages, exported or not, that holds a
// private key, a crypto.Signer, a cipher, or bytes named as a key or
// secret is reached by one of keyHolders' cases, which builds a value
// holding real key material the way a deployment does and renders it
// through rendertest's whole matrix. A new such field fails
// TestKeyHolderMatrixCoversEveryKeyField until a case covers it, or
// notKeyMaterial says why it isn't one.
//
// A case whose renderings print its key today is skipped, with the
// reason in knownLeak, so the matrix records the gap without failing
// the build; removing knownLeak is how a fix proves itself. A case
// whose key sits in an exported field the caller fills, which fmt's
// reflection fallback prints as it prints any exported field, accepts
// that fallback, with the reason in inputField.

// keyHolder is one case of the key-material matrix.
type keyHolder struct {
	// covers are the fields, as package.Type.field, whose key material
	// the value build returns holds.
	covers []string
	// build returns the value to render and the key material it holds.
	build func(t *testing.T) (value any, secrets []string)
	// knownLeak, when set, skips the case: some rendering prints the key.
	knownLeak string
	// inputField, when set, accepts what fmt's reflection fallback
	// prints, which calls none of the value's methods: the key is in an
	// exported field of an input type the caller fills.
	inputField string
}

// signerSpecEd25519 is why the keys.SignerSpec EdDSA case accepts fmt's
// reflection fallback.
const signerSpecEd25519 = "an ed25519.PrivateKey in SignerSpec's exported Signer field is a byte slice, which fmt's reflection fallback (%w outside Errorf, %p, a SignerSpec in an unexported field) prints byte by byte; an *ecdsa.PrivateKey or *rsa.PrivateKey sits behind a pointer it prints as an address"

// keyHolders are the key-material matrix's cases, by name.
var keyHolders = map[string]keyHolder{
	"pairwise.NewHMAC": {
		build: func(t *testing.T) (any, []string) {
			key := randomBytes(t, 32)
			return must(pairwise.NewHMAC(key))(t), []string{string(key)}
		}},
	"pairwise.NewReversible": {covers: []string{"pairwise.memoryReversibleOps.block"},
		build: func(t *testing.T) (any, []string) {
			macKey, encKey := randomBytes(t, 32), randomBytes(t, 32)
			return must(pairwise.NewReversible(macKey, encKey))(t), []string{string(macKey), string(encKey)}
		}},
	"keys.NewKeyManagerFromSigners ES256": {covers: []string{"keys.signerBackend.signer"},
		build: func(t *testing.T) (any, []string) { return signerKeyManager(t, fapi.ES256, ecdsaKey(t)) }},
	"keys.NewKeyManagerFromSigners PS256": {covers: []string{"keys.signerBackend.signer"},
		build: func(t *testing.T) (any, []string) { return signerKeyManager(t, fapi.PS256, rsaKey(t)) }},
	"keys.NewKeyManagerFromSigners EdDSA": {covers: []string{"keys.signerBackend.signer"},
		build: func(t *testing.T) (any, []string) { return signerKeyManager(t, fapi.EdDSA, ed25519Key(t)) }},
	"keys.SignerSpec ES256 and PS256": {covers: []string{"keys.SignerSpec.Signer"},
		build: func(t *testing.T) (any, []string) {
			ec, rsa := ecdsaKey(t), rsaKey(t)
			return []keys.SignerSpec{
				{Purpose: keys.JARMSigning, Algorithm: fapi.ES256, Signer: ec},
				{Purpose: keys.IDTokenSigning, Algorithm: fapi.PS256, Signer: rsa},
			}, append(keySecrets(ec), keySecrets(rsa)...)
		}},
	"keys.SignerSpec EdDSA": {covers: []string{"keys.SignerSpec.Signer"}, inputField: signerSpecEd25519,
		build: func(t *testing.T) (any, []string) {
			key := ed25519Key(t)
			return keys.SignerSpec{Purpose: keys.JARMSigning, Algorithm: fapi.EdDSA, Signer: key}, keySecrets(key)
		}},
	"federation issuers' Dependencies": {
		covers: []string{
			"federation.HistoricalKeysIssueDependencies.Signer", "federation.ResolveIssueDependencies.Signer",
			"federation.SelfIssueDependencies.Signer", "federation.SubordinateIssueDependencies.Signer",
			"federation.jwksDependencyFields.signer",
			"federation.TrustMarkIssueDependencies.Signer",
		},
		build: func(t *testing.T) (any, []string) {
			key := ecdsaKey(t)
			return struct {
				Historical  federation.HistoricalKeysIssueDependencies
				Resolve     federation.ResolveIssueDependencies
				Self        federation.SelfIssueDependencies
				Subordinate federation.SubordinateIssueDependencies
				TrustMark   federation.TrustMarkIssueDependencies
			}{
				federation.HistoricalKeysIssueDependencies{Signer: key, Algorithm: fapi.ES256},
				federation.ResolveIssueDependencies{Signer: key, Algorithm: fapi.ES256},
				federation.SelfIssueDependencies{Signer: key, Algorithm: fapi.ES256},
				federation.SubordinateIssueDependencies{Signer: key, Algorithm: fapi.ES256},
				federation.TrustMarkIssueDependencies{Signer: key, Algorithm: fapi.ES256},
			}, keySecrets(key)
		}},
	"federation issuers": {
		build: func(t *testing.T) (any, []string) {
			key := ed25519Key(t)
			return federationIssuers(t, key), keySecrets(key)
		}},
	"keys.NewInMemoryRSA": {covers: []string{"keys.inMemoryRSA.priv"},
		build: func(t *testing.T) (any, []string) {
			key := rsaKey(t)
			return must(keys.NewInMemoryRSA(key, "k"))(t), keySecrets(key)
		}},
	"keys.NewInMemoryECDH": {covers: []string{"keys.inMemoryECDH.priv"},
		build: func(t *testing.T) (any, []string) {
			key := must(ecdh.P256().GenerateKey(rand.Reader))(t)
			return must(keys.NewInMemoryECDH(key, "k"))(t), keySecrets(key)
		}},
	"ephemeral.NewKeyManager ES256 and PS256": {covers: []string{"ephemeral.signingKey.signer"},
		build: func(t *testing.T) (any, []string) {
			return ephemeralKeyManager(t, map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.JARMSigning: fapi.ES256, keys.IDTokenSigning: fapi.PS256}, nil)
		}},
	"ephemeral.NewKeyManager EdDSA": {covers: []string{"ephemeral.signingKey.signer"},
		build: func(t *testing.T) (any, []string) {
			return ephemeralKeyManager(t, map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.JARMSigning: fapi.EdDSA}, nil)
		}},
	"ephemeral.NewKeyManagerWithDecryption": {covers: []string{"ephemeral.decryptionKeys.keys"},
		build: func(t *testing.T) (any, []string) {
			return ephemeralKeyManager(t, map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.JARMSigning: fapi.ES256},
				map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{keys.IDTokenDecryption: fapi.RSAOAEP256, keys.UserInfoDecryption: fapi.ECDHESA256KW})
		}},
	"client sealers": {covers: []string{"client.sealKey.aead"},
		build: func(t *testing.T) (any, []string) {
			key := randomBytes(t, 32)
			c := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity}).Client
			return struct {
				Tokens  *client.TokenSetSealer
				Session *client.BackchannelSessionSealer
			}{must(client.NewTokenSetSealer(c, [][]byte{key}))(t), must(client.NewBackchannelSessionSealer(c, [][]byte{key}))(t)}, []string{string(key)}
		}},
}

// notKeyMaterial are the fields TestKeyHolderMatrixCoversEveryKeyField
// would take for key material that aren't, with the reason.
var notKeyMaterial = map[string]string{
	"keys.UnwrapRequest.EncryptedKey": "the content encryption key wrapped to the recipient's key: ciphertext",
}

// TestKeyHoldersDontPrintTheirKeys renders each keyHolders case through
// rendertest's matrix and fails for a rendering that carries its key.
func TestKeyHoldersDontPrintTheirKeys(t *testing.T) {
	for _, name := range slices.Sorted(maps.Keys(keyHolders)) {
		t.Run(name, func(t *testing.T) {
			tc := keyHolders[name]
			if tc.knownLeak != "" {
				t.Skip("known leak, awaiting a decision: " + tc.knownLeak)
			}
			value, secrets := tc.build(t)
			opts := []rendertest.Option{rendertest.Quick()}
			if tc.inputField != "" {
				opts = append(opts, rendertest.Allow(rendertest.Fallback))
			}
			rendertest.Check(t, value, secrets, opts...)
		})
	}
}

// keyMaterialTypes are the field types that hold key material.
var keyMaterialTypes = map[string]bool{
	"crypto.Signer": true, "crypto.Decrypter": true, "crypto.PrivateKey": true,
	"*ecdsa.PrivateKey": true, "*rsa.PrivateKey": true, "ed25519.PrivateKey": true, "*ecdh.PrivateKey": true,
	"cipher.Block": true, "cipher.AEAD": true,
}

// keyMaterialName is a byte-slice field name that says it holds a key.
var keyMaterialName = regexp.MustCompile(`(?i)key|secret|seed|priv`)

// TestKeyHolderMatrixCoversEveryKeyField parses the guarded packages and
// fails for a struct field holding key material (see keyMaterialTypes
// and keyMaterialName; a map or slice of them too) that no keyHolders
// case covers and notKeyMaterial doesn't excuse, and for a table entry
// naming no such field.
func TestKeyHolderMatrixCoversEveryKeyField(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range keyHolders {
		for _, field := range tc.covers {
			covered[field] = true
		}
	}
	found := map[string]bool{}
	for _, dir := range guardedPackages {
		for _, field := range keyMaterialFields(t, dir) {
			found[field] = true
			if _, excused := notKeyMaterial[field]; !covered[field] && !excused {
				t.Errorf("%s holds key material, and no keyHolders case covers it: add one, or say in notKeyMaterial why it isn't key material", field)
			}
		}
	}
	for _, field := range append(slices.Collect(maps.Keys(covered)), slices.Collect(maps.Keys(notKeyMaterial))...) {
		if !found[field] {
			t.Errorf("the key-material tables name %s, which no guarded package declares as a key field", field)
		}
	}
}

// keyMaterialFields is the key-material fields of the struct types
// declared in dir's non-test files, as package.Type.field.
func keyMaterialFields(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range typeSpecs(file) {
			if st, ok := spec.Type.(*ast.StructType); ok {
				out = append(out, structKeyFields(file.Name.Name+"."+spec.Name.Name, st)...)
			}
		}
	}
	return out
}

// structKeyFields is st's key-material fields, prefixed with typeName.
func structKeyFields(typeName string, st *ast.StructType) []string {
	var out []string
	for _, field := range st.Fields.List {
		typ := typeString(field.Type)
		for _, name := range field.Names {
			if holdsKeyMaterial(typ, name.Name) {
				out = append(out, typeName+"."+name.Name)
			}
		}
	}
	return out
}

// holdsKeyMaterial reports whether a field of type typ named name holds
// key material.
func holdsKeyMaterial(typ, name string) bool {
	for {
		if keyMaterialTypes[typ] {
			return true
		}
		if typ == "[]byte" || typ == "[][]byte" {
			return keyMaterialName.MatchString(name)
		}
		_, elem, ok := strings.Cut(typ, "]")
		if !ok || !strings.HasPrefix(typ, "[") && !strings.HasPrefix(typ, "map[") {
			return false
		}
		typ = elem
	}
}

// typeString writes a field's type expression as Go source does, for
// the shapes key material comes in.
func typeString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	case *ast.SelectorExpr:
		return typeString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + typeString(t.Elt)
	case *ast.MapType:
		return "map[" + typeString(t.Key) + "]" + typeString(t.Value)
	}
	return ""
}

// must is a constructor's result v, failing the test it's given on
// err: must(f())(t).
func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))(t)
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	return must(rsa.GenerateKey(rand.Reader, 2048))(t)
}

func ed25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// federationIssuers is one of each federation issuer, signing with key.
func federationIssuers(t *testing.T, key ed25519.PrivateKey) any {
	t.Helper()
	const id = "https://entity.example"
	clock := federation.SystemClock{}
	jwks := []byte(`{"keys":[]}`)
	return struct {
		Historical  *federation.HistoricalKeysIssuer
		Resolve     *federation.ResolveIssuer
		Self        *federation.SelfIssuer
		Subordinate *federation.SubordinateIssuer
		TrustMark   *federation.TrustMarkIssuer
	}{
		must(federation.NewHistoricalKeysIssuer(federation.HistoricalKeysIssueConfig{EntityID: id},
			federation.HistoricalKeysIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k", Clock: clock}))(t),
		must(federation.NewResolveIssuer(federation.ResolveIssueConfig{EntityID: id},
			federation.ResolveIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k", Clock: clock}))(t),
		must(federation.NewSelfIssuer(federation.SelfIssueConfig{EntityID: id, Lifetime: time.Hour},
			federation.SelfIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k", JWKS: jwks, Clock: clock}))(t),
		must(federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{EntityID: id, Lifetime: time.Hour},
			federation.SubordinateIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k", Clock: clock}))(t),
		must(federation.NewTrustMarkIssuer(federation.TrustMarkIssueConfig{EntityID: id},
			federation.TrustMarkIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k", Clock: clock}))(t),
	}
}

// signerKeyManager is keys.NewKeyManagerFromSigners over signer, with
// the key material it holds.
func signerKeyManager(t *testing.T, alg fapi.SignatureAlgorithm, signer crypto.Signer) (any, []string) {
	t.Helper()
	return must(keys.NewKeyManagerFromSigners([]keys.SignerSpec{{Purpose: keys.JARMSigning, Algorithm: alg, Signer: signer}}))(t), keySecrets(signer)
}

// ephemeralKeyManager is ephemeral.NewKeyManagerWithDecryption over
// purposes, with the key material it generated, read from its
// unexported fields.
func ephemeralKeyManager(t *testing.T, signing map[keys.SigningPurpose]fapi.SignatureAlgorithm, decryption map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm) (any, []string) {
	t.Helper()
	m, err := ephemeral.NewKeyManagerWithDecryption(signing, decryption)
	if err != nil {
		t.Fatal(err)
	}
	var secrets []string
	held := reflect.ValueOf(m).Elem()
	if dk := unexportedField(held, "decryption"); !dk.IsNil() {
		secrets = append(secrets, mapKeySecrets(unexportedField(dk.Elem(), "keys"))...)
	}
	return m, append(secrets, mapKeySecrets(unexportedField(held, "keys"))...)
}

// unexportedField is v's field name, readable though unexported.
func unexportedField(v reflect.Value, name string) reflect.Value {
	f := v.FieldByName(name)
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
}

// mapKeySecrets is the key material of m's values: a key, or a pointer
// to a struct holding one in its signer field.
func mapKeySecrets(m reflect.Value) []string {
	var secrets []string
	for _, v := range m.Seq2() {
		if v.Kind() == reflect.Pointer && v.Elem().Kind() == reflect.Struct {
			v = unexportedField(v.Elem(), "signer")
		}
		secrets = append(secrets, keySecrets(v.Interface())...)
	}
	return secrets
}

// keySecrets is the private parts of key, as bytes and as the decimal
// big.Int fields encode in.
func keySecrets(key any) []string {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return []string{string(k.D.FillBytes(make([]byte, 32))), k.D.String()}
	case *rsa.PrivateKey:
		return []string{string(k.D.Bytes()), k.D.String(), k.Primes[0].String()}
	case ed25519.PrivateKey:
		return []string{string(k.Seed())}
	case *ecdh.PrivateKey:
		return []string{string(k.Bytes())}
	}
	panic("keySecrets: unexpected key type " + reflect.TypeOf(key).String())
}
