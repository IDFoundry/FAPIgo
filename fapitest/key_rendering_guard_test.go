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
	"io/fs"
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
	"github.com/idfoundry/fapigo/client/sessioncookie"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/rendertest"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/server/interactioncookie"
)

// This file is the rendering matrix for key material, beside the
// redaction guard's for the values a flow hands its caller: every
// struct field of the guarded packages, exported or not, that holds a
// private key, a crypto.Signer, a cipher, or bytes named as a key or
// secret, or whose type holds such a field at any depth (a deps pointer
// to a Dependencies struct with a Signer in it, a map of structs with a
// cipher in each), is reached by one of keyHolders' cases, which builds
// a value holding real key material the way a deployment does and
// renders it through rendertest's whole matrix. A new such field fails
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
	"keys.NewKeyManagerFromSigners ES256": {covers: []string{"keys.signerBackend.signer", "keys.signerKeyManager.backends"},
		build: func(t *testing.T) (any, []string) { return signerKeyManager(t, fapi.ES256, ecdsaKey(t)) }},
	"keys.NewKeyManagerFromSigners PS256": {covers: []string{"keys.signerBackend.signer", "keys.signerKeyManager.backends"},
		build: func(t *testing.T) (any, []string) { return signerKeyManager(t, fapi.PS256, rsaKey(t)) }},
	"keys.NewKeyManagerFromSigners EdDSA": {covers: []string{"keys.signerBackend.signer", "keys.signerKeyManager.backends"},
		build: func(t *testing.T) (any, []string) { return signerKeyManager(t, fapi.EdDSA, ed25519Key(t)) }},
	"keys.NewKeyManagerFromSigners with DeclareCustody": {covers: []string{"keys.custodyKeyManager.signerKeyManager"},
		build: func(t *testing.T) (any, []string) {
			key := ecdsaKey(t)
			custody := keys.DeclareCustody(keys.KeyCustody{Durable: true})
			return must(keys.NewKeyManagerFromSigners([]keys.SignerSpec{{Purpose: keys.JARMSigning, Algorithm: fapi.ES256, Signer: key}}, custody))(t), keySecrets(key)
		}},
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
		covers: []string{
			"federation.HistoricalKeysIssuer.deps", "federation.ResolveIssuer.deps", "federation.SelfIssuer.deps",
			"federation.SubordinateIssuer.deps", "federation.TrustMarkIssuer.deps",
			// The shadows the issuers' Format methods print in their place.
			"federation.historicalKeysIssuerShadow.Dependencies", "federation.resolveIssuerShadow.Dependencies",
			"federation.selfIssuerShadow.Dependencies", "federation.subordinateIssuerShadow.Dependencies",
			"federation.trustMarkIssuerShadow.Dependencies",
		},
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
	"ephemeral.NewKeyManager ES256 and PS256": {covers: []string{"ephemeral.signingKey.signer", "ephemeral.KeyManager.keys"},
		build: func(t *testing.T) (any, []string) {
			return ephemeralKeyManager(t, map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.JARMSigning: fapi.ES256, keys.IDTokenSigning: fapi.PS256}, nil)
		}},
	"ephemeral.NewKeyManager EdDSA": {covers: []string{"ephemeral.signingKey.signer", "ephemeral.KeyManager.keys"},
		build: func(t *testing.T) (any, []string) {
			return ephemeralKeyManager(t, map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.JARMSigning: fapi.EdDSA}, nil)
		}},
	"ephemeral.NewKeyManagerWithDecryption": {covers: []string{"ephemeral.decryptionKeys.keys", "ephemeral.KeyManager.decryption", "ephemeral.KeyManager.keys"},
		build: func(t *testing.T) (any, []string) {
			return ephemeralKeyManager(t, map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.JARMSigning: fapi.ES256},
				map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{keys.IDTokenDecryption: fapi.RSAOAEP256, keys.UserInfoDecryption: fapi.ECDHESA256KW})
		}},
	"client sealers": {covers: []string{"client.sealKey.aead", "client.sealKeyring.keys", "client.TokenSetSealer.keys", "client.BackchannelSessionSealer.keys"},
		build: func(t *testing.T) (any, []string) {
			key := randomBytes(t, 32)
			c := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity}).Client
			return struct {
				Tokens  *client.TokenSetSealer
				Session *client.BackchannelSessionSealer
			}{must(client.NewTokenSetSealer(c, [][]byte{key}))(t), must(client.NewBackchannelSessionSealer(c, [][]byte{key}))(t)}, []string{string(key)}
		}},
	"cookie jars": {covers: []string{"interactioncookie.Cookie.jar", "sessioncookie.Cookie.jar"},
		build: func(t *testing.T) (any, []string) {
			key := randomBytes(t, 32)
			return struct {
				Interaction *interactioncookie.Cookie
				Session     *sessioncookie.Cookie
			}{must(interactioncookie.New([][]byte{key}, interactioncookie.Options{}))(t), must(sessioncookie.New([][]byte{key}, sessioncookie.Options{}))(t)}, []string{string(key)}
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
// fails for a struct field holding key material that no keyHolders case
// covers and notKeyMaterial doesn't excuse, and for a table entry naming
// no such field. A field holds key material directly (see
// keyMaterialTypes and keyMaterialName; a map, slice or array of them
// too), or transitively: its type, through pointers, slices, arrays,
// maps' values, channels, generic types' arguments, inline structs and
// the named types this module declares (in the guarded packages or
// internal/), reaches a field holding it directly. A case covering a
// transitive holder renders the value that holds it, so its renderings
// check the nested key too.
func TestKeyHolderMatrixCoversEveryKeyField(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range keyHolders {
		for _, field := range tc.covers {
			covered[field] = true
		}
	}
	ix := newTypeIndex(t)
	found := map[string]bool{}
	for _, field := range ix.keyMaterialFields() {
		found[field.name] = true
		if _, excused := notKeyMaterial[field.name]; !covered[field.name] && !excused {
			t.Errorf("%s holds key material%s, and no keyHolders case covers it: add one, or say in notKeyMaterial why it isn't key material", field.name, field.via)
		}
	}
	for _, field := range append(slices.Collect(maps.Keys(covered)), slices.Collect(maps.Keys(notKeyMaterial))...) {
		if !found[field] {
			t.Errorf("the key-material tables name %s, which no guarded package declares as a key field", field)
		}
	}
}

// TestKeyMaterialIndexFollowsNestedTypes checks the guard's transitive
// detection on a package of its own: through pointers, maps, slices,
// generic arguments, inline structs and another module package's type,
// across a cycle, and not into a type holding no key material.
func TestKeyMaterialIndexFollowsNestedTypes(t *testing.T) {
	const other = modulePath + "/internal/other"
	files := map[string][]*ast.File{
		modulePath + "/guarded": {parseSource(t, `package guarded
import (
	"crypto"
	"sync/atomic"
	o "github.com/idfoundry/fapigo/internal/other"
)
type W struct{ x *X }
type X struct {
	y *Y
	k crypto.Signer
}
type Y struct{ x *X }
type Z struct{ y map[string][]Y }
type G struct{ p atomic.Pointer[X] }
type I struct{ s struct{ secretKey []byte } }
type O struct{ j *o.Jar }
type named []*X
type N struct{ n named }
type P struct {
	n    int
	self *P
	jwks []byte
}
`)},
		other: {parseSource(t, `package other
import "crypto/cipher"
type Jar struct{ keys []key }
type key struct{ aead cipher.AEAD }
`)},
	}
	var got []string
	for _, field := range indexTypes(files, []string{modulePath + "/guarded"}).keyMaterialFields() {
		got = append(got, field.name)
	}
	want := []string{"guarded.W.x", "guarded.X.y", "guarded.X.k", "guarded.Y.x", "guarded.Z.y", "guarded.G.p", "guarded.I.s", "guarded.O.j", "guarded.N.n"}
	if !slices.Equal(got, want) {
		t.Errorf("key-material fields\n got %v\nwant %v", got, want)
	}
}

// parseSource parses src, a Go file.
func parseSource(t *testing.T, src string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "src.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// modulePath is the import path of the module the guarded packages are in.
const modulePath = "github.com/idfoundry/fapigo"

// typeDecl is a named type declared in this module.
type typeDecl struct {
	// name is the type as package.Type, package being its package's name.
	name string
	// expr is the type's definition.
	expr ast.Expr
	// file resolves the names expr uses.
	file *fileScope
}

// fileScope resolves the type names a file's declarations use.
type fileScope struct {
	// path is the file's package's import path.
	path string
	// imports maps a name the file imports a package as to its path.
	imports map[string]string
}

// keyField is a field holding key material.
type keyField struct {
	// name is the field as package.Type.field.
	name string
	// via, for a transitive holder, says through which type it does.
	via string
}

// typeIndex is the named types this module declares, by import path and
// name, and which of them reach key material.
type typeIndex struct {
	decls map[string]*typeDecl
	// guarded are the guarded packages' types, the ones whose fields
	// the guard reports, in declaration order.
	guarded []string
	// reaches memoizes typeReaches's final results; visiting holds the
	// types it is inside, so a cycle ends.
	reaches  map[string]bool
	visiting map[string]bool
}

// newTypeIndex parses the guarded packages and internal/'s.
func newTypeIndex(t *testing.T) *typeIndex {
	t.Helper()
	dirs := slices.Clone(guardedPackages)
	err := filepath.WalkDir("../internal", func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && d.Name() != "testdata" {
			dirs = append(dirs, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := map[string][]*ast.File{}
	var guarded []string
	for _, dir := range dirs {
		path := importPath(t, dir)
		parsed[path] = parseDir(t, dir)
		if slices.Contains(guardedPackages, dir) {
			guarded = append(guarded, path)
		}
	}
	return indexTypes(parsed, guarded)
}

// indexTypes indexes the type declarations of files, by import path,
// reporting the fields of guarded's.
func indexTypes(files map[string][]*ast.File, guarded []string) *typeIndex {
	ix := &typeIndex{decls: map[string]*typeDecl{}, reaches: map[string]bool{}, visiting: map[string]bool{}}
	names := map[string]string{}
	for path, pkg := range files {
		if len(pkg) > 0 {
			names[path] = pkg[0].Name.Name
		}
	}
	// Sorted paths, and each package's file order, keep the guard's
	// reports in a stable order.
	for _, path := range slices.Sorted(maps.Keys(files)) {
		for _, file := range files[path] {
			ix.add(file, &fileScope{path: path, imports: fileImports(file, names)}, slices.Contains(guarded, path))
		}
	}
	return ix
}

// add indexes file's type declarations, recording them as guarded if
// guarded is set.
func (ix *typeIndex) add(file *ast.File, scope *fileScope, guarded bool) {
	for _, spec := range typeSpecs(file) {
		key := scope.path + "." + spec.Name.Name
		ix.decls[key] = &typeDecl{name: file.Name.Name + "." + spec.Name.Name, expr: spec.Type, file: scope}
		if guarded {
			ix.guarded = append(ix.guarded, key)
		}
	}
}

// importPath is dir's import path.
func importPath(t *testing.T, dir string) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		t.Fatal(err)
	}
	if rel == "." {
		return modulePath
	}
	return modulePath + "/" + filepath.ToSlash(rel)
}

// parseDir parses dir's non-test files.
func parseDir(t *testing.T, dir string) []*ast.File {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	return files
}

// fileImports maps the names file imports this module's packages as to
// their import paths; names holds each package's name.
func fileImports(file *ast.File, names map[string]string) map[string]string {
	out := map[string]string{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name, ok := names[path]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if ok || imp.Name != nil {
			out[name] = path
		}
	}
	return out
}

// keyMaterialFields is the fields of the guarded packages' struct types
// holding key material, directly or transitively.
func (ix *typeIndex) keyMaterialFields() []keyField {
	var out []keyField
	for _, key := range ix.guarded {
		decl := ix.decls[key]
		st, ok := decl.expr.(*ast.StructType)
		if !ok {
			continue
		}
		for _, field := range st.Fields.List {
			out = append(out, ix.fieldKeys(decl, field)...)
		}
	}
	return out
}

// fieldKeys is field of decl's struct, once per name, if it holds key
// material.
func (ix *typeIndex) fieldKeys(decl *typeDecl, field *ast.Field) []keyField {
	names := fieldNames(field)
	var out []keyField
	for _, name := range names {
		if holdsKeyMaterial(typeString(field.Type), name) {
			out = append(out, keyField{name: decl.name + "." + name})
		} else if ix.exprReaches(decl.file, field.Type) {
			out = append(out, keyField{name: decl.name + "." + name, via: " through its type, " + typeString(field.Type)})
		}
	}
	return out
}

// fieldNames is field's names, or an embedded field's type name.
func fieldNames(field *ast.Field) []string {
	if len(field.Names) == 0 {
		typ := strings.TrimPrefix(typeString(field.Type), "*")
		return []string{typ[strings.LastIndex(typ, ".")+1:]}
	}
	names := make([]string, len(field.Names))
	for i, name := range field.Names {
		names[i] = name.Name
	}
	return names
}

// exprReaches reports whether a value of type e, resolved in scope,
// holds key material in a field, at any depth.
func (ix *typeIndex) exprReaches(scope *fileScope, e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.StarExpr:
		return ix.exprReaches(scope, t.X)
	case *ast.ArrayType:
		return ix.exprReaches(scope, t.Elt)
	case *ast.MapType:
		return ix.exprReaches(scope, t.Value)
	case *ast.ChanType:
		return ix.exprReaches(scope, t.Value)
	case *ast.IndexExpr:
		return ix.exprReaches(scope, t.X) || ix.exprReaches(scope, t.Index)
	case *ast.IndexListExpr:
		return ix.exprReaches(scope, t.X) || slices.ContainsFunc(t.Indices, func(e ast.Expr) bool { return ix.exprReaches(scope, e) })
	case *ast.StructType:
		return ix.structReaches(scope, t)
	case *ast.Ident:
		return ix.typeReaches(scope.path + "." + t.Name)
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && scope.imports[pkg.Name] != "" && ix.typeReaches(scope.imports[pkg.Name]+"."+t.Sel.Name)
	}
	return false
}

// structReaches reports whether one of st's fields holds key material,
// directly or transitively.
func (ix *typeIndex) structReaches(scope *fileScope, st *ast.StructType) bool {
	for _, field := range st.Fields.List {
		for _, name := range fieldNames(field) {
			if holdsKeyMaterial(typeString(field.Type), name) {
				return true
			}
		}
		if ix.exprReaches(scope, field.Type) {
			return true
		}
	}
	return false
}

// typeReaches reports whether the named type key, a module type's
// import path and name, holds key material: false for a type the module
// doesn't declare, or one already being resolved.
func (ix *typeIndex) typeReaches(key string) bool {
	if reaches, done := ix.reaches[key]; done {
		return reaches
	}
	decl := ix.decls[key]
	if decl == nil || ix.visiting[key] {
		return false
	}
	ix.visiting[key] = true
	reaches := ix.exprReaches(decl.file, decl.expr)
	delete(ix.visiting, key)
	// A false found inside another type's resolution may be a cycle cut
	// short, so only an outermost one is final.
	if reaches || len(ix.visiting) == 0 {
		ix.reaches[key] = reaches
	}
	return reaches
}

// holdsKeyMaterial reports whether a field of type typ named name holds
// key material directly.
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
