package federation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

var testJWKS = json.RawMessage(`{"keys":[]}`)

// checkAllDependencies runs check on one of each issuer's dependencies,
// signing with signer.
func checkAllDependencies(signer crypto.Signer, check func(name string, deps any, run func(func(any)))) {
	h := HistoricalKeysIssueDependencies{Signer: signer, Algorithm: fapi.ES256, KeyID: "k1", JWKS: testJWKS, Clock: SystemClock{}}
	r := ResolveIssueDependencies{Signer: signer, Algorithm: fapi.ES256, KeyID: "k1", Clock: SystemClock{}}
	s := SelfIssueDependencies{Signer: signer, Algorithm: fapi.ES256, KeyID: "k1", JWKS: testJWKS, Clock: SystemClock{}}
	sub := SubordinateIssueDependencies{Signer: signer, Algorithm: fapi.ES256, KeyID: "k1", Clock: SystemClock{}}
	tm := TrustMarkIssueDependencies{Signer: signer, Algorithm: fapi.ES256, KeyID: "k1", Clock: SystemClock{}}
	check("HistoricalKeysIssueDependencies", h, func(f func(any)) { f(h); f(&h) })
	check("ResolveIssueDependencies", r, func(f func(any)) { f(r); f(&r) })
	check("SelfIssueDependencies", s, func(f func(any)) { f(s); f(&s) })
	check("SubordinateIssueDependencies", sub, func(f func(any)) { f(sub); f(&sub) })
	check("TrustMarkIssueDependencies", tm, func(f func(any)) { f(tm); f(&tm) })
}

// TestIssueDependenciesPrintNoKey: each issuer's dependencies print
// [REDACTED] for their Signer, whatever prints them through their own
// methods, and the encoders refuse them. fmt's reflection fallback sees
// Signer as the exported field it is, so it's allowed for an
// ed25519.PrivateKey, a byte slice it prints whole; an
// *ecdsa.PrivateKey sits behind a pointer it prints as an address.
func TestIssueDependenciesPrintNoKey(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSecrets := []string{string(ec.D.FillBytes(make([]byte, 32))), ec.D.String()}
	rendertest.Check(t, HistoricalKeysIssueDependencies{Signer: ec, Algorithm: fapi.ES256, JWKS: testJWKS}, ecSecrets)
	rendertest.Check(t, ResolveIssueDependencies{Signer: ec, Algorithm: fapi.ES256}, ecSecrets)
	rendertest.Check(t, SelfIssueDependencies{Signer: ec, Algorithm: fapi.ES256, JWKS: testJWKS}, ecSecrets)
	rendertest.Check(t, SubordinateIssueDependencies{Signer: ec, Algorithm: fapi.ES256}, ecSecrets)
	rendertest.Check(t, TrustMarkIssueDependencies{Signer: ec, Algorithm: fapi.ES256}, ecSecrets)

	edSecrets, fallback := []string{string(ed.Seed())}, rendertest.Allow(rendertest.Fallback)
	quick := rendertest.Quick()
	rendertest.Check(t, HistoricalKeysIssueDependencies{Signer: ed, Algorithm: fapi.EdDSA, JWKS: testJWKS}, edSecrets, fallback, quick)
	rendertest.Check(t, ResolveIssueDependencies{Signer: ed, Algorithm: fapi.EdDSA}, edSecrets, fallback, quick)
	rendertest.Check(t, SelfIssueDependencies{Signer: ed, Algorithm: fapi.EdDSA, JWKS: testJWKS}, edSecrets, fallback, quick)
	rendertest.Check(t, SubordinateIssueDependencies{Signer: ed, Algorithm: fapi.EdDSA}, edSecrets, fallback, quick)
	rendertest.Check(t, TrustMarkIssueDependencies{Signer: ed, Algorithm: fapi.EdDSA}, edSecrets, fallback, quick)
}

// TestIssueDependenciesPrintTheirFields: under %+v and %#v each
// issuer's dependencies print every field but Signer as fmt would, and
// a dependencies value without a Signer prints no placeholder.
func TestIssueDependenciesPrintTheirFields(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkAllDependencies(ec, func(name string, deps any, _ func(func(any))) {
		want := "{Signer:[REDACTED] Algorithm:ES256 KeyID:k1 Clock:{}}"
		if strings.HasPrefix(name, "Historical") || strings.HasPrefix(name, "Self") {
			want = "{Signer:[REDACTED] Algorithm:ES256 KeyID:k1 JWKS:" + fmt.Sprintf("%+v", []byte(testJWKS)) + " Clock:{}}"
		}
		if got := fmt.Sprintf("%+v", deps); got != want {
			t.Errorf("%s: %%+v = %q, want %q", name, got, want)
		}
		if got := fmt.Sprintf("%#v", deps); !strings.HasPrefix(got, "federation."+name+"{") || strings.Contains(got, "Shadow") {
			t.Errorf("%s: %%#v = %q, want the real type's name", name, got)
		}
	})
	checkAllDependencies(nil, func(name string, deps any, _ func(func(any))) {
		if got := fmt.Sprint(deps); strings.Contains(got, "REDACTED") {
			t.Errorf("%s without a Signer prints %q, want no placeholder", name, got)
		}
	})
}

// TestIssueDependenciesLogNoKey: log/slog's JSON handler logs each
// issuer's dependencies' fields, with [REDACTED] for Signer.
func TestIssueDependenciesLogNoKey(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkAllDependencies(ec, func(name string, deps any, _ func(func(any))) {
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("deps", "v", deps)
		want := `"v":{"Signer":"[REDACTED]","Algorithm":"ES256","KeyID":"k1","Clock":{}}`
		if strings.HasPrefix(name, "Historical") || strings.HasPrefix(name, "Self") {
			want = `"v":{"Signer":"[REDACTED]","Algorithm":"ES256","KeyID":"k1","JWKS":{"keys":[]},"Clock":{}}`
		}
		if got := buf.String(); !strings.Contains(got, want) {
			t.Errorf("%s: slog JSON logged %s, want it to hold %s", name, got, want)
		}
	})
}

// TestIssueDependenciesShadowsMatch keeps each issuer's dependencies'
// shadow in step with it.
func TestIssueDependenciesShadowsMatch(t *testing.T) {
	plain, withJWKS := reflect.TypeFor[issueDependenciesShadow](), reflect.TypeFor[jwksIssueDependenciesShadow]()
	rendertest.CheckShadow(t, reflect.TypeFor[HistoricalKeysIssueDependencies](), withJWKS)
	rendertest.CheckShadow(t, reflect.TypeFor[ResolveIssueDependencies](), plain)
	rendertest.CheckShadow(t, reflect.TypeFor[SelfIssueDependencies](), withJWKS)
	rendertest.CheckShadow(t, reflect.TypeFor[SubordinateIssueDependencies](), plain)
	rendertest.CheckShadow(t, reflect.TypeFor[TrustMarkIssueDependencies](), plain)
}

// xmlHolder holds dependencies in a field, as a configuration struct
// encoding/xml can name would.
type xmlHolder struct{ Deps any }

// TestIssueDependenciesRefuseEncoding: encoding/json and encoding/xml,
// given each issuer's dependencies as a value, a pointer, or a field of
// a struct, and the dependencies' own MarshalText and MarshalJSON, all
// fail with ErrIssueDependenciesSerialization rather than writing the
// Signer.
func TestIssueDependenciesRefuseEncoding(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkAllDependencies(ec, func(name string, deps any, run func(func(any))) {
		run(func(v any) { checkEncodersRefuse(t, name, v) })
		m := deps.(interface {
			MarshalText() ([]byte, error)
			MarshalJSON() ([]byte, error)
		})
		if out, err := m.MarshalText(); !errors.Is(err, ErrIssueDependenciesSerialization) || out != nil {
			t.Errorf("%s.MarshalText = %q, %v; want ErrIssueDependenciesSerialization", name, out, err)
		}
		if out, err := m.MarshalJSON(); !errors.Is(err, ErrIssueDependenciesSerialization) || out != nil {
			t.Errorf("%s.MarshalJSON = %q, %v; want ErrIssueDependenciesSerialization", name, out, err)
		}
	})
}

// checkEncodersRefuse fails t unless encoding/json refuses v, name's
// dependencies, alone, in a struct and in a slice, and encoding/xml
// refuses it alone and in a struct.
func checkEncodersRefuse(t *testing.T, name string, v any) {
	t.Helper()
	for _, shape := range []any{v, struct{ Deps any }{v}, []any{v}} {
		if out, err := json.Marshal(shape); !errors.Is(err, ErrIssueDependenciesSerialization) {
			t.Errorf("json.Marshal(%T holding %s) = %s, %v; want ErrIssueDependenciesSerialization", shape, name, out, err)
		}
	}
	for _, shape := range []any{v, xmlHolder{Deps: v}} {
		if out, err := xml.Marshal(shape); !errors.Is(err, ErrIssueDependenciesSerialization) {
			t.Errorf("xml.Marshal(%T holding %s) = %s, %v; want ErrIssueDependenciesSerialization", shape, name, out, err)
		}
	}
}
