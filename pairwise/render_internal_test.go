package pairwise

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/idfoundry/fapigo/internal/rendertest"
	"github.com/idfoundry/fapigo/keys"
)

// renderKey returns a key of n bytes for the rendering tests: distinct
// bytes, so none passes for another's encoding.
func renderKey(n int, offset byte) []byte {
	key := make([]byte, n)
	for i := range key {
		key[i] = offset + byte(i)*7
	}
	return key
}

// TestDeriversPrintNoKey: a Deriver over an in-memory key prints its
// custody and [REDACTED] for its key operations, whatever prints it.
func TestDeriversPrintNoKey(t *testing.T) {
	hmacKey := renderKey(32, 3)
	h, err := NewHMAC(hmacKey, keys.DeclareCustody(keys.KeyCustody{Durable: true}))
	if err != nil {
		t.Fatal(err)
	}
	rendertest.Check(t, h, []string{string(hmacKey)})
	rendertest.Check(t, *h, []string{string(hmacKey)})

	macKey, encKey := renderKey(32, 5), renderKey(32, 101)
	r, err := newReversible(macKey, encKey, keys.DeclareCustody(keys.KeyCustody{Durable: true}))
	if err != nil {
		t.Fatal(err)
	}
	rendertest.Check(t, r, []string{string(macKey), string(encKey)})
	rendertest.Check(t, *r, []string{string(macKey), string(encKey)})

	if got, want := fmt.Sprintf("%+v", h), "{ops:[REDACTED] custody:{Durable:true CrossInstanceConsistent:false}}"; got != want {
		t.Errorf("%%+v = %q, want %q", got, want)
	}
	if got, want := fmt.Sprintf("%#v", *h), `pairwise.HMACDeriver{ops:"[REDACTED]", custody:keys.KeyCustody{Durable:true, CrossInstanceConsistent:false}}`; got != want {
		t.Errorf("%%#v = %q, want %q", got, want)
	}
}

// TestDeriverShadowsMatch keeps each deriver's shadow in step with it.
func TestDeriverShadowsMatch(t *testing.T) {
	rendertest.CheckShadow(t, reflect.TypeFor[HMACDeriver](), reflect.TypeFor[hmacDeriverShadow]())
	rendertest.CheckShadow(t, reflect.TypeFor[ReversibleDeriver](), reflect.TypeFor[reversibleDeriverShadow]())
}
