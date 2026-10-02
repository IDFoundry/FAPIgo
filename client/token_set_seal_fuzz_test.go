package client_test

import (
	"reflect"
	"testing"
)

// FuzzOpenTokenSet covers OpenTokenSet on arbitrary stored bytes: it
// never panics, and anything it opens is the one set sealed under this
// key. (Each fuzz worker seals afresh, with its own nonce, so the bytes
// themselves can't be compared.)
func FuzzOpenTokenSet(f *testing.F) {
	c := sealingClient(&testing.T{}, testClientID)
	sealed, err := c.SealTokenSet(fullTokenSet(), sealKey(1))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte{1, 0, 0, 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		opened, err := c.OpenTokenSet(b, sealKey(1))
		if err == nil && !reflect.DeepEqual(revealed(opened), revealed(fullTokenSet())) {
			t.Fatalf("OpenTokenSet opened a set nobody sealed: %v", revealed(opened))
		}
	})
}
