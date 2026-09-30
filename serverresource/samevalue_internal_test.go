package serverresource

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

// valueNonceStore is a comparable type that can hold an uncomparable
// value, where == panics.
type valueNonceStore struct{ inner any }

func (valueNonceStore) Issue(context.Context, storage.NonceIssuance) error { return nil }
func (valueNonceStore) Consume(context.Context, storage.NonceConsumption) (storage.NonceRecord, error) {
	return storage.NonceRecord{}, nil
}

func TestSameValue(t *testing.T) {
	uncomparable := valueNonceStore{inner: map[string]int{}}
	if sameValue(uncomparable, valueNonceStore{inner: map[string]int{}}) {
		t.Error("sameValue(uncomparable values) = true, want false")
	}
	comparable := valueNonceStore{inner: "x"}
	if !sameValue(comparable, comparable) {
		t.Error("sameValue(v, v) = false, want true")
	}
	if sameValue(comparable, nil) || sameValue(comparable, valueNonceStore{inner: "y"}) {
		t.Error("sameValue(different values) = true, want false")
	}
}
