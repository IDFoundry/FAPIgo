package dpopnonce

import (
	"errors"

	"github.com/idfoundry/fapigo/storage"
)

// ErrDeclined is what a NoDPoPNonces decline (server's or resource's)
// returns from its storage.NonceStore methods: it stores no nonces, and
// its constructor treats it as a nil store, so they're only reached when
// it's passed somewhere else.
var ErrDeclined = errors.New("NoDPoPNonces declines DPoP nonces and stores none")

// Declined reports whether nonces is the decline type D, by value or
// pointer.
func Declined[D any](nonces storage.NonceStore) bool {
	switch any(nonces).(type) {
	case D, *D:
		return true
	}
	return false
}

// Active returns the store DPoP nonces are issued from and checked
// against: nonces, or nil when it's nil or the decline type D.
func Active[D any](nonces storage.NonceStore) storage.NonceStore {
	if Declined[D](nonces) {
		return nil
	}
	return nonces
}
