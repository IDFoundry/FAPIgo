package dpopnonce

import (
	"testing"

	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

type decline struct{ storage.NonceStore }

func TestDeclinedAndActive(t *testing.T) {
	store := memstore.NewNonceStore()
	for name, tc := range map[string]struct {
		nonces       storage.NonceStore
		wantDeclined bool
		wantActive   storage.NonceStore
	}{
		"nil":     {nil, false, nil},
		"store":   {store, false, store},
		"value":   {decline{}, true, nil},
		"pointer": {&decline{}, true, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if got := Declined[decline](tc.nonces); got != tc.wantDeclined {
				t.Errorf("Declined = %v, want %v", got, tc.wantDeclined)
			}
			if got := Active[decline](tc.nonces); got != tc.wantActive {
				t.Errorf("Active = %v, want %v", got, tc.wantActive)
			}
		})
	}
}
