package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// TestDecideBackchannelReportsAnOutageWhileExplainingARefusal: when a
// decision's update decides nothing, the store asks whether the handle
// is unknown or already decided; if the database can't answer that,
// the decision fails as an outage, not as an unknown handle.
func TestDecideBackchannelReportsAnOutageWhileExplainingARefusal(t *testing.T) {
	p := newPlace(t, sqlstore.SQLite)
	p.migrated()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hook := func(query string, after bool) {
		if !after && strings.Contains(query, "SELECT COUNT(*)") && strings.Contains(query, "backchannel_authentications") {
			cancel()
		}
	}
	b := p.handle(hookedDB(t, p, "", hook)).Backchannel()
	decision := storage.DecideBackchannelAuthentication{HandleHash: sha256.Sum256([]byte("handle-never-stored")), Status: storage.BackchannelAuthenticationDenied}
	_, err := b.DecideBackchannelAuthentication(ctx, decision)
	if !errors.Is(err, storage.ErrStoreUnavailable) || errors.Is(err, storage.ErrBackchannelAuthenticationNotFound) {
		t.Fatalf("DecideBackchannelAuthentication with the follow-up query failing = %v, want ErrStoreUnavailable, not not-found", err)
	}
}
