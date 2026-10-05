package fapitest

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// memClientRepository is an in-memory storage.ClientRepository holding
// exactly the one client the harness registers.
type memClientRepository struct {
	client storage.RegisteredClient
}

func (r *memClientRepository) ResolveClient(_ context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	if id != r.client.ID() {
		return storage.RegisteredClient{}, fmt.Errorf("fapitest: unknown client %q", id)
	}
	return r.client, nil
}
