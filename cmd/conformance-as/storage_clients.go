package main

import (
	"context"
	"fmt"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/storage"
)

// staticClientRepository is a read-only storage.ClientRepository built
// once at startup from configuration. It is never mutated after
// construction, so it needs no locking.
type staticClientRepository struct {
	clients map[fapi.ClientID]storage.RegisteredClient
}

func newStaticClientRepository(specs []ClientKeySpec) *staticClientRepository {
	r := &staticClientRepository{clients: make(map[fapi.ClientID]storage.RegisteredClient, len(specs))}
	for _, spec := range specs {
		r.clients[spec.Registered.ID()] = spec.Registered
	}
	return r
}

// ResolveClient implements storage.ClientRepository.
func (r *staticClientRepository) ResolveClient(_ context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	client, ok := r.clients[id]
	if !ok {
		return storage.RegisteredClient{}, fmt.Errorf("conformance-as: unknown client %q", id)
	}
	return client, nil
}
