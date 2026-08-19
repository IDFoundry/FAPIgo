package memstore

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// ClientRepository is a read-only storage.ClientRepository built once
// from a fixed client list. It is never mutated after construction, so
// it needs no locking.
type ClientRepository struct {
	clients map[fapi.ClientID]storage.RegisteredClient
}

// NewClientRepository builds a ClientRepository from clients.
func NewClientRepository(clients []storage.RegisteredClient) *ClientRepository {
	r := &ClientRepository{clients: make(map[fapi.ClientID]storage.RegisteredClient, len(clients))}
	for _, c := range clients {
		r.clients[c.ID()] = c
	}
	return r
}

// ResolveClient implements storage.ClientRepository.
func (r *ClientRepository) ResolveClient(_ context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	client, ok := r.clients[id]
	if !ok {
		return storage.RegisteredClient{}, fmt.Errorf("memstore: unknown client %q", id)
	}
	return client, nil
}
