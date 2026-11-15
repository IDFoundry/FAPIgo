package memstore

import (
	"context"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// GrantRegistry is an in-memory storage.GrantRegistry. See the package
// doc comment for why this is development/testing only.
type GrantRegistry struct {
	mu      sync.Mutex
	entries map[string]storage.NewGrantEntry
}

// NewGrantRegistry builds an empty GrantRegistry.
func NewGrantRegistry() *GrantRegistry {
	return &GrantRegistry{entries: make(map[string]storage.NewGrantEntry)}
}

// RecordGrant implements storage.GrantRegistry.
func (r *GrantRegistry) RecordGrant(_ context.Context, entry storage.NewGrantEntry) error {
	entry.Record = cloneRawMessage(entry.Record)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[entry.Key] = entry
	return nil
}

// ListGrants implements storage.GrantRegistry.
func (r *GrantRegistry) ListGrants(_ context.Context, listing storage.GrantListing) ([]storage.GrantEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []storage.GrantEntry
	for _, e := range r.entries {
		if e.SubjectKey != listing.SubjectKey || !listing.Now.Before(e.ExpiresAt) {
			continue
		}
		out = append(out, storage.GrantEntry{Key: e.Key, ClientID: e.ClientID, Record: cloneRawMessage(e.Record), ExpiresAt: e.ExpiresAt})
	}
	return out, nil
}

// DeleteGrant implements storage.GrantRegistry.
func (r *GrantRegistry) DeleteGrant(_ context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
	return nil
}
