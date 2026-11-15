package memstore

import (
	"context"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// BackchannelInbox is an in-memory storage.BackchannelInbox. See the
// package doc comment for why this is development/testing only.
type BackchannelInbox struct {
	mu      sync.Mutex
	entries map[[32]byte]storage.NewBackchannelInboxEntry
}

// NewBackchannelInbox builds an empty BackchannelInbox.
func NewBackchannelInbox() *BackchannelInbox {
	return &BackchannelInbox{entries: make(map[[32]byte]storage.NewBackchannelInboxEntry)}
}

// AddBackchannelRequest implements storage.BackchannelInbox.
func (b *BackchannelInbox) AddBackchannelRequest(_ context.Context, entry storage.NewBackchannelInboxEntry) error {
	entry.Record = cloneRawMessage(entry.Record)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[entry.HandleHash] = entry
	return nil
}

// ListBackchannelRequests implements storage.BackchannelInbox.
func (b *BackchannelInbox) ListBackchannelRequests(_ context.Context, listing storage.BackchannelInboxListing) ([]storage.BackchannelInboxEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []storage.BackchannelInboxEntry
	for _, e := range b.entries {
		if e.SubjectKey != listing.SubjectKey || !listing.Now.Before(e.ExpiresAt) {
			continue
		}
		out = append(out, storage.BackchannelInboxEntry{HandleHash: e.HandleHash, ClientID: e.ClientID, Record: cloneRawMessage(e.Record), ExpiresAt: e.ExpiresAt})
	}
	return out, nil
}

// RemoveBackchannelRequest implements storage.BackchannelInbox.
func (b *BackchannelInbox) RemoveBackchannelRequest(_ context.Context, handleHash [32]byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, handleHash)
	return nil
}
