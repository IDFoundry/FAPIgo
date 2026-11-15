package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// NewBackchannelInboxEntry is what BackchannelInbox.AddBackchannelRequest
// keeps for one pending CIBA request.
type NewBackchannelInboxEntry struct {
	// HandleHash is the request's NewBackchannelAuthentication.HandleHash:
	// the entry's key, and what RemoveBackchannelRequest removes it by.
	HandleHash [32]byte

	// SubjectKey is what ListBackchannelRequests finds the entry by: a
	// digest the server derives from its issuer and the internal subject
	// identifier of the end user the request's hint named (base64url, at
	// most 64 bytes), never the identifier itself.
	SubjectKey string

	ClientID fapi.ClientID

	// Record is what the server needs back to show and complete the
	// request, its backchannel authentication handle among it — opaque
	// to the store, which returns it unmodified. It names a pending
	// request, so a store that can encrypt at rest should.
	Record json.RawMessage

	// ExpiresAt is the request's own expiry: the entry isn't listed from
	// then on, and may be deleted.
	ExpiresAt time.Time
}

// BackchannelInboxListing is the input to
// BackchannelInbox.ListBackchannelRequests.
type BackchannelInboxListing struct {
	// SubjectKey is NewBackchannelInboxEntry.SubjectKey, as the server
	// derives it for the subject asked about.
	SubjectKey string

	// Now is the server's current time (server.Dependencies.Clock): an
	// entry whose ExpiresAt isn't after it is not listed.
	Now time.Time
}

// BackchannelInboxEntry is one entry ListBackchannelRequests returns.
type BackchannelInboxEntry struct {
	HandleHash [32]byte
	ClientID   fapi.ClientID
	Record     json.RawMessage
	ExpiresAt  time.Time
}

// BackchannelInbox keeps, for each end user, the CIBA requests awaiting
// their decision: what server.Server.ListBackchannelInteractions shows
// on the user's authentication device, from any instance. It's
// server.Dependencies.BackchannelInbox, optional, and separate from
// BackchannelAuthenticationStore so adding it changes no existing store.
//
// AddBackchannelRequest stores entry, replacing any entry with the same
// HandleHash. ListBackchannelRequests returns every entry with
// listing.SubjectKey whose ExpiresAt is after listing.Now, in any order.
// RemoveBackchannelRequest deletes the entry with handleHash, and
// succeeds when there is none. A store that couldn't answer wraps
// ErrStoreUnavailable. Run TestBackchannelInboxContract against an
// implementation.
type BackchannelInbox interface {
	AddBackchannelRequest(ctx context.Context, entry NewBackchannelInboxEntry) error
	ListBackchannelRequests(ctx context.Context, listing BackchannelInboxListing) ([]BackchannelInboxEntry, error)
	RemoveBackchannelRequest(ctx context.Context, handleHash [32]byte) error
}
