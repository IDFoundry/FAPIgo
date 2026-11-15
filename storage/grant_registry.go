package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// NewGrantEntry is what GrantRegistry.RecordGrant keeps for one grant
// the server issued a refresh token for.
type NewGrantEntry struct {
	// Key identifies the entry: a digest the server derives from the
	// grant's refresh token (base64url, at most 64 bytes), never the
	// token or the hash it's stored under in the GrantStore. Unique per
	// grant.
	Key string

	// SubjectKey is what ListGrants finds the entry by: a digest the
	// server derives from its issuer and the end user's internal subject
	// identifier (base64url, at most 64 bytes), never the identifier
	// itself.
	SubjectKey string

	ClientID fapi.ClientID

	// Record is the grant as the server needs it back — opaque to the
	// store, which returns it unmodified.
	Record json.RawMessage

	// ExpiresAt is when the grant's refresh token expires: the entry
	// isn't listed from then on, and may be deleted.
	ExpiresAt time.Time
}

// GrantListing is the input to GrantRegistry.ListGrants.
type GrantListing struct {
	// SubjectKey is NewGrantEntry.SubjectKey, as the server derives it
	// for the subject asked about.
	SubjectKey string

	// Now is the server's current time (server.Dependencies.Clock): an
	// entry whose ExpiresAt isn't after it is not listed.
	Now time.Time
}

// GrantEntry is one entry ListGrants returns.
type GrantEntry struct {
	Key       string
	ClientID  fapi.ClientID
	Record    json.RawMessage
	ExpiresAt time.Time
}

// GrantRegistry keeps a record of each grant the server issued a
// refresh token for, by the end user who granted it: what
// server.Server.ListGrants shows on a "connected apps" page, and what
// RevokeListedGrant revokes. It's server.Dependencies.GrantRegistry,
// optional, and separate from GrantStore so adding it changes no
// existing store.
//
// A grant with no refresh token isn't recorded: its access token, the
// only thing issued from it, expires within Limits.AccessTokenLifetime.
//
// RecordGrant stores entry, replacing any entry with the same Key.
// ListGrants returns every entry with listing.SubjectKey whose ExpiresAt
// is after listing.Now, in any order. DeleteGrant deletes the entry with
// key, and succeeds when there is none. A store that couldn't answer
// wraps ErrStoreUnavailable. Run TestGrantRegistryContract against an
// implementation.
type GrantRegistry interface {
	RecordGrant(ctx context.Context, entry NewGrantEntry) error
	ListGrants(ctx context.Context, listing GrantListing) ([]GrantEntry, error)
	DeleteGrant(ctx context.Context, key string) error
}
