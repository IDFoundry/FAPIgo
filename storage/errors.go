package storage

import "errors"

// ErrStoreUnavailable is the error a store wraps (fmt.Errorf("...: %w",
// storage.ErrStoreUnavailable)) when it couldn't answer at all — its
// backend unreachable, a timeout — as opposed to answering "unknown" or
// "already used". A caller tells the two apart with errors.Is: the
// authorization server and a resource server answer an unavailable
// store with 500 server_error instead of telling the client its
// credentials, code, refresh token or DPoP proof is invalid.
//
// Wrapping it is optional. An error that doesn't wrap it (or
// context.Canceled or context.DeadlineExceeded) keeps meaning what the
// method's own contract says, so a store that never wraps it behaves
// as before.
var ErrStoreUnavailable = errors.New("storage: store unavailable")
