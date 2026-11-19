package server

import (
	"context"
	"errors"

	"github.com/idfoundry/fapigo/storage"
)

// storeUnavailable reports whether a ClientRepository.ResolveClient, or
// another store call, failed because the store couldn't answer rather
// than because what was asked for is unknown: an error wrapping
// storage.ErrStoreUnavailable, or this request's own context ending
// first. The request's context is checked rather than the error, so a
// federation resolution that times out fetching an unreachable entity
// stays an unknown client.
func storeUnavailable(ctx context.Context, err error) bool {
	return errors.Is(err, storage.ErrStoreUnavailable) || ctx.Err() != nil
}

// storeOutage reports whether a store call (other than ResolveClient,
// which storeUnavailable covers) failed because the store couldn't
// answer: storeUnavailable says so, or the error wraps context.Canceled
// or context.DeadlineExceeded, as a resource server also counts it. No
// store's timeout means unknown.
func storeOutage(ctx context.Context, err error) bool {
	return storeUnavailable(ctx, err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// storeFailure is the error for a failed store call, or a failed check
// that called one (a replay check): a 500 server_error described by
// what when the store couldn't answer (storeOutage), otherwise refused,
// the endpoint's own answer for what the store doesn't know, has used
// up or refuses. The client did nothing wrong, and acts on a client
// error: a refresh token answered invalid_grant is discarded (RFC 6749
// §5.2), and a revocation answered 200 is taken as done (RFC 7009
// §2.2).
func storeFailure(ctx context.Context, err error, what string, refused *Error) *Error {
	if storeOutage(ctx, err) {
		return newError(ErrorServerError, 500, what, err)
	}
	return refused
}

// unresolvedClientError is the error for a ResolveClient failure at a
// client-authenticating endpoint: 500 server_error when the store
// couldn't answer (storeUnavailable), otherwise 401 invalid_client.
func unresolvedClientError(ctx context.Context, err error) *Error {
	if storeUnavailable(ctx, err) {
		return newError(ErrorServerError, 500, "failed to look up the client", err)
	}
	return newError(ErrorInvalidClient, 401, "unknown client", err)
}
