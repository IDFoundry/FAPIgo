package server

import (
	"context"
	"errors"

	"github.com/idfoundry/fapigo/storage"
)

// clientStoreUnavailable reports whether a ClientRepository.ResolveClient
// failure means the store couldn't answer, rather than that the client
// is unknown: an error wrapping storage.ErrStoreUnavailable, or this
// request's own context ending first. Either is answered with 500
// server_error, never invalid_client: the client did nothing wrong, and
// a 401 would tell it its credentials are. The request's context is
// checked rather than the error, so a federation resolution that times
// out fetching an unreachable entity stays an unknown client.
func clientStoreUnavailable(ctx context.Context, err error) bool {
	return errors.Is(err, storage.ErrStoreUnavailable) || ctx.Err() != nil
}

// unresolvedClientError is the error for a ResolveClient failure at a
// client-authenticating endpoint: 500 server_error when the store
// couldn't answer (clientStoreUnavailable), otherwise 401 invalid_client.
func unresolvedClientError(ctx context.Context, err error) *Error {
	if clientStoreUnavailable(ctx, err) {
		return newError(ErrorServerError, 500, "failed to look up the client", err)
	}
	return newError(ErrorInvalidClient, 401, "unknown client", err)
}
