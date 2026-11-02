package server

import (
	"context"
	"strconv"
	"time"

	"github.com/idfoundry/fapigo/internal/replaykey"
	"github.com/idfoundry/fapigo/storage"
)

// maxInteractionsPerRequestURI is how many interactions BeginAuthorization
// begins for one request_uri. Each one stores its own copy of the
// pushed request (storage.TransactionStore.BeginAuthorization) for
// Limits.InteractionLifetime, so without a bound one pushed request
// could be copied into the store once per GET of the authorization
// endpoint for as long as its request_uri lives. A browser loading,
// prefetching and reloading the page needs a handful.
const maxInteractionsPerRequestURI = 8

// interactionSlotReplayNamespace holds the slots claimInteractionSlot
// records, apart from every replayed jti.
const interactionSlotReplayNamespace storage.ReplayNamespace = "server:authorization-interaction"

// claimInteractionSlot records, in Dependencies.Replay, one of the
// maxInteractionsPerRequestURI interactions referenceKey (a
// parReferenceKey) may begin, before BeginAuthorization asks the
// transaction store to store another. The replay store is shared by
// every instance and its UseOnce is atomic, so the bound holds across a
// fleet without changing storage.TransactionStore. A slot is kept as
// long as the pushed request can be redeemed: PushedRequestLifetime
// from now, plus twice MaxClockSkew as for every replay record.
//
// A request_uri that turns out unknown or expired still spends a slot
// here (only a 32-byte digest, under a key no pushed request has);
// that costs no more than the replay records any request with a jti
// leaves.
func (s *Server) claimInteractionSlot(ctx context.Context, referenceKey string, now time.Time) *Error {
	expiresAt := now.Add(s.cfg.Limits.PushedRequestLifetime + 2*s.cfg.Limits.MaxClockSkew)
	for slot := range maxInteractionsPerRequestURI {
		err := s.deps.Replay.UseOnce(ctx, storage.ReplayUse{
			Namespace: interactionSlotReplayNamespace,
			Digest:    replaykey.Digest(referenceKey, strconv.Itoa(slot)),
			ExpiresAt: expiresAt,
		})
		if err == nil {
			return nil
		}
		if clientStoreUnavailable(ctx, err) {
			return newError(ErrorServerError, 500, "failed to record the interaction", err)
		}
	}
	return newError(ErrorInvalidRequestURI, 400, "request_uri has begun too many interactions", nil)
}
