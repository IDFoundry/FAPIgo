package server

import (
	"context"
	"strconv"
	"time"

	fapi "github.com/idfoundry/fapigo"
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

// refuseUnusableRequestURI asks Dependencies.PushedRequestLookup, when
// it's set, whether clientID can begin an interaction for the pushed
// request referenceKey (a parReferenceKey) names, before
// claimInteractionSlot writes anything (see its doc comment). A
// request_uri that is unknown, already used, expired or presented with
// another client_id is refused with the invalid_request_uri the store
// would refuse it with, and leaves nothing behind. The answer is
// advisory: a request_uri it finds usable still has to claim a slot,
// and the store's BeginAuthorization still decides, atomically, whether
// it begins. A lookup that couldn't answer is a 500 server_error, as
// the store's would be.
func (s *Server) refuseUnusableRequestURI(ctx context.Context, clientID fapi.ClientID, referenceKey string, now time.Time) *Error {
	if s.deps.PushedRequestLookup == nil {
		return nil
	}
	pushed, err := s.deps.PushedRequestLookup.LookupPushedRequest(ctx, storage.LookupPushedRequestTransaction{Reference: referenceKey, Now: now})
	if err != nil {
		return storeFailure(ctx, err, "failed to look up the pushed authorization request", newError(ErrorInvalidRequestURI, 400, "request_uri is invalid, expired, or already used", err))
	}
	// Backstops, as for the store's own answer: a lookup keying by
	// Reference can't find another client's request, nor (keeping to its
	// contract) an expired one.
	if pushed.ClientID != clientID {
		return newError(ErrorInvalidRequestURI, 400, "client_id does not match the pushed authorization request", nil)
	}
	if !now.Before(pushed.ExpiresAt) {
		return newError(ErrorInvalidRequestURI, 400, "request_uri has expired", nil)
	}
	return nil
}

// claimInteractionSlot records, in Dependencies.Replay, one of the
// maxInteractionsPerRequestURI interactions referenceKey (a
// parReferenceKey) may begin, before BeginAuthorization asks the
// transaction store to store another. The replay store is shared by
// every instance and its UseOnce is atomic, so the bound holds across a
// fleet without changing storage.TransactionStore. A slot is kept as
// long as the pushed request can be redeemed: PushedRequestLifetime
// from now, plus twice MaxClockSkew as for every replay record.
//
// A slot is claimed before anyone has authenticated. Every other replay
// record this server writes follows an authentication, the clientless
// VerifyTokenRequestDPoP aside, but anyone who can reach the
// authorization endpoint can claim a slot for any client_id and any
// request_uri of this server's form, and it lasts as long as a real
// one: a 32-byte digest, under a key no pushed request has. So
// BeginAuthorization asks Dependencies.PushedRequestLookup first, when
// it's set (refuseUnusableRequestURI), and only a request_uri the store
// holds for the client_id presented spends a slot. Without the lookup,
// one that turns out unknown, expired or already used spends one too.
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
		if storeUnavailable(ctx, err) {
			return newError(ErrorServerError, 500, "failed to record the interaction", err)
		}
	}
	return newError(ErrorInvalidRequestURI, 400, "request_uri has begun too many interactions", nil)
}
