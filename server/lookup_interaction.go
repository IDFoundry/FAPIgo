package server

import (
	"context"

	"github.com/idfoundry/fapigo/storage"
)

// LookupInteraction returns the InteractionRequest of the in-progress
// interaction handle identifies, rebuilt from what BeginAuthorization
// stored, as BeginAuthorization returned it: what a login or consent
// page needs to show, on any instance sharing this server's storage. It
// lets the login UI carry only the handle (see
// interactioncookie.Options.Lookup) rather than the request with it, so
// none of the request's personal data, such as its login hint or
// authorization details, is kept in the browser.
//
// It consumes nothing: CompleteAuthorization still completes handle
// once. And it changes nothing about the handle itself, which is still
// a bearer value for the interaction: bind it to the browser that began
// it, as InteractionHandle's doc comment asks.
//
// It needs Dependencies.InteractionLookup; without it, every call is an
// ErrorServerError *Error. A handle that is unknown, completed (or whose
// request_uri another interaction completed) or expired is an
// ErrorInvalidRequest *Error, as CompleteAuthorization reports it; a
// client no longer registered is ErrorUnauthorizedClient, as
// BeginAuthorization reports it. A store or client repository that
// couldn't answer is ErrorServerError.
func (s *Server) LookupInteraction(ctx context.Context, handle InteractionHandle) (InteractionRequest, error) {
	if s.deps.InteractionLookup == nil {
		return InteractionRequest{}, newError(ErrorServerError, 500, "interaction lookup is not configured: set Dependencies.InteractionLookup", nil)
	}
	now := s.deps.Clock.Now()
	pending, err := s.deps.InteractionLookup.LookupAuthorization(ctx, storage.LookupAuthorizationTransaction{
		Handle: interactionHandleKey(handle.String()),
		Now:    now,
	})
	if err != nil {
		if storeUnavailable(ctx, err) {
			return InteractionRequest{}, newError(ErrorServerError, 500, "failed to look up the interaction", err)
		}
		return InteractionRequest{}, newError(ErrorInvalidRequest, 400, "interaction handle is invalid, expired, or already used", err)
	}
	// Backstop: a store keeping to its contract returns no expired
	// interaction.
	if !now.Before(pending.ExpiresAt) {
		return InteractionRequest{}, newError(ErrorInvalidRequest, 400, "interaction handle has expired", nil)
	}
	request, err := s.decodeOwnRequestRecord(pending.Request)
	if err != nil {
		return InteractionRequest{}, recordFailure(err, newError(ErrorInvalidRequest, 400, "interaction handle is invalid, expired, or already used", nil), "pushed authorization request")
	}
	// Resolved again, as BeginAuthorization does: for its current
	// display details, and so a client that has stopped resolving isn't
	// shown as one to consent to.
	client, err := s.deps.Clients.ResolveClient(ctx, pending.ClientID)
	if err != nil {
		if storeUnavailable(ctx, err) {
			return InteractionRequest{}, newError(ErrorServerError, 500, "failed to look up the client", err)
		}
		return InteractionRequest{}, newError(ErrorUnauthorizedClient, 400, "client is no longer registered", err)
	}
	interaction, err := s.authorizationInteraction(client, request)
	if err != nil {
		return InteractionRequest{}, newError(ErrorServerError, 500, "stored extension parameters no longer validate", err)
	}
	return interaction, nil
}
