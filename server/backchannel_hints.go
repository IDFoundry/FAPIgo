package server

import (
	"context"
	"errors"

	fapi "github.com/idfoundry/fapigo"
)

// BackchannelHintChecker decides whether a CIBA backchannel
// authentication request's hint identifies an end user this server can
// authenticate out of band — see Dependencies.BackchannelHints.
type BackchannelHintChecker interface {
	// CheckBackchannelHints is called for a request that has passed
	// every other check (client authentication, the signed request, its
	// parameters) and before it is stored, with the hints it carries.
	// Exactly one of hints' fields is set. It returns nil to accept the
	// request, an error wrapping ErrUnknownUserID or
	// ErrExpiredLoginHintToken to refuse it with that CIBA §13 error,
	// or any other error for a failure to decide (refused with
	// server_error).
	//
	// Accepting a hint doesn't authenticate anyone: the end user still
	// has to approve on their own device, and only that decision
	// (CompleteBackchannelAuthentication) establishes who they are.
	CheckBackchannelHints(ctx context.Context, clientID fapi.ClientID, hints BackchannelAuthenticationHints) error
}

// Errors a BackchannelHintChecker returns to refuse a request with the
// corresponding CIBA §13 error.
var (
	ErrUnknownUserID         = errors.New("server: the hint identifies no known end user")
	ErrExpiredLoginHintToken = errors.New("server: the login_hint_token has expired")
)

// checkBackchannelHints applies Dependencies.BackchannelHints, when set.
// The public descriptions are fixed: the checker's own error text stays
// out of the response.
func (s *Server) checkBackchannelHints(ctx context.Context, clientID fapi.ClientID, hints BackchannelAuthenticationHints) *Error {
	if s.deps.BackchannelHints == nil {
		return nil
	}
	err := s.deps.BackchannelHints.CheckBackchannelHints(ctx, clientID, hints)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrUnknownUserID):
		return newError(ErrorUnknownUserID, 400, "the hint does not identify an end user this server can authenticate", err)
	case errors.Is(err, ErrExpiredLoginHintToken):
		return newError(ErrorExpiredLoginHintToken, 400, "the login_hint_token has expired", err)
	default:
		return newError(ErrorServerError, 500, "the hint could not be checked", err)
	}
}
