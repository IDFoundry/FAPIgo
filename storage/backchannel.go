package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// BackchannelAuthenticationStatus is the closed set of states a pending
// CIBA backchannel authentication request can be in.
type BackchannelAuthenticationStatus uint8

const (
	_ BackchannelAuthenticationStatus = iota

	// BackchannelAuthenticationPending means no decision has been
	// recorded yet — the end user has not yet approved, denied, or
	// failed to authenticate out-of-band.
	BackchannelAuthenticationPending

	// BackchannelAuthenticationApproved means the end user authenticated
	// and approved the request.
	BackchannelAuthenticationApproved

	// BackchannelAuthenticationDenied means the end user (or the
	// application, on their behalf) declined to authorize the request.
	BackchannelAuthenticationDenied

	// BackchannelAuthenticationAuthenticationFailed means the end user
	// could not be authenticated at all.
	BackchannelAuthenticationAuthenticationFailed
)

// NewBackchannelAuthentication is what CreateBackchannelAuthentication
// persists for one client-initiated backchannel authentication request.
type NewBackchannelAuthentication struct {
	// AuthReqIDHash is the SHA-256 digest of the raw auth_req_id value
	// handed to the client — matching NewAuthorizationCode.CodeHash's
	// digest-only discipline, used to look this record up by the value a
	// client presents back. Required unconditionally, regardless of
	// DeliveryMode.
	AuthReqIDHash [32]byte

	// AuthReqID is the same auth_req_id value in the clear. Unlike
	// AuthReqIDHash, this is required only for DeliveryMode "ping": CIBA
	// §10.2 requires the ping notification body itself carry the literal
	// auth_req_id, so the server must be able to produce it again later
	// — the same reasoning ClientNotificationToken's own doc comment
	// gives for why that field can't be digest-only either. Leave "" for
	// DeliveryMode "poll", where nothing ever needs it back.
	AuthReqID string

	// HandleHash is the SHA-256 digest of the raw, embedder-facing
	// handle value — a distinct identifier from AuthReqIDHash, never
	// handed to the OAuth client, the same separation
	// InteractionHandle keeps from the PAR reference.
	HandleHash [32]byte

	ClientID fapi.ClientID

	// Parameters are the backchannel authentication request's own
	// parameters (scope, login_hint/login_hint_token/id_token_hint,
	// acr_values, binding_message) — mirrors NewPARRecord.Parameters.
	Parameters map[string]json.RawMessage

	// TokenClaims mirrors NewPARRecord.TokenClaims.
	TokenClaims map[string]json.RawMessage

	// RequestedIDTokenClaims and RequestedUserinfoClaims mirror
	// NewAuthorizationCode's fields of the same name — the claim names
	// this request's own "claims" parameter (OIDC Core §5.5) asked for,
	// split by delivery location.
	RequestedIDTokenClaims  []string
	RequestedUserinfoClaims []string

	// DeliveryMode is "poll" or "ping" (CIBA §7.1's "backchannel_token_delivery_mode",
	// restricted to these two values — FAPI-CIBA prohibits "push").
	DeliveryMode string

	// ClientNotificationToken is the raw bearer value this server must
	// later present to the client's own notification endpoint in ping
	// mode — "" for poll mode. Unlike every other secret this package
	// stores, this cannot be digest-only: the server is the party that
	// later presents it, not merely compares against it.
	ClientNotificationToken fapi.Secret

	// DPoPJKT is the "dpop_jkt" request parameter, if the client sent
	// one at BC-Auth time — "" if it didn't (see NewAuthorizationCode.DPoPJKT
	// for the equivalent PAR-side field).
	DPoPJKT string

	// PollInterval is the minimum time that must elapse between two
	// polls of this same request before PollBackchannelAuthentication
	// returns *BackchannelAuthenticationSlowDownError.
	PollInterval time.Duration

	ExpiresAt time.Time
}

// LookedUpBackchannelAuthentication is what
// BackchannelAuthenticationStore.LookupBackchannelAuthentication returns
// for a pending request, without consuming or deciding it.
type LookedUpBackchannelAuthentication struct {
	ClientID fapi.ClientID

	// Parameters mirrors NewBackchannelAuthentication.Parameters — the
	// original request's own parameters, unmodified, so a caller can
	// validate a decision (e.g. a narrowed authorization_details grant)
	// against exactly what was requested before recording that decision.
	Parameters map[string]json.RawMessage
}

// DecideBackchannelAuthentication is the input to
// BackchannelAuthenticationStore.DecideBackchannelAuthentication.
type DecideBackchannelAuthentication struct {
	HandleHash [32]byte

	// Status must be one of Approved, Denied or AuthenticationFailed —
	// never Pending.
	Status BackchannelAuthenticationStatus

	// Subject, Scope, AuthorizationDetails, AuthTime, ACR and AMR are set
	// only when Status is Approved. AuthorizationDetails mirrors
	// NewAuthorizationCode.AuthorizationDetails — the resource owner's
	// granted Rich Authorization Requests (RFC 9396) detail array, or nil.
	Subject              string
	Scope                []string
	AuthorizationDetails json.RawMessage
	AuthTime             time.Time
	ACR                  string
	AMR                  []string

	// Reason is an optional, human-readable explanation, set when Status
	// is Denied or AuthenticationFailed — mirrors Deny/AuthenticationFailed's
	// own reason parameter.
	Reason string
}

// DecidedBackchannelAuthentication is returned by a successful
// DecideBackchannelAuthentication: ClientID for the caller's own audit
// logging (mirroring CompleteAuthorization's CompletedInteraction.ClientID),
// plus DeliveryMode and ClientNotificationToken — copied straight from
// the record NewBackchannelAuthentication originally created — so the
// caller can dispatch a CIBA §10.2 ping notification without a second
// round trip to this store.
type DecidedBackchannelAuthentication struct {
	ClientID fapi.ClientID

	// DeliveryMode is "poll" or "ping", mirroring
	// NewBackchannelAuthentication.DeliveryMode exactly.
	DeliveryMode string

	// ClientNotificationToken is "" for a "poll" DeliveryMode; for
	// "ping", it's the bearer token the caller must present to the
	// client's own notification endpoint.
	ClientNotificationToken fapi.Secret

	// AuthReqID mirrors NewBackchannelAuthentication.AuthReqID — "" for
	// a "poll" DeliveryMode; for "ping", the literal auth_req_id value
	// CIBA §10.2 requires the notification body to carry.
	AuthReqID string
}

// PollBackchannelAuthentication is the input to
// BackchannelAuthenticationStore.PollBackchannelAuthentication.
type PollBackchannelAuthentication struct {
	AuthReqIDHash [32]byte
	Now           time.Time
}

// PolledBackchannelAuthentication is what a successful
// PollBackchannelAuthentication returns.
type PolledBackchannelAuthentication struct {
	Status               BackchannelAuthenticationStatus
	ClientID             fapi.ClientID
	Subject              string
	Scope                []string
	AuthorizationDetails json.RawMessage
	AuthTime             time.Time
	ACR                  string
	AMR                  []string
	TokenClaims          map[string]json.RawMessage
	DPoPJKT              string
	Reason               string

	// RequestedIDTokenClaims and RequestedUserinfoClaims mirror
	// NewBackchannelAuthentication's fields of the same name.
	RequestedIDTokenClaims  []string
	RequestedUserinfoClaims []string
}

// BackchannelAuthenticationAlreadyRedeemedError mirrors
// AuthorizationCodeAlreadyRedeemedError exactly: returned when a poll
// observes an already-consumed Approved record — a CIBA auth_req_id
// issues tokens exactly once (CIBA §10.3).
type BackchannelAuthenticationAlreadyRedeemedError struct {
	IssuedAccessTokenKey   string
	IssuedRefreshTokenHash *[32]byte
}

func (e *BackchannelAuthenticationAlreadyRedeemedError) Error() string {
	return "storage: backchannel authentication request already redeemed"
}

// BackchannelAuthenticationExpiredError is returned by
// PollBackchannelAuthentication once the record's own ExpiresAt has
// passed, regardless of its decision status.
type BackchannelAuthenticationExpiredError struct{}

func (e *BackchannelAuthenticationExpiredError) Error() string {
	return "storage: backchannel authentication request has expired"
}

// BackchannelAuthenticationSlowDownError is returned by
// PollBackchannelAuthentication when called again before the record's
// own PollInterval has elapsed since the previous poll.
type BackchannelAuthenticationSlowDownError struct{}

func (e *BackchannelAuthenticationSlowDownError) Error() string {
	return "storage: polled again before the minimum interval elapsed"
}

// BackchannelAuthenticationStore persists CIBA backchannel
// authentication requests: creation, the out-of-band decision, and
// client polling for that decision.
type BackchannelAuthenticationStore interface {
	CreateBackchannelAuthentication(ctx context.Context, record NewBackchannelAuthentication) error

	// LookupBackchannelAuthentication returns the pending request
	// identified by HandleHash's own ClientID and Parameters, without
	// consuming or deciding it — unlike DecideBackchannelAuthentication,
	// this may be called any number of times. It exists so a caller can
	// validate a decision (e.g. that a narrowed authorization_details
	// grant is an acceptable subset of what was requested) against the
	// original request before calling DecideBackchannelAuthentication to
	// record it. Returns a plain error if HandleHash is unknown.
	LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (LookedUpBackchannelAuthentication, error)

	// DecideBackchannelAuthentication atomically records the terminal
	// outcome of a pending request identified by decision.HandleHash,
	// returning DecidedBackchannelAuthentication (see its own doc
	// comment). A second call for the same HandleHash must fail —
	// exactly one decision may ever be recorded, the same way
	// CompleteAuthorization's interaction handle is single-use.
	DecideBackchannelAuthentication(ctx context.Context, decision DecideBackchannelAuthentication) (DecidedBackchannelAuthentication, error)

	// PollBackchannelAuthentication atomically:
	//   - returns *BackchannelAuthenticationExpiredError once ExpiresAt
	//     has passed, regardless of decision status;
	//   - returns *BackchannelAuthenticationSlowDownError if called again
	//     before PollInterval has elapsed since the previous poll for
	//     this AuthReqIDHash (the interval is tracked internally — the
	//     caller supplies no interval of its own, only Now, so the
	//     check-and-record-last-poll-time step stays atomic rather than
	//     a check-then-act race);
	//   - returns Status Pending, unconsumed, on every poll before a
	//     decision has been recorded;
	//   - returns Status Denied or AuthenticationFailed, unconsumed and
	//     freely repeatable, once DecideBackchannelAuthentication has
	//     recorded one — mirroring RedeemRefreshToken's reusable
	//     contract, not RedeemAuthorizationCode's single-use one;
	//   - on the first poll to observe Status Approved, atomically marks
	//     the record redeemed and returns it; every subsequent poll for
	//     the same AuthReqIDHash returns
	//     *BackchannelAuthenticationAlreadyRedeemedError — an approved
	//     auth_req_id issues tokens exactly once (CIBA §10.3), the same
	//     single-use guarantee RedeemAuthorizationCode has.
	// It returns a plain error if AuthReqIDHash is unknown.
	PollBackchannelAuthentication(ctx context.Context, poll PollBackchannelAuthentication) (PolledBackchannelAuthentication, error)
}
