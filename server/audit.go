package server

import (
	"context"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// AuditEventType is a closed set of security-significant events the
// server can record.
type AuditEventType uint8

const (
	_ AuditEventType = iota

	// AuditEventPushAuthorizationRequest records the outcome of a
	// PushAuthorizationRequest call.
	AuditEventPushAuthorizationRequest

	// AuditEventBeginAuthorization records the outcome of a
	// BeginAuthorization call.
	AuditEventBeginAuthorization

	// AuditEventCompleteAuthorization records the outcome of a
	// CompleteAuthorization call.
	AuditEventCompleteAuthorization

	// AuditEventExchangeAuthorizationCode records the outcome of an
	// ExchangeAuthorizationCode call.
	AuditEventExchangeAuthorizationCode

	// AuditEventRefreshAccessToken records the outcome of a
	// RefreshAccessToken call.
	AuditEventRefreshAccessToken

	// AuditEventBeginBackchannelAuthentication records the outcome of a
	// BeginBackchannelAuthentication call.
	AuditEventBeginBackchannelAuthentication

	// AuditEventCompleteBackchannelAuthentication records the outcome of
	// a CompleteBackchannelAuthentication call.
	AuditEventCompleteBackchannelAuthentication

	// AuditEventExchangeBackchannelAuthentication records the outcome of
	// an ExchangeBackchannelAuthentication call.
	AuditEventExchangeBackchannelAuthentication

	// AuditEventRequestClientCredentialsToken records the outcome of a
	// RequestClientCredentialsToken call.
	AuditEventRequestClientCredentialsToken
)

// AuditOutcome is a closed set of outcomes for an AuditEvent.
type AuditOutcome uint8

const (
	_ AuditOutcome = iota
	AuditOutcomeSuccess
	AuditOutcomeFailure
)

// AuditEvent is a structured, security-significant event. Description is
// a short, safe summary (e.g. an ErrorCode) — never a raw internal error
// or anything that could carry a token, key or assertion value.
type AuditEvent struct {
	Type        AuditEventType
	Time        time.Time
	ClientID    fapi.ClientID // "" if the client could not be identified
	Outcome     AuditOutcome
	Description string
}

// AuditSink records AuditEvents. Under AssuranceProduction, New requires
// one to be configured.
type AuditSink interface {
	Record(ctx context.Context, event AuditEvent) error
}
