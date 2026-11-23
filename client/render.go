package client

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/idfoundry/fapigo/internal/redact"
)

// scopeKey is the slog key of a scope, in the renderings below that log
// one.
const scopeKey = "Scope"

// This file holds the renderings of this package's types that carry
// bearer material: a code, PKCE verifier or nonce, an access token, an
// auth_req_id, a notification token or a session handle. Each type
// prints a shadow of itself (see internal/redact): a struct with the
// same field names in the same order, in which every bearer value is a
// redact.Hidden, so fmt prints [REDACTED] for it under every verb and
// flag. LogValue gives log/slog the same fields as a group, holding
// each value it nests that has a LogValue (a SessionHandle, a
// fapi.Secret, extension values) as that LogValue, already resolved: a
// handle's String is its wire value, and a handler that prints a
// resolved value with %v, or slog.Value's String, prints a group's
// attributes as fmt does, while one that encodes them unresolved prints
// what encoding/json gives, every value for extension.Values.

type validatedAuthorizationResponseShadow struct {
	issuer       string
	clientID     string
	code         redact.Hidden
	redirectURI  string
	pkceVerifier redact.Hidden
	nonce        redact.Hidden
	maxAge       string
	hasMaxAge    bool
	openID       bool
	essentialACR []string
	resource     []string
	scope        []string
}

func (r ValidatedAuthorizationResponse) shadow() validatedAuthorizationResponseShadow {
	return validatedAuthorizationResponseShadow{
		issuer: r.issuer, clientID: r.clientID, code: redact.Mask(r.code), redirectURI: r.redirectURI,
		pkceVerifier: redact.Mask(r.pkceVerifier), nonce: redact.Mask(r.nonce),
		maxAge: r.maxAge.String(), hasMaxAge: r.hasMaxAge, openID: r.openID,
		essentialACR: r.essentialACR, resource: r.resource, scope: r.scope,
	}
}

// Format implements fmt.Formatter: r prints its fields, with [REDACTED]
// in place of its code, PKCE verifier and nonce, under every verb and
// flag.
func (r ValidatedAuthorizationResponse) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "client.validatedAuthorizationResponseShadow", "client.ValidatedAuthorizationResponse")
}

// String is r's %v rendering, without its code, PKCE verifier and nonce.
func (r ValidatedAuthorizationResponse) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's issuer, client, redirect URI
// and scope, with its code logged as [REDACTED].
func (r ValidatedAuthorizationResponse) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Issuer", r.issuer), slog.String("ClientID", r.clientID),
		slog.String("RedirectURI", r.redirectURI), slog.Any(scopeKey, r.scope),
		slog.Any("Code", r.code.LogValue()),
	)
}

type resourceClientShadow struct {
	client string
	token  redact.Hidden
	err    string
}

func (rc ResourceClient) shadow() resourceClientShadow {
	shadow := resourceClientShadow{client: fmt.Sprintf("%p", rc.client), token: redact.Mask(rc.token), err: "<nil>"}
	if rc.err != nil {
		shadow.err = rc.err.Error()
	}
	return shadow
}

// Format implements fmt.Formatter: rc prints its Client's address, its
// error if it has one, and [REDACTED] for its access token, under every
// verb and flag.
func (rc ResourceClient) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, rc.shadow(), "client.resourceClientShadow", "client.ResourceClient")
}

// String is rc's %v rendering, without its access token.
func (rc ResourceClient) String() string { return fmt.Sprint(rc.shadow()) }

// LogValue implements slog.LogValuer: rc's access token, logged as
// [REDACTED], and its error if it has one.
func (rc ResourceClient) LogValue() slog.Value {
	attrs := []slog.Attr{slog.Any("Token", rc.token.LogValue())}
	if rc.err != nil {
		attrs = append(attrs, slog.String("Error", rc.err.Error()))
	}
	return slog.GroupValue(attrs...)
}

type backchannelAuthenticationSessionShadow struct {
	issuer            string
	clientID          string
	authReqID         redact.Hidden
	interval          string
	expiresAt         string
	notificationToken redact.Hidden
	openID            bool
	essentialACR      []string
	resource          []string
	scope             []string
}

func (s BackchannelAuthenticationSession) shadow() backchannelAuthenticationSessionShadow {
	return backchannelAuthenticationSessionShadow{
		issuer: s.issuer, clientID: s.clientID, authReqID: redact.Mask(s.authReqID),
		interval: s.interval.String(), expiresAt: s.expiresAt.String(), notificationToken: redact.Mask(s.notificationToken),
		openID: s.openID, essentialACR: s.essentialACR, resource: s.resource, scope: s.scope,
	}
}

// Format implements fmt.Formatter: s prints its fields, with
// [REDACTED] in place of its auth_req_id and notification token, under
// every verb and flag.
func (s BackchannelAuthenticationSession) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, s.shadow(), "client.backchannelAuthenticationSessionShadow", "client.BackchannelAuthenticationSession")
}

// String is s's %v rendering, without its auth_req_id and notification
// token.
func (s BackchannelAuthenticationSession) String() string { return fmt.Sprint(s.shadow()) }

// LogValue implements slog.LogValuer: s's issuer, client, expiry and
// interval, with its auth_req_id and notification token logged as
// [REDACTED].
func (s BackchannelAuthenticationSession) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Issuer", s.issuer), slog.String("ClientID", s.clientID),
		slog.Time("ExpiresAt", s.expiresAt), slog.Duration("Interval", s.interval),
		slog.Any("AuthReqID", s.authReqID.LogValue()), slog.Any("NotificationToken", s.notificationToken.LogValue()),
	)
}

type backchannelNotificationShadow struct {
	authReqID redact.Hidden
	token     redact.Hidden
}

func (n BackchannelNotification) shadow() backchannelNotificationShadow {
	return backchannelNotificationShadow{authReqID: redact.Mask(n.authReqID), token: redact.Mask(n.token)}
}

// Format implements fmt.Formatter: n prints [REDACTED] for its
// auth_req_id and its bearer token, under every verb and flag.
func (n BackchannelNotification) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, n.shadow(), "client.backchannelNotificationShadow", "client.BackchannelNotification")
}

// String is n's %v rendering, without its auth_req_id and bearer token.
func (n BackchannelNotification) String() string { return fmt.Sprint(n.shadow()) }

// LogValue implements slog.LogValuer: n's auth_req_id and bearer token,
// logged as [REDACTED].
func (n BackchannelNotification) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("AuthReqID", n.authReqID.LogValue()), slog.Any("Token", n.token.LogValue()))
}

// LogValue implements slog.LogValuer: h is logged as [REDACTED]. Its
// String stays its wire value, which fmt prints.
func (h SessionHandle) LogValue() slog.Value { return h.value.LogValue() }

type authorizationSessionShadow struct {
	url       string
	handle    redact.Hidden
	expiresAt string
}

func (s AuthorizationSession) shadow() authorizationSessionShadow {
	u := s.URL()
	return authorizationSessionShadow{url: redact.URL(u.URL()), handle: redact.Mask(s.handle.value), expiresAt: s.expiresAt.String()}
}

// Format implements fmt.Formatter: s prints its authorization URL's
// scheme, host, path and parameter names, never the request_uri it
// carries, its expiry, and [REDACTED] for its SessionHandle, under every
// verb and flag.
func (s AuthorizationSession) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, s.shadow(), "client.authorizationSessionShadow", "client.AuthorizationSession")
}

// String is s's %v rendering, without its handle or its URL's values.
func (s AuthorizationSession) String() string { return fmt.Sprint(s.shadow()) }

// LogValue implements slog.LogValuer: s's URL summarized as Format
// prints it, its expiry, and its handle logged as [REDACTED].
func (s AuthorizationSession) LogValue() slog.Value {
	shadow := s.shadow()
	return slog.GroupValue(
		slog.String("URL", shadow.url), slog.Any("Handle", s.handle.LogValue()), slog.Time("ExpiresAt", s.expiresAt),
	)
}

type authorizationCallbackShadow struct {
	RawQuery string
	Session  redact.Hidden
}

func (cb AuthorizationCallback) shadow() authorizationCallbackShadow {
	return authorizationCallbackShadow{RawQuery: redact.Query(cb.RawQuery), Session: redact.Mask(cb.Session.value)}
}

// Format implements fmt.Formatter: cb prints its query's parameter
// names, with [REDACTED] for every value, and [REDACTED] for its
// Session, under every verb and flag. Its fields themselves are the raw
// callback: never log them.
func (cb AuthorizationCallback) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, cb.shadow(), "client.authorizationCallbackShadow", "client.AuthorizationCallback")
}

// String is cb's %v rendering, without its query's values or Session.
func (cb AuthorizationCallback) String() string { return fmt.Sprint(cb.shadow()) }

// LogValue implements slog.LogValuer: cb's query's parameter names, and
// its Session logged as [REDACTED].
func (cb AuthorizationCallback) LogValue() slog.Value {
	return slog.GroupValue(slog.String("RawQuery", redact.Query(cb.RawQuery)), slog.Any("Session", cb.Session.LogValue()))
}

type beginBackchannelAuthenticationRequestShadow struct {
	Scope                []string
	LoginHint            string
	LoginHintToken       redact.Hidden
	IDTokenHint          redact.Hidden
	ACRValues            []string
	EssentialACRValues   []string
	BindingMessage       string
	RequestedExpiry      time.Duration
	AuthorizationDetails []json.RawMessage
	Resource             []string
}

func (r BeginBackchannelAuthenticationRequest) shadow() beginBackchannelAuthenticationRequestShadow {
	return beginBackchannelAuthenticationRequestShadow{
		Scope: r.Scope, LoginHint: r.LoginHint,
		LoginHintToken: redact.MaskString(r.LoginHintToken), IDTokenHint: redact.MaskString(r.IDTokenHint),
		ACRValues: r.ACRValues, EssentialACRValues: r.EssentialACRValues, BindingMessage: r.BindingMessage,
		RequestedExpiry: r.RequestedExpiry, AuthorizationDetails: r.AuthorizationDetails, Resource: r.Resource,
	}
}

// Format implements fmt.Formatter: r prints its fields, with
// [REDACTED] in place of its login_hint_token and id_token_hint, under
// every verb and flag. The fields themselves carry the hint tokens:
// never log them.
func (r BeginBackchannelAuthenticationRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "client.beginBackchannelAuthenticationRequestShadow", "client.BeginBackchannelAuthenticationRequest")
}

// String is r's %v rendering, without its hint tokens.
func (r BeginBackchannelAuthenticationRequest) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's fields, with its
// login_hint_token and id_token_hint logged as [REDACTED].
func (r BeginBackchannelAuthenticationRequest) LogValue() slog.Value {
	shadow := r.shadow()
	return slog.GroupValue(
		slog.Any(scopeKey, shadow.Scope), slog.String("LoginHint", shadow.LoginHint),
		slog.String("LoginHintToken", string(shadow.LoginHintToken)), slog.String("IDTokenHint", string(shadow.IDTokenHint)),
		slog.Any("ACRValues", shadow.ACRValues), slog.Any("EssentialACRValues", shadow.EssentialACRValues),
		slog.String("BindingMessage", shadow.BindingMessage), slog.Duration("RequestedExpiry", shadow.RequestedExpiry),
		slog.Int("AuthorizationDetails", len(shadow.AuthorizationDetails)), slog.Any("Resource", shadow.Resource),
	)
}

// LogValue implements slog.LogValuer: r's fields as a group, with its
// Extensions as parameter names only. log/slog's JSON handler would
// otherwise encode r with encoding/json, and Extensions through its
// MarshalJSON, which carries every value; fmt prints r's fields, and
// Extensions as names, already.
func (r BeginAuthorizationRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any(scopeKey, r.Scope), slog.Int("RedirectPort", int(r.RedirectPort)),
		slog.Any("ACRValues", r.ACRValues), slog.Duration("MaxAge", r.MaxAge), slog.Bool("HasMaxAge", r.HasMaxAge),
		slog.Any("Prompt", r.Prompt), slog.Any("EssentialACRValues", r.EssentialACRValues),
		slog.Any("Extensions", r.Extensions.LogValue()), slog.Int("AuthorizationDetails", len(r.AuthorizationDetails)),
		slog.Any("Claims", r.Claims), slog.Any("Resource", r.Resource),
	)
}
