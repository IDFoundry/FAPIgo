package server

import (
	"fmt"
	"log/slog"
	"net/url"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/redact"
)

// This file holds the renderings of this package's results that carry
// an interaction or CIBA handle, an auth_req_id, a request_uri, a
// redirect carrying an authorization code, or extension values and hint
// tokens: each prints a shadow of itself (see internal/redact), in which
// every bearer value is a redact.Hidden, and logs a group of the same
// fields. A handle's own String stays its wire value; only LogValue
// redacts it. So a group holds each value it nests that has a LogValue
// (a handle, an interaction, its hints and its extension values) as that
// LogValue, already resolved: log/slog's own handlers resolve a group's
// attributes, but a handler that prints a resolved value with %v, or
// slog.Value's String, prints them as fmt does, a handle as its wire
// value, and one that encodes them unresolved prints what encoding/json
// gives, an interaction as its storage encoding.

// The slog keys more than two renderings below share.
const (
	handleKey      = "Handle"
	interactionKey = "Interaction"
	expiresAtKey   = "ExpiresAt"
)

// LogValue implements slog.LogValuer: h is logged as [REDACTED]. Its
// String stays its wire value, which fmt prints.
func (h InteractionHandle) LogValue() slog.Value { return h.value.LogValue() }

// LogValue implements slog.LogValuer: h is logged as [REDACTED]. Its
// String stays its wire value, which fmt prints.
func (h BackchannelAuthenticationHandle) LogValue() slog.Value { return h.value.LogValue() }

// LogValue implements slog.LogValuer: a is logged as [REDACTED]. Its
// String stays its wire value, which fmt prints.
func (a AuthReqID) LogValue() slog.Value { return a.value.LogValue() }

// LogValue implements slog.LogValuer: r is logged as [REDACTED]. Its
// String stays its wire value, which fmt prints.
func (r RequestURI) LogValue() slog.Value { return r.value.LogValue() }

type pushAuthorizationResultShadow struct {
	RequestURI    redact.Hidden
	ExpiresIn     time.Duration
	NextDPoPNonce string
}

func (r PushAuthorizationResult) shadow() pushAuthorizationResultShadow {
	return pushAuthorizationResultShadow{RequestURI: redact.Mask(r.RequestURI.value), ExpiresIn: r.ExpiresIn, NextDPoPNonce: r.NextDPoPNonce}
}

// Format implements fmt.Formatter: r prints its lifetime and DPoP nonce,
// and [REDACTED] for its RequestURI, under every verb and flag.
func (r PushAuthorizationResult) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "server.pushAuthorizationResultShadow", "server.PushAuthorizationResult")
}

// String is r's %v rendering, without its request_uri.
func (r PushAuthorizationResult) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's RequestURI as [REDACTED], its
// lifetime and its DPoP nonce.
func (r PushAuthorizationResult) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("RequestURI", r.RequestURI.LogValue()), slog.Duration("ExpiresIn", r.ExpiresIn),
		slog.String("NextDPoPNonce", r.NextDPoPNonce),
	)
}

type interactionRequiredShadow struct {
	Handle      redact.Hidden
	Interaction InteractionRequest
	ExpiresAt   time.Time
}

func (a InteractionRequired) shadow() interactionRequiredShadow {
	return interactionRequiredShadow{Handle: redact.Mask(a.Handle.value), Interaction: a.Interaction, ExpiresAt: a.ExpiresAt}
}

// Format implements fmt.Formatter: a prints its fields with [REDACTED]
// for its Handle, under every verb and flag; its Interaction prints its
// extension values as parameter names only.
func (a InteractionRequired) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, a.shadow(), "server.interactionRequiredShadow", "server.InteractionRequired")
}

// String is a's %v rendering, without its Handle.
func (a InteractionRequired) String() string { return fmt.Sprint(a.shadow()) }

// LogValue implements slog.LogValuer: a's Handle as [REDACTED], its
// Interaction (see InteractionRequest.LogValue) and its expiry.
func (a InteractionRequired) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any(handleKey, a.Handle.LogValue()), slog.Any(interactionKey, a.Interaction.LogValue()), slog.Time(expiresAtKey, a.ExpiresAt),
	)
}

type backchannelInteractionRequiredShadow struct {
	Handle      redact.Hidden
	AuthReqID   redact.Hidden
	ExpiresIn   time.Duration
	Interval    time.Duration
	Interaction BackchannelInteractionRequest
}

func (a BackchannelInteractionRequired) shadow() backchannelInteractionRequiredShadow {
	return backchannelInteractionRequiredShadow{
		Handle: redact.Mask(a.Handle.value), AuthReqID: redact.Mask(a.AuthReqID.value),
		ExpiresIn: a.ExpiresIn, Interval: a.Interval, Interaction: a.Interaction,
	}
}

// Format implements fmt.Formatter: a prints its fields with [REDACTED]
// for its Handle and AuthReqID, under every verb and flag. WriteJSON
// writes the auth_req_id itself, for the client.
func (a BackchannelInteractionRequired) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, a.shadow(), "server.backchannelInteractionRequiredShadow", "server.BackchannelInteractionRequired")
}

// String is a's %v rendering, without its Handle and AuthReqID.
func (a BackchannelInteractionRequired) String() string { return fmt.Sprint(a.shadow()) }

// LogValue implements slog.LogValuer: a's Handle and AuthReqID as
// [REDACTED], its lifetimes and its Interaction (see
// BackchannelInteractionRequest.LogValue).
func (a BackchannelInteractionRequired) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any(handleKey, a.Handle.LogValue()), slog.Any("AuthReqID", a.AuthReqID.LogValue()),
		slog.Duration("ExpiresIn", a.ExpiresIn), slog.Duration("Interval", a.Interval),
		slog.Any(interactionKey, a.Interaction.LogValue()),
	)
}

type pendingBackchannelInteractionShadow struct {
	ID          string
	Handle      redact.Hidden
	Interaction BackchannelInteractionRequest
	ExpiresAt   time.Time
}

func (p PendingBackchannelInteraction) shadow() pendingBackchannelInteractionShadow {
	return pendingBackchannelInteractionShadow{ID: p.ID, Handle: redact.Mask(p.Handle.value), Interaction: p.Interaction, ExpiresAt: p.ExpiresAt}
}

// Format implements fmt.Formatter: p prints its fields with [REDACTED]
// for its Handle, under every verb and flag. Its ID, which can't
// complete the request, prints.
func (p PendingBackchannelInteraction) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, p.shadow(), "server.pendingBackchannelInteractionShadow", "server.PendingBackchannelInteraction")
}

// String is p's %v rendering, without its Handle.
func (p PendingBackchannelInteraction) String() string { return fmt.Sprint(p.shadow()) }

// LogValue implements slog.LogValuer: p's ID, its Handle as [REDACTED],
// its Interaction and its expiry.
func (p PendingBackchannelInteraction) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("ID", p.ID), slog.Any(handleKey, p.Handle.LogValue()),
		slog.Any(interactionKey, p.Interaction.LogValue()), slog.Time(expiresAtKey, p.ExpiresAt),
	)
}

// redirectSummary is raw, a redirect URL, as a log may show it: its
// scheme, host, path and parameter names (see internal/redact.URL), or
// [REDACTED] for a value that isn't an absolute URL, which has no part
// known to be safe to show.
func redirectSummary(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return redact.Redacted
	}
	return redact.URL(*u)
}

type authorizationRedirectShadow struct {
	destination string
}

func (r AuthorizationRedirect) shadow() authorizationRedirectShadow {
	return authorizationRedirectShadow{destination: redirectSummary(r.destination.Reveal())}
}

// Format implements fmt.Formatter: r prints its destination's scheme,
// host, path and parameter names, under every verb and flag, never the
// code, state or signed response it carries.
func (r AuthorizationRedirect) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "server.authorizationRedirectShadow", "server.AuthorizationRedirect")
}

// String is r's %v rendering, without its destination's values.
func (r AuthorizationRedirect) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's destination, summarized as
// Format prints it.
func (r AuthorizationRedirect) LogValue() slog.Value {
	return slog.GroupValue(slog.String("Destination", r.shadow().destination))
}

type redirectResponseShadow struct {
	Destination string
}

func (r RedirectResponse) shadow() redirectResponseShadow {
	return redirectResponseShadow{Destination: destinationSummary(r.Destination)}
}

// destinationSummary is u, a redirect URL, as a log may show it.
func destinationSummary(u fapi.URL) string {
	if u.IsZero() {
		return ""
	}
	return redact.URL(u.URL())
}

// Format implements fmt.Formatter: r prints its Destination's scheme,
// host, path and parameter names, under every verb and flag.
func (r RedirectResponse) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "server.redirectResponseShadow", "server.RedirectResponse")
}

// String is r's %v rendering, without its Destination's values.
func (r RedirectResponse) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's Destination, summarized as
// Format prints it.
func (r RedirectResponse) LogValue() slog.Value {
	return slog.GroupValue(slog.String("Destination", r.shadow().Destination))
}

type backchannelAuthenticationHintsShadow struct {
	LoginHint      LoginHint
	LoginHintToken redact.Hidden
	IDTokenHint    redact.Hidden
}

func (h BackchannelAuthenticationHints) shadow() backchannelAuthenticationHintsShadow {
	return backchannelAuthenticationHintsShadow{
		LoginHint: h.LoginHint, LoginHintToken: redact.MaskString(h.LoginHintToken), IDTokenHint: redact.MaskString(h.IDTokenHint),
	}
}

// Format implements fmt.Formatter: h prints its LoginHint, and
// [REDACTED] for its login_hint_token and id_token_hint, under every
// verb and flag. The fields themselves are the hint tokens: never log
// them.
func (h BackchannelAuthenticationHints) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, h.shadow(), "server.backchannelAuthenticationHintsShadow", "server.BackchannelAuthenticationHints")
}

// String is h's %v rendering, without its hint tokens.
func (h BackchannelAuthenticationHints) String() string { return fmt.Sprint(h.shadow()) }

// LogValue implements slog.LogValuer: h's LoginHint, and its hint tokens
// as [REDACTED].
func (h BackchannelAuthenticationHints) LogValue() slog.Value {
	shadow := h.shadow()
	return slog.GroupValue(
		slog.String("LoginHint", string(shadow.LoginHint)),
		slog.String("LoginHintToken", string(shadow.LoginHintToken)), slog.String("IDTokenHint", string(shadow.IDTokenHint)),
	)
}

// LogValue implements slog.LogValuer: r's fields as a group, its
// Extensions as parameter names only, rather than MarshalText, the
// storage encoding, which log/slog would otherwise log and which
// carries every value.
func (r InteractionRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("ClientID", r.ClientID.String()), slog.Any("Scope", r.Scope),
		slog.String("LoginHint", string(r.Hints.LoginHint)), slog.Any("ACRValues", r.ACRValues),
		slog.Any("EssentialACRValues", r.EssentialACRValues), slog.String("RequiredSubject", r.RequiredSubject),
		slog.Duration("MaxAge", r.MaxAge), slog.Bool("HasMaxAge", r.HasMaxAge),
		slog.Any("Prompt", r.Prompt), slog.Any("UILocales", r.UILocales), slog.Any("ClaimsLocales", r.ClaimsLocales),
		slog.String("Display", string(r.Display)), slog.Any("ClientDisplay", r.ClientDisplay),
		slog.String("RedirectURI", urlString(r.RedirectURI)), slog.Any("AuthorizationDetails", r.AuthorizationDetails),
		slog.Any("Resources", r.Resources), slog.Any("RequestedClaims", r.RequestedClaims),
		slog.Any("Extensions", r.Extensions.LogValue()),
	)
}

// LogValue implements slog.LogValuer: r's fields as a group, with its
// hint tokens as [REDACTED] and its Extensions as parameter names only.
func (r BackchannelInteractionRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("ClientID", r.ClientID.String()), slog.Any("Scope", r.Scope),
		slog.Any("Hints", r.Hints.LogValue()), slog.Any("ACRValues", r.ACRValues),
		slog.Any("EssentialACRValues", r.EssentialACRValues), slog.String("RequiredSubject", r.RequiredSubject),
		slog.String("BindingMessage", r.BindingMessage), slog.Any("ClientDisplay", r.ClientDisplay),
		slog.Any("AuthorizationDetails", r.AuthorizationDetails), slog.Any("Resources", r.Resources),
		slog.Any("RequestedClaims", r.RequestedClaims), slog.Any("Extensions", r.Extensions.LogValue()),
	)
}
