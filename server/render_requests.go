package server

import (
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/idfoundry/fapigo/internal/redact"
)

// This file holds the renderings of the requests an HTTP adapter builds
// and hands to the server: forms carrying codes, verifiers, refresh
// tokens, client assertions, auth_req_ids and request objects, DPoP
// proofs and client attestations, and the handles and tokens a
// completion or a ping carries. Each prints a shadow (see
// internal/redact) in which only the values of form parameters on
// formValueAllowlist print. The exported fields themselves still hold
// every value, as they must: fmt's reflection fallback and the encoders
// print them as they print any exported field, so never log the fields.
// A group holds each value it nests that has a LogValue (a form, a
// handle, a ping's token) as that LogValue, already resolved, as the
// results' groups do (see render.go): a handler that encodes a group's
// attributes without resolving them would print a form's raw fields.

// The slog keys more than two renderings below share.
const (
	clientAttestationsKey    = "ClientAttestations"
	clientAttestationPoPsKey = "ClientAttestationPoPs"
)

// formValueAllowlist names the form parameters whose values a rendering
// prints. None of them carries a credential, a code, a token, a handle,
// a hint token, a request object, a request_uri (a bearer value in the
// front channel until its interaction completes) or a value this server
// can't classify, such as an extension parameter's. Every other
// parameter prints [REDACTED].
var formValueAllowlist = map[string]bool{
	"grant_type": true, "response_type": true, "response_mode": true, "client_id": true,
	"scope": true, "redirect_uri": true, "code_challenge_method": true, "code_challenge": true,
	"prompt": true, "max_age": true, "acr_values": true, "ui_locales": true, "claims_locales": true,
	"display": true, "resource": true, "token_type_hint": true, "client_assertion_type": true,
	"dpop_jkt": true, "requested_expiry": true,
}

type formParameterShadow struct {
	Name  string
	Value string
}

func (p FormParameter) shadow() formParameterShadow {
	shadow := formParameterShadow{Name: redact.Name(p.Name)}
	switch {
	case p.Value == "":
	case formValueAllowlist[p.Name]:
		shadow.Value = redact.Text(p.Value)
	default:
		shadow.Value = redact.Redacted
	}
	return shadow
}

// formShadowRenames are the names the form shadows print under %#v, and
// those of the types they shadow.
var formShadowRenames = []string{
	"server.formRequestShadow", "server.FormRequest",
	"server.formParameterShadow", "server.FormParameter",
}

// Format implements fmt.Formatter: p prints its name, and its value only
// for a parameter that carries no credential (grant_type, scope,
// redirect_uri and the like), under every verb and flag; any other
// value, an unknown or extension parameter's included, prints as
// [REDACTED].
func (p FormParameter) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, p.shadow(), formShadowRenames...)
}

// String is p's %v rendering.
func (p FormParameter) String() string { return fmt.Sprint(p.shadow()) }

// LogValue implements slog.LogValuer: p as name=value, with the value
// as Format prints it.
func (p FormParameter) LogValue() slog.Value {
	shadow := p.shadow()
	return slog.StringValue(shadow.Name + "=" + shadow.Value)
}

type formRequestShadow struct {
	Parameters    []formParameterShadow
	EndpointRoute EndpointRoute
}

func (f FormRequest) shadow() formRequestShadow {
	if f.Parameters == nil {
		return formRequestShadow{EndpointRoute: f.EndpointRoute}
	}
	shadow := formRequestShadow{Parameters: make([]formParameterShadow, len(f.Parameters)), EndpointRoute: f.EndpointRoute}
	for i, p := range f.Parameters {
		shadow.Parameters[i] = p.shadow()
	}
	return shadow
}

// Format implements fmt.Formatter: f prints each parameter as
// FormParameter does, under every verb and flag.
func (f FormRequest) Format(s fmt.State, verb rune) {
	redact.Format(s, verb, f.shadow(), formShadowRenames...)
}

// String is f's %v rendering.
func (f FormRequest) String() string { return fmt.Sprint(f.shadow()) }

// LogValue implements slog.LogValuer: f's parameters, each as
// FormParameter.LogValue logs it.
func (f FormRequest) LogValue() slog.Value {
	params := make([]string, len(f.Parameters))
	for i, p := range f.Parameters {
		params[i] = p.LogValue().String()
	}
	return slog.GroupValue(slog.Any("Parameters", params), slog.String("EndpointRoute", f.EndpointRoute.String()))
}

// certificateSummary is cert as a rendering shows it: its subject, or ""
// for none, %q-quoted if it holds a byte outside printable ASCII (see
// redact.Text). A certificate is public, but its encoding is long, and
// a self-signed one's subject is the client's to choose: a newline in
// it, which pkix.Name's String leaves as it is, would forge a log line.
func certificateSummary(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return redact.Text(cert.Subject.String())
}

type httpRequestPartsShadow struct {
	HTTP                  formRequestShadow
	DPoPProofs            []redact.Hidden
	ClientAttestations    []redact.Hidden
	ClientAttestationPoPs []redact.Hidden
	PeerCertificate       string
}

func (p httpRequestParts) shadow() httpRequestPartsShadow {
	return httpRequestPartsShadow{
		HTTP: p.HTTP.shadow(), DPoPProofs: redact.MaskStrings(p.DPoPProofs),
		ClientAttestations: redact.MaskStrings(p.ClientAttestations), ClientAttestationPoPs: redact.MaskStrings(p.ClientAttestationPoPs),
		PeerCertificate: certificateSummary(p.PeerCertificate),
	}
}

// format prints p's shadow under verb as the request type named
// realName, which has p's fields.
func (p httpRequestParts) format(f fmt.State, verb rune, realName string) {
	redact.Format(f, verb, p.shadow(), append([]string{"server.httpRequestPartsShadow", realName}, formShadowRenames...)...)
}

func (p httpRequestParts) String() string { return fmt.Sprint(p.shadow()) }

func (p httpRequestParts) LogValue() slog.Value {
	shadow := p.shadow()
	return slog.GroupValue(
		slog.Any("HTTP", p.HTTP.LogValue()), slog.Any("DPoPProofs", shadow.DPoPProofs),
		slog.Any(clientAttestationsKey, shadow.ClientAttestations), slog.Any(clientAttestationPoPsKey, shadow.ClientAttestationPoPs),
		slog.String("PeerCertificate", shadow.PeerCertificate),
	)
}

// Format implements fmt.Formatter: r prints its form as FormRequest
// does, its DPoP proofs and client attestations as [REDACTED] and its
// certificate as its subject, under every verb and flag.
func (r PushAuthorizationRequest) Format(f fmt.State, verb rune) {
	httpRequestParts(r).format(f, verb, "server.PushAuthorizationRequest")
}

// String is r's %v rendering, without its credentials.
func (r PushAuthorizationRequest) String() string { return httpRequestParts(r).String() }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r PushAuthorizationRequest) LogValue() slog.Value { return httpRequestParts(r).LogValue() }

// Format implements fmt.Formatter, as PushAuthorizationRequest's does:
// no code, verifier or credential prints.
func (r AuthorizationCodeExchangeRequest) Format(f fmt.State, verb rune) {
	httpRequestParts(r).format(f, verb, "server.AuthorizationCodeExchangeRequest")
}

// String is r's %v rendering, without its code or credentials.
func (r AuthorizationCodeExchangeRequest) String() string { return httpRequestParts(r).String() }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r AuthorizationCodeExchangeRequest) LogValue() slog.Value {
	return httpRequestParts(r).LogValue()
}

// Format implements fmt.Formatter, as PushAuthorizationRequest's does:
// no refresh token or credential prints.
func (r RefreshTokenRequest) Format(f fmt.State, verb rune) {
	httpRequestParts(r).format(f, verb, "server.RefreshTokenRequest")
}

// String is r's %v rendering, without its refresh token or credentials.
func (r RefreshTokenRequest) String() string { return httpRequestParts(r).String() }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r RefreshTokenRequest) LogValue() slog.Value { return httpRequestParts(r).LogValue() }

// Format implements fmt.Formatter, as PushAuthorizationRequest's does:
// no credential prints.
func (r ClientCredentialsTokenRequest) Format(f fmt.State, verb rune) {
	httpRequestParts(r).format(f, verb, "server.ClientCredentialsTokenRequest")
}

// String is r's %v rendering, without its credentials.
func (r ClientCredentialsTokenRequest) String() string { return httpRequestParts(r).String() }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r ClientCredentialsTokenRequest) LogValue() slog.Value {
	return httpRequestParts(r).LogValue()
}

// Format implements fmt.Formatter, as PushAuthorizationRequest's does:
// no auth_req_id or credential prints.
func (r BackchannelTokenExchangeRequest) Format(f fmt.State, verb rune) {
	httpRequestParts(r).format(f, verb, "server.BackchannelTokenExchangeRequest")
}

// String is r's %v rendering, without its auth_req_id or credentials.
func (r BackchannelTokenExchangeRequest) String() string { return httpRequestParts(r).String() }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r BackchannelTokenExchangeRequest) LogValue() slog.Value {
	return httpRequestParts(r).LogValue()
}

// Format implements fmt.Formatter, as PushAuthorizationRequest's does:
// neither the signed request nor a credential prints.
func (r BeginBackchannelAuthenticationRequest) Format(f fmt.State, verb rune) {
	httpRequestParts(r).format(f, verb, "server.BeginBackchannelAuthenticationRequest")
}

// String is r's %v rendering, without its request or credentials.
func (r BeginBackchannelAuthenticationRequest) String() string { return httpRequestParts(r).String() }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r BeginBackchannelAuthenticationRequest) LogValue() slog.Value {
	return httpRequestParts(r).LogValue()
}

type tokenEndpointRequestShadow struct {
	parts httpRequestPartsShadow
}

// Format implements fmt.Formatter: t prints the request it holds as
// PushAuthorizationRequest does, under every verb and flag.
func (t TokenEndpointRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, tokenEndpointRequestShadow{parts: t.parts.get().shadow()},
		append([]string{"server.tokenEndpointRequestShadow", "server.TokenEndpointRequest", "server.httpRequestPartsShadow", "server.httpRequestParts"}, formShadowRenames...)...)
}

// String is t's %v rendering, without its code, tokens or credentials.
func (t TokenEndpointRequest) String() string {
	return fmt.Sprint(tokenEndpointRequestShadow{parts: t.parts.get().shadow()})
}

// LogValue implements slog.LogValuer: the request t holds, as Format
// prints it.
func (t TokenEndpointRequest) LogValue() slog.Value { return t.parts.get().LogValue() }

type tokenRevocationRequestShadow struct {
	HTTP                  formRequestShadow
	ClientAttestations    []redact.Hidden
	ClientAttestationPoPs []redact.Hidden
	PeerCertificate       string
}

func (r TokenRevocationRequest) shadow() tokenRevocationRequestShadow {
	return tokenRevocationRequestShadow{
		HTTP: r.HTTP.shadow(), ClientAttestations: redact.MaskStrings(r.ClientAttestations),
		ClientAttestationPoPs: redact.MaskStrings(r.ClientAttestationPoPs), PeerCertificate: certificateSummary(r.PeerCertificate),
	}
}

// Format implements fmt.Formatter: r prints its form as FormRequest
// does, with the token it revokes as [REDACTED], its client attestations
// as [REDACTED] and its certificate as its subject, under every verb and
// flag.
func (r TokenRevocationRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), append([]string{"server.tokenRevocationRequestShadow", "server.TokenRevocationRequest"}, formShadowRenames...)...)
}

// String is r's %v rendering, without its token or credentials.
func (r TokenRevocationRequest) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r TokenRevocationRequest) LogValue() slog.Value {
	shadow := r.shadow()
	return slog.GroupValue(
		slog.Any("HTTP", r.HTTP.LogValue()), slog.Any(clientAttestationsKey, shadow.ClientAttestations),
		slog.Any(clientAttestationPoPsKey, shadow.ClientAttestationPoPs), slog.String("PeerCertificate", shadow.PeerCertificate),
	)
}

type attestedClientAuthenticationRequestShadow struct {
	ClientAttestations    []redact.Hidden
	ClientAttestationPoPs []redact.Hidden
	ClientID              string
	malformed             bool
	otherClientAuth       bool
}

func (r AttestedClientAuthenticationRequest) shadow() attestedClientAuthenticationRequestShadow {
	return attestedClientAuthenticationRequestShadow{
		ClientAttestations: redact.MaskStrings(r.ClientAttestations), ClientAttestationPoPs: redact.MaskStrings(r.ClientAttestationPoPs),
		ClientID: redact.Text(r.ClientID), malformed: r.malformed, otherClientAuth: r.otherClientAuth,
	}
}

// Format implements fmt.Formatter: r prints its ClientID, %q-quoted if
// it holds a byte outside printable ASCII, and its client attestations
// as [REDACTED], under every verb and flag.
func (r AttestedClientAuthenticationRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "server.attestedClientAuthenticationRequestShadow", "server.AttestedClientAuthenticationRequest")
}

// String is r's %v rendering, without its attestations.
func (r AttestedClientAuthenticationRequest) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's ClientID, and its client
// attestations as [REDACTED].
func (r AttestedClientAuthenticationRequest) LogValue() slog.Value {
	shadow := r.shadow()
	return slog.GroupValue(
		slog.Any(clientAttestationsKey, shadow.ClientAttestations), slog.Any(clientAttestationPoPsKey, shadow.ClientAttestationPoPs),
		slog.String("ClientID", r.ClientID),
	)
}

type beginAuthorizationRequestShadow struct {
	RequestURI redact.Hidden
	ClientID   string
	Request    redact.Hidden
}

func (r BeginAuthorizationRequest) shadow() beginAuthorizationRequestShadow {
	return beginAuthorizationRequestShadow{RequestURI: redact.MaskString(r.RequestURI), ClientID: redact.Text(r.ClientID.String()), Request: redact.MaskString(r.Request)}
}

// Format implements fmt.Formatter: r prints its client_id, %q-quoted if
// it holds a byte outside printable ASCII, and its request_uri and
// request object as [REDACTED], under every verb and flag. A live
// request_uri is a bearer value: see BeginAuthorization.
func (r BeginAuthorizationRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "server.beginAuthorizationRequestShadow", "server.BeginAuthorizationRequest")
}

// String is r's %v rendering, without its request_uri or request.
func (r BeginAuthorizationRequest) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r BeginAuthorizationRequest) LogValue() slog.Value {
	shadow := r.shadow()
	return slog.GroupValue(
		slog.String("RequestURI", string(shadow.RequestURI)), slog.String("ClientID", r.ClientID.String()),
		slog.String("Request", string(shadow.Request)),
	)
}

type completeAuthorizationRequestShadow struct {
	Handle redact.Hidden
	Result InteractionResult
}

// Format implements fmt.Formatter: r prints its Handle as [REDACTED],
// and its Result, under every verb and flag.
func (r CompleteAuthorizationRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, completeAuthorizationRequestShadow{Handle: redact.Mask(r.Handle.value), Result: r.Result},
		"server.completeAuthorizationRequestShadow", "server.CompleteAuthorizationRequest")
}

// String is r's %v rendering, without its Handle.
func (r CompleteAuthorizationRequest) String() string {
	return fmt.Sprint(completeAuthorizationRequestShadow{Handle: redact.Mask(r.Handle.value), Result: r.Result})
}

// LogValue implements slog.LogValuer: r's Handle as [REDACTED], and its
// Result.
func (r CompleteAuthorizationRequest) LogValue() slog.Value {
	return slog.GroupValue(slog.Any(handleKey, r.Handle.LogValue()), slog.String("Result", fmt.Sprintf("%+v", r.Result)))
}

// Format implements fmt.Formatter: r prints its Handle as [REDACTED],
// and its Result, under every verb and flag.
func (r CompleteBackchannelAuthenticationRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, completeAuthorizationRequestShadow{Handle: redact.Mask(r.Handle.value), Result: r.Result},
		"server.completeAuthorizationRequestShadow", "server.CompleteBackchannelAuthenticationRequest")
}

// String is r's %v rendering, without its Handle.
func (r CompleteBackchannelAuthenticationRequest) String() string {
	return fmt.Sprint(completeAuthorizationRequestShadow{Handle: redact.Mask(r.Handle.value), Result: r.Result})
}

// LogValue implements slog.LogValuer: r's Handle as [REDACTED], and its
// Result.
func (r CompleteBackchannelAuthenticationRequest) LogValue() slog.Value {
	return slog.GroupValue(slog.Any(handleKey, r.Handle.LogValue()), slog.String("Result", fmt.Sprintf("%+v", r.Result)))
}

type backchannelNotificationShadow struct {
	Endpoint                string
	ClientNotificationToken redact.Hidden
	AuthReqID               redact.Hidden
}

func (n BackchannelNotification) shadow() backchannelNotificationShadow {
	return backchannelNotificationShadow{
		Endpoint: destinationSummary(n.Endpoint), ClientNotificationToken: redact.Mask(n.ClientNotificationToken),
		AuthReqID: redact.MaskString(n.AuthReqID),
	}
}

// Format implements fmt.Formatter: n prints its Endpoint's scheme, host,
// path and parameter names, and its token and auth_req_id as
// [REDACTED], under every verb and flag. NewBackchannelNotificationRequest
// sends the values themselves.
func (n BackchannelNotification) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, n.shadow(), "server.backchannelNotificationShadow", "server.BackchannelNotification")
}

// String is n's %v rendering, without its token or auth_req_id.
func (n BackchannelNotification) String() string { return fmt.Sprint(n.shadow()) }

// LogValue implements slog.LogValuer: n's fields as Format prints them.
func (n BackchannelNotification) LogValue() slog.Value {
	shadow := n.shadow()
	return slog.GroupValue(
		slog.String("Endpoint", shadow.Endpoint), slog.Any("ClientNotificationToken", n.ClientNotificationToken.LogValue()),
		slog.String("AuthReqID", string(shadow.AuthReqID)),
	)
}
