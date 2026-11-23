package client

import (
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

// Sentinel values no rendering of the type holding them may print.
const (
	renderCode       = "AUTH-CODE-SECRET-0001"
	renderVerifier   = "PKCE-VERIFIER-SECRET-0002"
	renderNonce      = "PENDING-NONCE-SECRET-0003"
	renderToken      = "ACCESS-TOKEN-SECRET-0004"
	renderAuthReqID  = "AUTH-REQ-ID-SECRET-0005"
	renderNotify     = "NOTIFY-TOKEN-SECRET-0006"
	renderHandle     = "SESSION-HANDLE-SECRET-0007"
	renderHintToken  = "LOGIN-HINT-TOKEN-SECRET-0008"
	renderIDHint     = "ID-TOKEN-HINT-SECRET-0009"
	renderRequestURI = "REQUEST-URI-SECRET-0010"
	renderState      = "STATE-VALUE-SECRET-0011"
)

func renderResponse() ValidatedAuthorizationResponse {
	return ValidatedAuthorizationResponse{
		issuer: "https://as.example", clientID: "client-1", code: fapi.NewSecret(renderCode),
		redirectURI: "https://rp.example/cb", pkceVerifier: fapi.NewSecret(renderVerifier),
		nonce: fapi.NewSecret(renderNonce), openID: true, scope: []string{"openid"},
	}
}

func renderBackchannelSession() BackchannelAuthenticationSession {
	return BackchannelAuthenticationSession{
		issuer: "https://as.example", clientID: "client-1", authReqID: fapi.NewSecret(renderAuthReqID),
		interval: 5 * time.Second, expiresAt: time.Unix(1_900_000_000, 0).UTC(),
		notificationToken: fapi.NewSecret(renderNotify), openID: true, scope: []string{"openid"},
	}
}

func TestValidatedAuthorizationResponsePrintsNoSecret(t *testing.T) {
	r := renderResponse()
	secrets := []string{renderCode, renderVerifier, renderNonce}
	rendertest.Check(t, r, secrets)
	rendertest.Check(t, CallbackSuccess{Response: r}, secrets, rendertest.Quick())

	want := "{issuer:https://as.example clientID:client-1 code:[REDACTED] redirectURI:https://rp.example/cb pkceVerifier:[REDACTED] nonce:[REDACTED] maxAge:0s hasMaxAge:false openID:true essentialACR:[] resource:[] scope:[openid]}"
	if got := fmt.Sprintf("%+v", r); got != want {
		t.Errorf("%%+v = %s\nwant  %s", got, want)
	}
	if got := fmt.Sprintf("%#v", r); !strings.HasPrefix(got, `client.ValidatedAuthorizationResponse{issuer:"https://as.example"`) {
		t.Errorf("%%#v = %s, want the real type's name", got)
	}
	if r.String() != fmt.Sprint(r) {
		t.Errorf("String() = %s, want the %%v rendering %s", r.String(), fmt.Sprint(r))
	}
	if got := logged(r); !strings.Contains(got, "k.Code=[REDACTED]") || !strings.Contains(got, "k.Issuer=https://as.example") {
		t.Errorf("slog = %s", got)
	}
}

func TestResourceClientPrintsNoToken(t *testing.T) {
	rc := &ResourceClient{client: &Client{}, token: fapi.NewSecret(renderToken)}
	rendertest.Check(t, rc, []string{renderToken})
	rendertest.Check(t, *rc, []string{renderToken}, rendertest.Quick())
	if got := fmt.Sprintf("%+v", rc); !strings.HasPrefix(got, "{client:0x") || !strings.HasSuffix(got, " token:[REDACTED] err:<nil>}") {
		t.Errorf("%%+v = %s", got)
	}
	failing := &ResourceClient{client: rc.client, err: newError(ErrorInvalidRequest, "the token was issued by a different issuer", nil)}
	if got := fmt.Sprint(failing); !strings.Contains(got, "different issuer") || !strings.Contains(logged(failing), "k.Error=") {
		t.Errorf("a failing ResourceClient renders as %s, without its error", got)
	}
	if got := logged(rc); !strings.Contains(got, "k.Token=[REDACTED]") || strings.Contains(got, "k.Error") {
		t.Errorf("slog = %s", got)
	}
}

func TestBackchannelAuthenticationSessionPrintsNoSecret(t *testing.T) {
	s := renderBackchannelSession()
	secrets := []string{renderAuthReqID, renderNotify}
	rendertest.Check(t, s, secrets)
	rendertest.Check(t, BackchannelAuthenticationPending{Session: s}, secrets, rendertest.Quick())
	if s.AuthReqID() != renderAuthReqID || s.NotificationToken() != renderNotify {
		t.Error("the accessors no longer return the wire values")
	}
	if got := fmt.Sprintf("%+v", s); !strings.Contains(got, "authReqID:[REDACTED] interval:5s") || !strings.Contains(got, "notificationToken:[REDACTED]") {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(s); !strings.Contains(got, "k.AuthReqID=[REDACTED]") || !strings.Contains(got, "k.NotificationToken=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
}

func TestBackchannelNotificationPrintsNoSecret(t *testing.T) {
	n := BackchannelNotification{authReqID: fapi.NewSecret(renderAuthReqID), token: fapi.NewSecret(renderNotify)}
	rendertest.Check(t, n, []string{renderAuthReqID, renderNotify})
	if got := fmt.Sprintf("%+v", n); got != "{authReqID:[REDACTED] token:[REDACTED]}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(n); !strings.Contains(got, "k.AuthReqID=[REDACTED] k.Token=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
	if n.AuthReqID() != renderAuthReqID {
		t.Error("AuthReqID no longer returns the wire value")
	}
}

// TestSessionHandleKeepsItsWireValue pins what a SessionHandle prints:
// its String is its wire value, for a cookie or a form field, so fmt's
// v, s, q, x and X, Sprint and the templates print it; log/slog logs it
// as [REDACTED], and fmt's reflection fallback prints an address.
func TestSessionHandleKeepsItsWireValue(t *testing.T) {
	h := SessionHandle{value: fapi.NewSecret(renderHandle)}
	checkHandleRenderings(t, h, renderHandle)
	var page bytes.Buffer
	if err := htmltemplate.Must(htmltemplate.New("p").Parse(`<input value="{{.}}">`)).Execute(&page, h); err != nil || page.String() != `<input value="`+renderHandle+`">` {
		t.Errorf("html/template rendered %s, %v; want the wire value", page.String(), err)
	}
	if fmt.Sprint(h) != renderHandle || fmt.Sprintf("%s %v", h, h) != renderHandle+" "+renderHandle {
		t.Error("fmt no longer prints a SessionHandle's wire value")
	}
	if got := logged(h); !strings.Contains(got, "k=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
	if parsed, err := ParseSessionHandle(h.String()); err == nil && parsed != h {
		t.Error("ParseSessionHandle(h.String()) isn't h")
	}
}

// checkHandleRenderings fails t for any rendering of h, a handle whose
// String is its wire value raw, that prints raw other than through fmt
// calling that String: log/slog at the top of an attribute, fmt's
// reflection fallback and the encoders must not.
func checkHandleRenderings[T any](t *testing.T, h T, raw string) {
	t.Helper()
	for _, l := range rendertest.Leaks(h, []string{raw}) {
		topLevelSlog := strings.HasPrefix(l.Printer, "slog ") && l.Printer != "slog error attribute" && (l.Shape == "value" || l.Shape == "pointer")
		if l.Class != rendertest.Logging || topLevelSlog {
			t.Errorf("%T printed its value other than through String: %v", h, l)
		}
	}
}

func TestAuthorizationSessionPrintsNoHandle(t *testing.T) {
	u, err := fapi.ParseEndpointURL("https://as.example/authorize?client_id=client-1&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A" + renderRequestURI)
	if err != nil {
		t.Fatal(err)
	}
	s := AuthorizationSession{url: fapi.NewSecret(u.String()), handle: SessionHandle{value: fapi.NewSecret(renderHandle)}, expiresAt: time.Unix(1_900_000_000, 0).UTC()}
	rendertest.Check(t, s, []string{renderHandle, renderRequestURI})
	if s.URL() != u || (AuthorizationSession{}).URL() != (fapi.URL{}) {
		t.Errorf("URL() = %v, want %v back, and the zero URL for the zero session", s.URL(), u)
	}
	want := "{url:https://as.example/authorize?client_id=[REDACTED]&request_uri=[REDACTED] handle:[REDACTED] expiresAt:2030-03-17 17:46:40 +0000 UTC}"
	if got := fmt.Sprintf("%+v", s); got != want {
		t.Errorf("%%+v = %s\nwant  %s", got, want)
	}
	if got := logged(s); !strings.Contains(got, "k.URL=") || !strings.Contains(got, "k.Handle=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
}

// TestAuthorizationSessionURLParsesBack checks the URL an
// AuthorizationSession keeps as a string parses back to the one
// BeginAuthorization built: from an endpoint with a query of its own, a
// loopback endpoint over http, and an escaped path.
func TestAuthorizationSessionURLParsesBack(t *testing.T) {
	for _, raw := range []string{"https://as.example/authorize?tenant=a%20b", "http://127.0.0.1:8080/authorize", "https://as.example/a%2Fb/authorize"} {
		endpoint, err := fapi.ParseEndpointURL(raw, fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatal(err)
		}
		built := endpoint.WithAddedQuery(url.Values{"client_id": {"client-1"}, "request_uri": {"urn:ietf:params:oauth:request_uri:" + renderRequestURI}})
		if got := (AuthorizationSession{url: fapi.NewSecret(built.String())}).URL(); got != built {
			t.Errorf("URL() = %v, want %v", got, built)
		}
	}
}

func TestAuthorizationCallbackPrintsNoValue(t *testing.T) {
	cb := AuthorizationCallback{
		RawQuery: "code=" + renderCode + "&state=" + renderState + "&iss=https%3A%2F%2Fas.example",
		Session:  SessionHandle{value: fapi.NewSecret(renderHandle)},
	}
	rendertest.Check(t, cb, []string{renderHandle})
	// RawQuery is an exported string: fmt's reflection fallback and the
	// encoders print it, as they print any exported field.
	rendertest.Check(t, cb, []string{renderCode, renderState}, rendertest.Allow(rendertest.Fallback, rendertest.Encoding))
	if got := fmt.Sprintf("%+v", cb); got != "{RawQuery:code=[REDACTED]&state=[REDACTED]&iss=[REDACTED] Session:[REDACTED]}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(cb); !strings.Contains(got, `k.RawQuery="code=[REDACTED]&state=[REDACTED]&iss=[REDACTED]" k.Session=[REDACTED]`) {
		t.Errorf("slog = %s", got)
	}
}

func TestBeginBackchannelAuthenticationRequestPrintsNoHintToken(t *testing.T) {
	r := BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"}, LoginHintToken: renderHintToken, IDTokenHint: renderIDHint,
		BindingMessage: "W4SCT", RequestedExpiry: time.Minute,
	}
	// The hint tokens are exported strings: fmt's reflection fallback and
	// the encoders print them, as they print any exported field.
	rendertest.Check(t, r, []string{renderHintToken, renderIDHint}, rendertest.Allow(rendertest.Fallback, rendertest.Encoding))
	if got := fmt.Sprintf("%+v", r); !strings.Contains(got, "LoginHintToken:[REDACTED] IDTokenHint:[REDACTED]") || !strings.Contains(got, "BindingMessage:W4SCT") {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(r); !strings.Contains(got, "k.LoginHintToken=[REDACTED] k.IDTokenHint=[REDACTED]") || !strings.Contains(got, "k.BindingMessage=W4SCT") {
		t.Errorf("slog = %s", got)
	}
}

// logged is what log/slog's text handler writes for v as attribute k.
func logged(v any) string {
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "k", v)
	return buf.String()
}

// TestBeginAuthorizationRequestLogsNoExtensionValue checks log/slog's
// JSON handler logs an authorization request's extension parameters by
// name, rather than encoding them with MarshalJSON.
func TestBeginAuthorizationRequestLogsNoExtensionValue(t *testing.T) {
	var values extension.Values
	def := extension.Definition[string]{Sensitivity: extension.Sensitive, Name: "x_otp", Cardinality: extension.Single, AllowedSources: extension.SourcePlainParameter, MaxBytes: 64}
	if err := extension.Set(&values, def, renderNonce); err != nil {
		t.Fatal(err)
	}
	r := BeginAuthorizationRequest{Scope: []string{"openid"}, Extensions: values}
	// encoding/json of the request itself carries the value: MarshalJSON
	// is Values' storage encoding.
	rendertest.Check(t, r, []string{renderNonce}, rendertest.Allow(rendertest.Encoding))
	var js bytes.Buffer
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "k", r)
	if !strings.Contains(js.String(), `"Extensions":{"x_otp":"[REDACTED]"}`) || !strings.Contains(js.String(), `"Scope":["openid"]`) {
		t.Errorf("slog JSON = %s", js.String())
	}
}

// TestShadowsKeepTheirTypesFields checks each rendering's shadow has the
// fields of the type it prints for, in order.
func TestShadowsKeepTheirTypesFields(t *testing.T) {
	for real, shadow := range map[reflect.Type]reflect.Type{
		reflect.TypeFor[ValidatedAuthorizationResponse]():        reflect.TypeFor[validatedAuthorizationResponseShadow](),
		reflect.TypeFor[ResourceClient]():                        reflect.TypeFor[resourceClientShadow](),
		reflect.TypeFor[BackchannelAuthenticationSession]():      reflect.TypeFor[backchannelAuthenticationSessionShadow](),
		reflect.TypeFor[BackchannelNotification]():               reflect.TypeFor[backchannelNotificationShadow](),
		reflect.TypeFor[AuthorizationSession]():                  reflect.TypeFor[authorizationSessionShadow](),
		reflect.TypeFor[AuthorizationCallback]():                 reflect.TypeFor[authorizationCallbackShadow](),
		reflect.TypeFor[BeginBackchannelAuthenticationRequest](): reflect.TypeFor[beginBackchannelAuthenticationRequestShadow](),
	} {
		rendertest.CheckShadow(t, real, shadow)
	}
}

// TestStringIsTheVRendering pins each redacting type's String to its %v
// rendering, for a logger that prints a fmt.Stringer rather than
// formatting it.
func TestStringIsTheVRendering(t *testing.T) {
	for _, v := range []fmt.Stringer{
		renderResponse(), ResourceClient{token: fapi.NewSecret(renderToken)}, renderBackchannelSession(),
		BackchannelNotification{authReqID: fapi.NewSecret(renderAuthReqID), token: fapi.NewSecret(renderNotify)},
		AuthorizationSession{handle: SessionHandle{value: fapi.NewSecret(renderHandle)}},
		AuthorizationCallback{RawQuery: "code=" + renderCode},
		BeginBackchannelAuthenticationRequest{LoginHintToken: renderHintToken},
	} {
		if got, want := v.String(), fmt.Sprintf("%v", v); got != want {
			t.Errorf("%T.String() = %s, want its %%v rendering %s", v, got, want)
		}
	}
}
