package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/redact"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

// Sentinel values no rendering of the type holding them may print.
const (
	renderInteractionHandle = "INTERACTION-HANDLE-SECRET-0001"
	renderCIBAHandle        = "CIBA-HANDLE-SECRET-0002"
	renderAuthReqID         = "AUTH-REQ-ID-SECRET-0003"
	renderCode              = "AUTH-CODE-SECRET-0004"
	renderState             = "STATE-SECRET-0005"
	renderHintToken         = "LOGIN-HINT-TOKEN-SECRET-0006"
	renderIDTokenHint       = "ID-TOKEN-HINT-SECRET-0007"
	renderOTP               = "SENSITIVE-OTP-SECRET-0008"
	renderPushedRequestURI  = "urn:ietf:params:oauth:request_uri:PUSHED-REQUEST-URI-SECRET-0009"
)

var renderOTPDef = extension.Definition[string]{
	Sensitivity: extension.Sensitive, Name: "x_otp", Cardinality: extension.Single,
	AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
}

func renderExtensions(t *testing.T) extension.Values {
	t.Helper()
	var values extension.Values
	if err := extension.Set(&values, renderOTPDef, renderOTP); err != nil {
		t.Fatal(err)
	}
	return values
}

func renderInteraction(t *testing.T) InteractionRequest {
	t.Helper()
	return InteractionRequest{ClientID: "client-1", Scope: []string{"openid"}, Extensions: renderExtensions(t)}
}

func renderBackchannelInteraction(t *testing.T) BackchannelInteractionRequest {
	t.Helper()
	return BackchannelInteractionRequest{
		ClientID: "client-1", Scope: []string{"openid"}, BindingMessage: "W4SCT",
		Hints:      BackchannelAuthenticationHints{LoginHintToken: renderHintToken, IDTokenHint: renderIDTokenHint},
		Extensions: renderExtensions(t),
	}
}

// TestHandlesKeepTheirWireValue pins what a handle prints: its String is
// its wire value, for a cookie or a form field, so fmt's v, s, q, x and
// X, Sprint and the templates print it; log/slog logs it as
// [REDACTED], and fmt's reflection fallback prints an address.
func TestHandlesKeepTheirWireValue(t *testing.T) {
	checkHandle(t, InteractionHandle{value: redact.MakeHandle(renderInteractionHandle)}, renderInteractionHandle)
	checkHandle(t, BackchannelAuthenticationHandle{value: redact.MakeHandle(renderCIBAHandle)}, renderCIBAHandle)
	checkHandle(t, AuthReqID{value: redact.MakeHandle(renderAuthReqID)}, renderAuthReqID)
	// A request_uri is a bearer value until its interaction completes,
	// and its String its wire value, as a handle's is.
	checkHandle(t, RequestURI{value: redact.MakeHandle(renderPushedRequestURI)}, renderPushedRequestURI)
	if h, err := ParseInteractionHandle(renderInteractionHandle); err != nil || h.String() != renderInteractionHandle || h != (InteractionHandle{value: redact.MakeHandle(renderInteractionHandle)}) {
		t.Errorf("ParseInteractionHandle(String()) = %v, %v; want the handle back", h, err)
	}
}

func TestPushAuthorizationResultPrintsNoRequestURI(t *testing.T) {
	r := PushAuthorizationResult{RequestURI: RequestURI{value: redact.MakeHandle(renderPushedRequestURI)}, ExpiresIn: time.Minute, NextDPoPNonce: "dpop-nonce-1"}
	rendertest.Check(t, r, []string{renderPushedRequestURI})
	if got := fmt.Sprintf("%+v", r); got != "{RequestURI:[REDACTED] ExpiresIn:1m0s NextDPoPNonce:dpop-nonce-1}" || r.String() != fmt.Sprint(r) {
		t.Errorf("%%+v = %s, String() = %s", got, r.String())
	}
	if got := fmt.Sprintf("%#v", r); !strings.HasPrefix(got, `server.PushAuthorizationResult{RequestURI:"[REDACTED]", ExpiresIn:60000000000`) {
		t.Errorf("%%#v = %s", got)
	}
	if got := logged(r); !strings.Contains(got, "k.RequestURI=[REDACTED] k.ExpiresIn=1m0s k.NextDPoPNonce=dpop-nonce-1") {
		t.Errorf("slog = %s", got)
	}
	if r.RequestURI.String() != renderPushedRequestURI || fmt.Sprint(PushAuthorizationResult{}) != "{ 0s }" {
		t.Errorf("the request_uri's wire value is %q; the zero result prints %s", r.RequestURI.String(), PushAuthorizationResult{})
	}
}

// checkHandle fails t for any rendering of h that prints raw other than
// through fmt calling its String, and unless fmt, html/template and
// log/slog print what a handle's contract says.
func checkHandle[T interface {
	fmt.Stringer
	slog.LogValuer
}](t *testing.T, h T, raw string) {
	t.Helper()
	for _, l := range rendertest.Leaks(h, []string{raw}) {
		topLevelSlog := strings.HasPrefix(l.Printer, "slog ") && l.Printer != "slog error attribute" && (l.Shape == "value" || l.Shape == "pointer")
		if l.Class != rendertest.Logging || topLevelSlog {
			t.Errorf("%T printed its value other than through String: %v", h, l)
		}
	}
	var page bytes.Buffer
	if err := htmltemplate.Must(htmltemplate.New("p").Parse(`<input value="{{.}}">`)).Execute(&page, h); err != nil || page.String() != `<input value="`+raw+`">` {
		t.Errorf("html/template rendered %s, %v; want the wire value", page.String(), err)
	}
	if fmt.Sprint(h) != raw || fmt.Sprintf("%v", h) != raw {
		t.Errorf("fmt no longer prints %T's wire value", h)
	}
	if got := logged(h); !strings.Contains(got, "k=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
}

func TestInteractionRequiredPrintsNoHandleOrValue(t *testing.T) {
	a := InteractionRequired{Handle: InteractionHandle{value: redact.MakeHandle(renderInteractionHandle)}, Interaction: renderInteraction(t), ExpiresAt: time.Unix(1_900_000_000, 0).UTC()}
	rendertest.Check(t, a, []string{renderInteractionHandle})
	// An application keeps an interaction in its session as JSON, through
	// MarshalText, its storage encoding, which carries every value.
	rendertest.Check(t, a, []string{renderOTP}, rendertest.Allow(rendertest.Encoding))
	if got := fmt.Sprintf("%+v", a); !strings.HasPrefix(got, "{Handle:[REDACTED] Interaction:{ClientID:client-1") || !strings.Contains(got, "Extensions:map[x_otp:[REDACTED]]") {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(a); !strings.Contains(got, "k.Handle=[REDACTED]") || !strings.Contains(got, "k.Interaction.Extensions.x_otp=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
}

// TestInteractionRequestLogsNoValue checks log/slog logs an interaction
// as a group of its fields, rather than through MarshalText, the storage
// encoding, which carries the Sensitive value.
func TestInteractionRequestLogsNoValue(t *testing.T) {
	r := renderInteraction(t)
	// fmt prints the fields themselves, and Values its names; json is the
	// storage encoding, MarshalText.
	rendertest.Check(t, r, []string{renderOTP}, rendertest.Allow(rendertest.Encoding))
	var js bytes.Buffer
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "interaction", r)
	if !strings.Contains(js.String(), `"interaction":{"ClientID":"client-1","Scope":["openid"]`) || !strings.Contains(js.String(), `"Extensions":{"x_otp":"[REDACTED]"}`) {
		t.Errorf("slog JSON = %s", js.String())
	}
	encoded, err := r.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ParseInteractionRequest(string(encoded))
	if got, ok := extension.Get(restored.Extensions, renderOTPDef); err != nil || !ok || got != renderOTP {
		t.Errorf("the storage encoding no longer restores the Sensitive value: %q, %v, %v", got, ok, err)
	}
}

func TestBackchannelInteractionRequiredPrintsNoSecret(t *testing.T) {
	a := BackchannelInteractionRequired{
		Handle: BackchannelAuthenticationHandle{value: redact.MakeHandle(renderCIBAHandle)}, AuthReqID: AuthReqID{value: redact.MakeHandle(renderAuthReqID)},
		ExpiresIn: time.Minute, Interval: 5 * time.Second, Interaction: renderBackchannelInteraction(t),
	}
	rendertest.Check(t, a, []string{renderCIBAHandle, renderAuthReqID})
	rendertest.Check(t, a, []string{renderOTP}, rendertest.Allow(rendertest.Encoding))
	// The hint tokens are exported strings of the interaction: fmt's
	// reflection fallback and the encoders print them, as any exported
	// field.
	rendertest.Check(t, a, []string{renderHintToken, renderIDTokenHint}, rendertest.Allow(rendertest.Fallback, rendertest.Encoding))
	want := "{Handle:[REDACTED] AuthReqID:[REDACTED] ExpiresIn:1m0s Interval:5s Interaction:{ClientID:client-1 Scope:[openid] Hints:{LoginHint: LoginHintToken:[REDACTED] IDTokenHint:[REDACTED]}"
	if got := fmt.Sprintf("%+v", a); !strings.HasPrefix(got, want) {
		t.Errorf("%%+v = %s\nwant prefix %s", got, want)
	}
	if got := logged(a); !strings.Contains(got, "k.AuthReqID=[REDACTED]") || !strings.Contains(got, "k.Interaction.Hints.LoginHintToken=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
	var w bytes.Buffer
	if err := json.NewEncoder(&w).Encode(a.AuthReqID.String()); err != nil || !strings.Contains(w.String(), renderAuthReqID) {
		t.Error("AuthReqID.String no longer gives the wire value WriteJSON sends")
	}
}

func TestPendingBackchannelInteractionPrintsItsIDNotItsHandle(t *testing.T) {
	p := PendingBackchannelInteraction{ID: "pending-id-1", Handle: BackchannelAuthenticationHandle{value: redact.MakeHandle(renderCIBAHandle)}, Interaction: renderBackchannelInteraction(t), ExpiresAt: time.Unix(1_900_000_000, 0).UTC()}
	rendertest.Check(t, p, []string{renderCIBAHandle})
	rendertest.Check(t, p, []string{renderOTP}, rendertest.Allow(rendertest.Encoding))
	if got := fmt.Sprintf("%+v", p); !strings.HasPrefix(got, "{ID:pending-id-1 Handle:[REDACTED] Interaction:") {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(p); !strings.Contains(got, "k.ID=pending-id-1 k.Handle=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
}

func TestBackchannelAuthenticationHintsPrintNoToken(t *testing.T) {
	h := BackchannelAuthenticationHints{LoginHint: "user@example.com", LoginHintToken: renderHintToken, IDTokenHint: renderIDTokenHint}
	rendertest.Check(t, h, []string{renderHintToken, renderIDTokenHint}, rendertest.Allow(rendertest.Fallback, rendertest.Encoding))
	if got := fmt.Sprintf("%+v", h); got != "{LoginHint:user@example.com LoginHintToken:[REDACTED] IDTokenHint:[REDACTED]}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(h); !strings.Contains(got, "k.LoginHint=user@example.com k.LoginHintToken=[REDACTED] k.IDTokenHint=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
	if got := fmt.Sprintf("%+v", BackchannelAuthenticationHints{LoginHint: "user@example.com"}); got != "{LoginHint:user@example.com LoginHintToken: IDTokenHint:}" {
		t.Errorf("hints without tokens print %s, want empty placeholders", got)
	}
}

func TestAuthorizationRedirectPrintsNoCode(t *testing.T) {
	for _, raw := range []string{
		"https://rp.example/cb?code=" + renderCode + "&state=" + renderState + "&iss=https%3A%2F%2Fas.example",
		"https://rp.example/cb?registered=1&response=" + renderCode + "." + renderState,
		"com.example.app:/oauth2redirect?code=" + renderCode + "&state=" + renderState,
		"http://127.0.0.1:5000/cb?code=" + renderCode + "&state=" + renderState,
	} {
		destination, err := fapi.ParseRedirectURL(raw, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme())
		if err != nil {
			t.Fatal(err)
		}
		r := AuthorizationRedirect{destination: fapi.NewSecret(destination.String())}
		if r.Destination() != destination {
			t.Errorf("Destination() = %s, want %s back", r.Destination(), destination)
		}
		rendertest.Check(t, r, []string{renderCode, renderState})
	}
	r := AuthorizationRedirect{destination: fapi.NewSecret("https://rp.example/cb?code=" + renderCode + "&state=" + renderState)}
	if got := fmt.Sprintf("%+v", r); got != "{destination:https://rp.example/cb?code=[REDACTED]&state=[REDACTED]}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(r); !strings.Contains(got, `k.Destination="https://rp.example/cb?code=[REDACTED]&state=[REDACTED]"`) {
		t.Errorf("slog = %s", got)
	}
	if !(AuthorizationRedirect{}).Destination().IsZero() || fmt.Sprint(AuthorizationRedirect{}) != "{}" {
		t.Error("the zero AuthorizationRedirect has a destination")
	}
}

func TestRedirectResponsePrintsNoQueryValue(t *testing.T) {
	destination, err := fapi.ParseRedirectURL("https://rp.example/cb?code=" + renderCode)
	if err != nil {
		t.Fatal(err)
	}
	r := RedirectResponse{Destination: destination}
	// Destination is an exported fapi.URL: fmt's reflection fallback
	// prints it whole, and encoding/json as its string.
	rendertest.Check(t, r, []string{renderCode}, rendertest.Allow(rendertest.Fallback, rendertest.Encoding))
	if got := fmt.Sprintf("%+v", r); got != "{Destination:https://rp.example/cb?code=[REDACTED]}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(r); !strings.Contains(got, `k.Destination="https://rp.example/cb?code=[REDACTED]"`) {
		t.Errorf("slog = %s", got)
	}
	if got := fmt.Sprint(RedirectResponse{}); got != "{}" {
		t.Errorf("the zero RedirectResponse prints %s", got)
	}
}

// logged is what log/slog's text handler writes for v as attribute k.
func logged(v any) string {
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "k", v)
	return buf.String()
}

// TestRedirectSummaryOfANonURL pins that a destination that isn't an
// absolute URL, which buildAuthorizationResponse never makes, prints as
// [REDACTED] rather than as a path.
func TestRedirectSummaryOfANonURL(t *testing.T) {
	for raw, want := range map[string]string{"": "", renderCode: "[REDACTED]", "%zz" + renderCode: "[REDACTED]"} {
		if got := redirectSummary(raw); got != want {
			t.Errorf("redirectSummary(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestShadowsKeepTheirTypesFields checks each rendering's shadow has the
// fields of the type it prints for, in order.
func TestShadowsKeepTheirTypesFields(t *testing.T) {
	for typ, shadow := range map[reflect.Type]reflect.Type{
		reflect.TypeFor[InteractionRequired]():                      reflect.TypeFor[interactionRequiredShadow](),
		reflect.TypeFor[BackchannelInteractionRequired]():           reflect.TypeFor[backchannelInteractionRequiredShadow](),
		reflect.TypeFor[PendingBackchannelInteraction]():            reflect.TypeFor[pendingBackchannelInteractionShadow](),
		reflect.TypeFor[PushAuthorizationResult]():                  reflect.TypeFor[pushAuthorizationResultShadow](),
		reflect.TypeFor[AuthorizationRedirect]():                    reflect.TypeFor[authorizationRedirectShadow](),
		reflect.TypeFor[RedirectResponse]():                         reflect.TypeFor[redirectResponseShadow](),
		reflect.TypeFor[BackchannelAuthenticationHints]():           reflect.TypeFor[backchannelAuthenticationHintsShadow](),
		reflect.TypeFor[FormParameter]():                            reflect.TypeFor[formParameterShadow](),
		reflect.TypeFor[FormRequest]():                              reflect.TypeFor[formRequestShadow](),
		reflect.TypeFor[httpRequestParts]():                         reflect.TypeFor[httpRequestPartsShadow](),
		reflect.TypeFor[PushAuthorizationRequest]():                 reflect.TypeFor[httpRequestPartsShadow](),
		reflect.TypeFor[AuthorizationCodeExchangeRequest]():         reflect.TypeFor[httpRequestPartsShadow](),
		reflect.TypeFor[RefreshTokenRequest]():                      reflect.TypeFor[httpRequestPartsShadow](),
		reflect.TypeFor[ClientCredentialsTokenRequest]():            reflect.TypeFor[httpRequestPartsShadow](),
		reflect.TypeFor[BackchannelTokenExchangeRequest]():          reflect.TypeFor[httpRequestPartsShadow](),
		reflect.TypeFor[BeginBackchannelAuthenticationRequest]():    reflect.TypeFor[httpRequestPartsShadow](),
		reflect.TypeFor[TokenEndpointRequest]():                     reflect.TypeFor[tokenEndpointRequestShadow](),
		reflect.TypeFor[TokenRevocationRequest]():                   reflect.TypeFor[tokenRevocationRequestShadow](),
		reflect.TypeFor[AttestedClientAuthenticationRequest]():      reflect.TypeFor[attestedClientAuthenticationRequestShadow](),
		reflect.TypeFor[BeginAuthorizationRequest]():                reflect.TypeFor[beginAuthorizationRequestShadow](),
		reflect.TypeFor[CompleteAuthorizationRequest]():             reflect.TypeFor[completeAuthorizationRequestShadow](),
		reflect.TypeFor[CompleteBackchannelAuthenticationRequest](): reflect.TypeFor[completeAuthorizationRequestShadow](),
		reflect.TypeFor[BackchannelNotification]():                  reflect.TypeFor[backchannelNotificationShadow](),
	} {
		rendertest.CheckShadow(t, typ, shadow)
	}
}

// TestStringIsTheVRendering pins each result's String to its %v
// rendering, for a logger that prints a fmt.Stringer rather than
// formatting it.
func TestStringIsTheVRendering(t *testing.T) {
	for _, v := range []fmt.Stringer{
		InteractionRequired{Handle: InteractionHandle{value: redact.MakeHandle(renderInteractionHandle)}},
		BackchannelInteractionRequired{AuthReqID: AuthReqID{value: redact.MakeHandle(renderAuthReqID)}},
		PendingBackchannelInteraction{ID: "id", Handle: BackchannelAuthenticationHandle{value: redact.MakeHandle(renderCIBAHandle)}},
		PushAuthorizationResult{RequestURI: RequestURI{value: redact.MakeHandle(renderPushedRequestURI)}},
		AuthorizationRedirect{destination: fapi.NewSecret("https://rp.example/cb?code=" + renderCode)},
		RedirectResponse{}, BackchannelAuthenticationHints{LoginHintToken: renderHintToken},
	} {
		if got, want := v.String(), fmt.Sprintf("%v", v); got != want {
			t.Errorf("%T.String() = %s, want its %%v rendering %s", v, got, want)
		}
	}
}
