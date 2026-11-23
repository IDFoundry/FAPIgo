package server

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

// Sentinel credentials an inbound request carries.
const (
	renderRefreshToken = "REFRESH-TOKEN-SECRET-0101"
	renderVerifier     = "CODE-VERIFIER-SECRET-0102"
	renderAssertion    = "CLIENT-ASSERTION-SECRET-0103"
	renderProof        = "DPOP-PROOF-SECRET-0104"
	renderAttestation  = "CLIENT-ATTESTATION-SECRET-0105"
	renderRequest      = "REQUEST-OBJECT-SECRET-0106"
	renderRequestURI   = "REQUEST-URI-SECRET-0107"
	renderToken        = "REVOKED-TOKEN-SECRET-0108"
)

// renderForm is a token request form carrying every kind of credential a
// form can, and parameters whose values print.
var renderForm = FormRequest{Parameters: []FormParameter{
	{Name: "grant_type", Value: "authorization_code"},
	{Name: "code", Value: renderCode},
	{Name: "code_verifier", Value: renderVerifier},
	{Name: "refresh_token", Value: renderRefreshToken},
	{Name: "client_assertion", Value: renderAssertion},
	{Name: "client_assertion_type", Value: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
	{Name: "auth_req_id", Value: renderAuthReqID},
	{Name: "request", Value: renderRequest},
	{Name: "x_unregistered", Value: renderOTP},
	{Name: "scope", Value: "openid accounts"},
}}

// renderFormSecrets are renderForm's credentials.
var renderFormSecrets = []string{renderCode, renderVerifier, renderRefreshToken, renderAssertion, renderAuthReqID, renderRequest, renderOTP}

func renderParts() httpRequestParts {
	return httpRequestParts{
		HTTP: renderForm, DPoPProofs: []string{renderProof},
		ClientAttestations: []string{renderAttestation}, ClientAttestationPoPs: []string{renderAttestation + "-POP"},
		PeerCertificate: &x509.Certificate{Subject: pkix.Name{CommonName: "client-1"}, Raw: []byte("certificate")},
	}
}

// inboundSecrets are what renderParts carries besides its form.
var inboundSecrets = append([]string{renderProof, renderAttestation}, renderFormSecrets...)

// exportedResidual is what an inbound request's own exported fields
// hold raw, by design: fmt's reflection fallback and the encoders print
// them as they print any exported field.
var exportedResidual = rendertest.Allow(rendertest.Fallback, rendertest.Encoding)

func TestFormParameterPrintsOnlyAllowedValues(t *testing.T) {
	for name := range formValueAllowlist {
		if got := fmt.Sprint(FormParameter{Name: name, Value: "v"}); got != "{"+name+" v}" {
			t.Errorf("allowlisted %s prints %s, want its value", name, got)
		}
	}
	for _, name := range []string{
		"code", "code_verifier", "refresh_token", "token", "client_assertion", "auth_req_id",
		"client_notification_token", "request", "request_uri", "state", "nonce", "login_hint",
		"login_hint_token", "id_token_hint", "binding_message", "authorization_details", "claims", "x_otp",
	} {
		p := FormParameter{Name: name, Value: renderOTP}
		if got := fmt.Sprintf("%+v", p); got != "{Name:"+name+" Value:[REDACTED]}" {
			t.Errorf("%s prints %s, want its value redacted", name, got)
		}
		if got := p.LogValue().String(); got != name+"=[REDACTED]" {
			t.Errorf("%s logs %s", name, got)
		}
	}
	rendertest.Check(t, FormParameter{Name: "code", Value: renderCode}, []string{renderCode}, exportedResidual)
	if got := fmt.Sprint(FormParameter{Name: "evil\nlevel=INFO", Value: "x"}, FormParameter{Name: "scope", Value: "a\nb"}, FormParameter{Name: "code"}); got != `{"evil\nlevel=INFO" [REDACTED]} {scope "a\nb"} {code }` {
		t.Errorf("a name or value that could forge a log line, or an empty value, prints as %s", got)
	}
}

func TestFormRequestPrintsNoCredential(t *testing.T) {
	rendertest.Check(t, renderForm, renderFormSecrets, exportedResidual)
	if got := fmt.Sprintf("%#v", FormRequest{Parameters: []FormParameter{{Name: "code", Value: renderCode}}}); got != `server.FormRequest{Parameters:[]server.FormParameter{server.FormParameter{Name:"code", Value:"[REDACTED]"}}}` {
		t.Errorf("%%#v = %s", got)
	}
	if got := logged(renderForm); !strings.Contains(got, `k.Parameters="[grant_type=authorization_code code=[REDACTED]`) {
		t.Errorf("slog = %s", got)
	}
	if got := fmt.Sprint(FormRequest{}); got != "{[]}" {
		t.Errorf("an empty form prints %s", got)
	}
}

// TestTypedRequestsPrintNoCredential renders each request type that
// shares httpRequestParts' layout, as an adapter fills it.
func TestTypedRequestsPrintNoCredential(t *testing.T) {
	parts := renderParts()
	rendertest.Check(t, PushAuthorizationRequest(parts), inboundSecrets, exportedResidual)
	rendertest.Check(t, AuthorizationCodeExchangeRequest(parts), inboundSecrets, exportedResidual, rendertest.Quick())
	rendertest.Check(t, RefreshTokenRequest(parts), inboundSecrets, exportedResidual, rendertest.Quick())
	rendertest.Check(t, ClientCredentialsTokenRequest(parts), inboundSecrets, exportedResidual, rendertest.Quick())
	rendertest.Check(t, BackchannelTokenExchangeRequest(parts), inboundSecrets, exportedResidual, rendertest.Quick())
	rendertest.Check(t, BeginBackchannelAuthenticationRequest(parts), inboundSecrets, exportedResidual, rendertest.Quick())

	want := "{HTTP:{Parameters:[{Name:grant_type Value:authorization_code} {Name:code Value:[REDACTED]}"
	for name, got := range map[string]string{
		"PushAuthorizationRequest":              fmt.Sprintf("%+v", PushAuthorizationRequest(parts)),
		"AuthorizationCodeExchangeRequest":      AuthorizationCodeExchangeRequest(parts).String(),
		"RefreshTokenRequest":                   logged(RefreshTokenRequest(parts)),
		"ClientCredentialsTokenRequest":         fmt.Sprintf("%#v", ClientCredentialsTokenRequest(parts)),
		"BackchannelTokenExchangeRequest":       fmt.Sprint(BackchannelTokenExchangeRequest(parts)),
		"BeginBackchannelAuthenticationRequest": logged(BeginBackchannelAuthenticationRequest(parts)),
	} {
		if strings.Contains(got, renderCode) || !strings.Contains(got, "[REDACTED]") || !strings.Contains(got, "authorization_code") {
			t.Errorf("%s renders as %s", name, got)
		}
	}
	if got := fmt.Sprintf("%+v", PushAuthorizationRequest(parts)); !strings.HasPrefix(got, want) || !strings.HasSuffix(got, "DPoPProofs:[[REDACTED]] ClientAttestations:[[REDACTED]] ClientAttestationPoPs:[[REDACTED]] PeerCertificate:CN=client-1}") {
		t.Errorf("%%+v = %s", got)
	}
	if got := fmt.Sprintf("%#v", ClientCredentialsTokenRequest(parts)); !strings.HasPrefix(got, "server.ClientCredentialsTokenRequest{HTTP:server.FormRequest{") {
		t.Errorf("%%#v = %s, want the real type's name", got)
	}
}

// TestTokenEndpointRequestPrintsNoCredential reads a token request from
// HTTP, as an adapter does, and renders it in every position, its
// reflection fallback included: it has no exported field, and holds its
// form behind a pointer to a pointer, which fmt's reflection fallback
// prints as an address.
func TestTokenEndpointRequestPrintsNoCredential(t *testing.T) {
	r := httptest.NewRequest("POST", "https://as.example/token", strings.NewReader(
		"grant_type=refresh_token&refresh_token="+renderRefreshToken+"&client_assertion_type=x&client_assertion="+renderAssertion))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("DPoP", renderProof)
	req, err := TokenEndpointRequestFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{renderRefreshToken, renderAssertion, renderProof}
	rendertest.Check(t, req, secrets)
	// The shapes an embedder's own code reaches it in, by name: its
	// struct's unexported field (and log/slog's text handler printing that
	// struct), %p, and %w, in Sprintf and in Errorf.
	pointerFormat, wrapFormat := "%p", "%w"
	held := struct{ r TokenEndpointRequest }{req}
	for name, got := range map[string]string{
		"an unexported field": fmt.Sprintf("%+v", held), "an unexported field, logged": logged(held),
		"%p": fmt.Sprintf(pointerFormat, req), "%w": fmt.Sprintf(wrapFormat, req), "Errorf %w": fmt.Errorf(wrapFormat, req).Error(),
	} {
		if !strings.Contains(got, "0x") || containsAny(got, secrets) {
			t.Errorf("%s prints %s, want an address and no value", name, got)
		}
	}
	if got := fmt.Sprintf("%+v", req); got != "{parts:{HTTP:{Parameters:[{Name:grant_type Value:refresh_token} {Name:refresh_token Value:[REDACTED]} {Name:client_assertion_type Value:x} {Name:client_assertion Value:[REDACTED]}]} DPoPProofs:[[REDACTED]] ClientAttestations:[] ClientAttestationPoPs:[] PeerCertificate:}}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := fmt.Sprintf("%#v", req); !strings.HasPrefix(got, "server.TokenEndpointRequest{parts:server.httpRequestParts{HTTP:server.FormRequest{") {
		t.Errorf("%%#v = %s", got)
	}
	if req.String() != fmt.Sprint(req) || !strings.Contains(logged(req), "k.HTTP.Parameters=") {
		t.Errorf("String() = %s, slog = %s", req.String(), logged(req))
	}
}

// containsAny reports whether s contains any of values.
func containsAny(s string, values []string) bool {
	for _, v := range values {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

// TestTokenEndpointRequestKeepsValueSemantics checks the holder
// TokenEndpointRequest keeps its parts in: the zero request holds none,
// and SetPeerCertificate changes the request it is called on, never a
// copy made before, as when the request held its parts by value.
func TestTokenEndpointRequestKeepsValueSemantics(t *testing.T) {
	var zero TokenEndpointRequest
	if zero.GrantType() != "" || zero.AuthorizationCodeExchange().HTTP.Parameters != nil || fmt.Sprint(zero) != fmt.Sprint(tokenEndpointRequestShadow{}) {
		t.Errorf("the zero TokenEndpointRequest holds %v", zero)
	}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "client-1"}}
	zero.SetPeerCertificate(cert)
	if zero.ClientCredentials().PeerCertificate != cert || zero.GrantType() != "" {
		t.Error("SetPeerCertificate on the zero request didn't keep the certificate")
	}
	req := TokenEndpointRequest{parts: holdParts(renderParts())}
	copied := req
	req.SetPeerCertificate(cert)
	if copied.RefreshToken().PeerCertificate == cert || req.RefreshToken().PeerCertificate != cert {
		t.Error("SetPeerCertificate changed a copy made before it, or not the request it was called on")
	}
}

func TestOtherRequestsPrintNoCredential(t *testing.T) {
	revocation := TokenRevocationRequest{
		HTTP:               FormRequest{Parameters: []FormParameter{{Name: "token", Value: renderToken}, {Name: "token_type_hint", Value: "refresh_token"}}},
		ClientAttestations: []string{renderAttestation}, ClientAttestationPoPs: []string{renderAttestation + "-POP"},
	}
	rendertest.Check(t, revocation, []string{renderToken, renderAttestation}, exportedResidual)
	if got := fmt.Sprintf("%+v", revocation); got != "{HTTP:{Parameters:[{Name:token Value:[REDACTED]} {Name:token_type_hint Value:refresh_token}]} ClientAttestations:[[REDACTED]] ClientAttestationPoPs:[[REDACTED]] PeerCertificate:}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(revocation); !strings.Contains(got, "k.ClientAttestations=[[REDACTED]]") || strings.Contains(got, renderToken) {
		t.Errorf("slog = %s", got)
	}

	attested := AttestedClientAuthenticationRequest{ClientAttestations: []string{renderAttestation}, ClientAttestationPoPs: []string{renderAttestation + "-POP"}, ClientID: "client-1"}
	rendertest.Check(t, attested, []string{renderAttestation}, exportedResidual)
	if got := fmt.Sprintf("%+v", attested); got != "{ClientAttestations:[[REDACTED]] ClientAttestationPoPs:[[REDACTED]] ClientID:client-1 malformed:false otherClientAuth:false}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(attested); !strings.Contains(got, "k.ClientID=client-1") || strings.Contains(got, renderAttestation) {
		t.Errorf("slog = %s", got)
	}

	begin := BeginAuthorizationRequest{RequestURI: "urn:ietf:params:oauth:request_uri:" + renderRequestURI, ClientID: "client-1", Request: renderRequest}
	rendertest.Check(t, begin, []string{renderRequestURI, renderRequest}, exportedResidual)
	if got := fmt.Sprintf("%+v", begin); got != "{RequestURI:[REDACTED] ClientID:client-1 Request:[REDACTED]}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(begin); !strings.Contains(got, "k.RequestURI=[REDACTED] k.ClientID=client-1 k.Request=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
}

// TestRequestsQuoteWhatTheClientChose checks that what a client chose,
// and a rendering prints, can't forge a log line: a certificate's
// subject, which is a self-signed certificate's client's to choose and
// which pkix.Name's String leaves unescaped, and a request's client_id
// print %q-quoted when they hold a newline. log/slog's handlers escape
// what they log themselves.
func TestRequestsQuoteWhatTheClientChose(t *testing.T) {
	const forged = "client-1\nlevel=INFO msg=forged"
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: forged}}
	pushed := PushAuthorizationRequest{PeerCertificate: cert}
	attested := AttestedClientAuthenticationRequest{ClientID: forged}
	begin := BeginAuthorizationRequest{ClientID: fapi.ClientID(forged)}
	for name, got := range map[string]string{
		"PushAuthorizationRequest":            fmt.Sprintf("%+v", pushed),
		"TokenRevocationRequest":              fmt.Sprint(TokenRevocationRequest{PeerCertificate: cert}),
		"AttestedClientAuthenticationRequest": fmt.Sprintf("%v", attested),
		"BeginAuthorizationRequest":           fmt.Sprintf("%+v", begin),
	} {
		if strings.Contains(got, "\n") || !strings.Contains(got, `client-1\nlevel=INFO msg=forged"`) {
			t.Errorf("%s prints %q, want the value quoted", name, got)
		}
	}
	for _, v := range []any{pushed, attested, begin} {
		if got := logged(v); strings.Count(got, "\n") != 1 {
			t.Errorf("slog of %T = %q, want one line", v, got)
		}
	}
}

func TestCompletionRequestsPrintNoHandle(t *testing.T) {
	complete := CompleteAuthorizationRequest{Handle: InteractionHandle{value: fapi.NewSecret(renderInteractionHandle)}, Result: Deny("the user declined")}
	rendertest.Check(t, complete, []string{renderInteractionHandle})
	if got := fmt.Sprintf("%+v", complete); !strings.HasPrefix(got, "{Handle:[REDACTED] Result:") || complete.String() != fmt.Sprint(complete) {
		t.Errorf("%%+v = %s", got)
	}
	ciba := CompleteBackchannelAuthenticationRequest{Handle: BackchannelAuthenticationHandle{value: fapi.NewSecret(renderCIBAHandle)}, Result: Deny("the user declined")}
	rendertest.Check(t, ciba, []string{renderCIBAHandle})
	if got := fmt.Sprintf("%#v", ciba); !strings.HasPrefix(got, `server.CompleteBackchannelAuthenticationRequest{Handle:"[REDACTED]"`) || ciba.String() != fmt.Sprint(ciba) {
		t.Errorf("%%#v = %s", got)
	}
	for _, got := range []string{logged(complete), logged(ciba)} {
		if !strings.Contains(got, "k.Handle=[REDACTED]") || !strings.Contains(got, "the user declined") {
			t.Errorf("slog = %s", got)
		}
	}
}

func TestBackchannelNotificationPrintsNoToken(t *testing.T) {
	endpoint, err := fapi.ParseEndpointURL("https://rp.example/ciba/notify?tenant=t1")
	if err != nil {
		t.Fatal(err)
	}
	n := BackchannelNotification{Endpoint: endpoint, ClientNotificationToken: fapi.NewSecret(renderToken), AuthReqID: renderAuthReqID}
	rendertest.Check(t, n, []string{renderToken})
	// AuthReqID is an exported string: fmt's reflection fallback prints
	// it, as any exported field.
	rendertest.Check(t, n, []string{renderAuthReqID}, rendertest.Allow(rendertest.Fallback))
	if got := fmt.Sprintf("%+v", n); got != "{Endpoint:https://rp.example/ciba/notify?tenant=[REDACTED] ClientNotificationToken:[REDACTED] AuthReqID:[REDACTED]}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(n); !strings.Contains(got, "k.ClientNotificationToken=[REDACTED] k.AuthReqID=[REDACTED]") {
		t.Errorf("slog = %s", got)
	}
}

// TestRequestStringIsTheVRendering pins each request type's String to
// its %v rendering, for a logger that prints a fmt.Stringer rather than
// formatting it.
func TestRequestStringIsTheVRendering(t *testing.T) {
	parts := renderParts()
	for _, v := range []fmt.Stringer{
		FormParameter{Name: "code", Value: renderCode}, renderForm,
		PushAuthorizationRequest(parts), RefreshTokenRequest(parts), ClientCredentialsTokenRequest(parts),
		BackchannelTokenExchangeRequest(parts), BeginBackchannelAuthenticationRequest(parts),
		TokenRevocationRequest{HTTP: renderForm}, AttestedClientAuthenticationRequest{ClientID: "client-1"},
		BeginAuthorizationRequest{RequestURI: renderRequestURI}, BackchannelNotification{AuthReqID: renderAuthReqID},
	} {
		if got, want := v.String(), fmt.Sprintf("%v", v); got != want {
			t.Errorf("%T.String() = %s, want its %%v rendering %s", v, got, want)
		}
	}
}
