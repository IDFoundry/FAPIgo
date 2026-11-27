package resource

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/rendertest"
)

const (
	renderAccessToken = "ACCESS-TOKEN-SECRET-0201"
	renderProof       = "DPOP-PROOF-SECRET-0202"
	renderQueryValue  = "QUERY-VALUE-SECRET-0203"
)

// exportedResidual is what a request's own exported fields hold raw, by
// design: fmt's reflection fallback and the encoders print them as they
// print any exported field.
var exportedResidual = rendertest.Allow(rendertest.Fallback, rendertest.Encoding)

func TestVerifyRequestPrintsNoToken(t *testing.T) {
	r := httptest.NewRequest("GET", "https://rs.example/accounts?filter="+renderQueryValue, nil)
	r.Header.Set("Authorization", "DPoP "+renderAccessToken)
	r.Header.Set("DPoP", renderProof)
	req := VerifyRequestFromHTTP(r)
	rendertest.Check(t, req, []string{renderAccessToken, renderProof}, exportedResidual)
	if got := fmt.Sprintf("%+v", req); got != "{Method:GET URL: Authorization:DPoP [REDACTED] DPoPProofs:[[REDACTED]] PeerCertificate: requestPath:/accounts requestOrigin: repeatedAuthorization:false}" {
		t.Errorf("%%+v = %s", got)
	}

	withURL := VerifyRequest{Method: "POST", URL: r.URL, Authorization: "Bearer " + renderAccessToken,
		PeerCertificate: &x509.Certificate{Subject: pkix.Name{CommonName: "client-1"}}}
	rendertest.Check(t, withURL, []string{renderAccessToken, renderQueryValue}, exportedResidual)
	if got := fmt.Sprint(withURL); got != "{POST https://rs.example/accounts?filter=[REDACTED] Bearer [REDACTED] [] CN=client-1   false}" {
		t.Errorf("%%v = %s", got)
	}
	if got := logged(withURL); !strings.Contains(got, `k.Authorization="Bearer [REDACTED]"`) || !strings.Contains(got, `k.PeerCertificate="CN=client-1"`) {
		t.Errorf("slog = %s", got)
	}
	if got := fmt.Sprintf("%#v", withURL); !strings.HasPrefix(got, `resource.VerifyRequest{Method:"POST"`) {
		t.Errorf("%%#v = %s, want the real type's name", got)
	}
	for header, want := range map[string]string{
		"": "", renderAccessToken: "[REDACTED]", "bearer " + renderAccessToken: "bearer [REDACTED]",
		renderAccessToken + " x": "[REDACTED]", "Basic " + renderAccessToken: "[REDACTED]", "evil\nscheme " + renderAccessToken: "[REDACTED]",
	} {
		if got := authorizationSummary(header); got != want {
			t.Errorf("authorizationSummary(%q) = %q, want %q", header, got, want)
		}
	}
}

// TestVerifyRequestQuotesACertificateSubject checks that a certificate's
// subject, which is a self-signed certificate's client's to choose and
// which pkix.Name's String leaves unescaped, prints %q-quoted when it
// holds a newline, so it can't forge a log line. log/slog's handlers
// escape what they log themselves.
func TestVerifyRequestQuotesACertificateSubject(t *testing.T) {
	req := VerifyRequest{Method: "GET", PeerCertificate: &x509.Certificate{Subject: pkix.Name{CommonName: "client-1\nlevel=INFO msg=forged"}}}
	if got := fmt.Sprintf("%+v", req); strings.Contains(got, "\n") || !strings.Contains(got, `PeerCertificate:"CN=client-1\nlevel=INFO msg=forged"`) {
		t.Errorf("%%+v = %q, want the subject quoted", got)
	}
	if got := logged(req); strings.Count(got, "\n") != 1 {
		t.Errorf("slog = %q, want one line", got)
	}
}

func TestResolveAccessTokenRequestPrintsNoToken(t *testing.T) {
	r := ResolveAccessTokenRequest{Raw: renderAccessToken, Now: time.Unix(1_900_000_000, 0).UTC(), MaxClockSkew: time.Minute}
	rendertest.Check(t, r, []string{renderAccessToken}, exportedResidual)
	if got := fmt.Sprintf("%+v", r); got != "{Raw:[REDACTED] Now:2030-03-17 17:46:40 +0000 UTC MaxClockSkew:1m0s}" {
		t.Errorf("%%+v = %s", got)
	}
	if got := logged(r); !strings.Contains(got, "k.Raw=[REDACTED]") || r.String() != fmt.Sprint(r) {
		t.Errorf("slog = %s, String() = %s", got, r.String())
	}
}

// logged is what log/slog's text handler writes for v as attribute k.
func logged(v any) string {
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "k", v)
	return buf.String()
}

// TestShadowsKeepTheirTypesFields checks each rendering's shadow has the
// fields of the type it prints for, in order.
func TestShadowsKeepTheirTypesFields(t *testing.T) {
	rendertest.CheckShadow(t, reflect.TypeFor[VerifyRequest](), reflect.TypeFor[verifyRequestShadow]())
	rendertest.CheckShadow(t, reflect.TypeFor[ResolveAccessTokenRequest](), reflect.TypeFor[resolveAccessTokenRequestShadow]())
}

// TestStringIsTheVRendering pins each request's String to its %v
// rendering, for a logger that prints a fmt.Stringer rather than
// formatting it.
func TestStringIsTheVRendering(t *testing.T) {
	for _, v := range []fmt.Stringer{VerifyRequest{Authorization: "DPoP " + renderAccessToken}, ResolveAccessTokenRequest{Raw: renderAccessToken}} {
		if got, want := v.String(), fmt.Sprintf("%v", v); got != want {
			t.Errorf("%T.String() = %s, want its %%v rendering %s", v, got, want)
		}
	}
}
