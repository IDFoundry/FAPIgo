package server_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// fullHTTPRequest is a request carrying everything a client-authenticated
// endpoint can receive: a form, two DPoP headers (kept, so the
// more-than-one check still fires), attestation headers and a client
// certificate.
func fullHTTPRequest(t *testing.T, form string) (*http.Request, *x509.Certificate) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/endpoint", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("DPoP", "proof-1")
	r.Header.Add("DPoP", "proof-2")
	r.Header.Add("OAuth-Client-Attestation", "attestation")
	r.Header.Add("OAuth-Client-Attestation-PoP", "pop")
	cert := selfSignedTestClientCert(t)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r, cert
}

// checkRequestParts checks req — any of the request types — carries
// every part of fullHTTPRequest.
func checkRequestParts(t *testing.T, req any, cert *x509.Certificate, param, value string) {
	t.Helper()
	v := reflect.ValueOf(req)
	if got := v.FieldByName("HTTP").Interface().(server.FormRequest).Get(param); got != value {
		t.Errorf("%T form %s = %q, want %q", req, param, got, value)
	}
	for field, want := range map[string][]string{
		"DPoPProofs": {"proof-1", "proof-2"}, "ClientAttestations": {"attestation"}, "ClientAttestationPoPs": {"pop"},
	} {
		if got := v.FieldByName(field).Interface().([]string); !reflect.DeepEqual(got, want) {
			t.Errorf("%T.%s = %v, want %v", req, field, got, want)
		}
	}
	if got := v.FieldByName("PeerCertificate").Interface().(*x509.Certificate); got != cert {
		t.Errorf("%T.PeerCertificate = %v, want the presented certificate", req, got)
	}
}

func TestPushAuthorizationRequestFromHTTP(t *testing.T) {
	r, cert := fullHTTPRequest(t, "client_id=c&response_type=code")
	req, err := server.PushAuthorizationRequestFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	checkRequestParts(t, req, cert, "response_type", "code")
}

func TestBeginBackchannelAuthenticationRequestFromHTTP(t *testing.T) {
	r, cert := fullHTTPRequest(t, "scope=openid&login_hint=alice")
	req, err := server.BeginBackchannelAuthenticationRequestFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	checkRequestParts(t, req, cert, "login_hint", "alice")
}

func TestTokenEndpointRequestFromHTTP(t *testing.T) {
	r, cert := fullHTTPRequest(t, "grant_type=refresh_token&refresh_token=rt")
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.GrantType(); got != "refresh_token" {
		t.Errorf("GrantType() = %q, want refresh_token", got)
	}
	for _, typed := range []any{req.AuthorizationCodeExchange(), req.RefreshToken(), req.ClientCredentials(), req.BackchannelTokenExchange()} {
		checkRequestParts(t, typed, cert, "refresh_token", "rt")
	}

	proxied := selfSignedTestClientCert(t)
	req.SetPeerCertificate(proxied)
	if got := req.RefreshToken().PeerCertificate; got != proxied {
		t.Errorf("after SetPeerCertificate, PeerCertificate = %v, want the proxy-forwarded certificate", got)
	}
}

func TestRequestFromHTTPRejectsMalformedForm(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/par", strings.NewReader("a=1"))
	r.Header.Set("Content-Type", "application/json")
	if _, err := server.PushAuthorizationRequestFromHTTP(r); err == nil {
		t.Error("PushAuthorizationRequestFromHTTP(non-form body) = nil error, want error")
	}
	if _, err := server.TokenEndpointRequestFromHTTP(r); err == nil {
		t.Error("TokenEndpointRequestFromHTTP(non-form body) = nil error, want error")
	}
}
