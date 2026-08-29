package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

func TestHTTPBackchannelNotifierSendsRequiredRequestShape(t *testing.T) {
	var gotMethod, gotContentType, gotAuth string
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &gotBody); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	endpoint, err := fapi.ParseEndpointURL(ts.URL)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	notifier := newHTTPBackchannelNotifier()
	if err := notifier.Notify(context.Background(), server.BackchannelNotification{
		Endpoint:                endpoint,
		ClientNotificationToken: fapi.NewSecret("notify-token-1"),
		AuthReqID:               "auth-req-1",
	}); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("Method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotAuth != "Bearer notify-token-1" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer notify-token-1")
	}
	if len(gotBody) != 1 || gotBody["auth_req_id"] != "auth-req-1" {
		t.Errorf("body = %+v, want exactly {\"auth_req_id\": \"auth-req-1\"}", gotBody)
	}
}

func TestHTTPBackchannelNotifierDoesNotFollowRedirects(t *testing.T) {
	var invalidEndpointCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/notify", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/invalid-notify", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/invalid-notify", func(w http.ResponseWriter, r *http.Request) {
		invalidEndpointCalled = true
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	endpoint, err := fapi.ParseEndpointURL(ts.URL + "/notify")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	notifier := newHTTPBackchannelNotifier()
	if err := notifier.Notify(context.Background(), server.BackchannelNotification{
		Endpoint:                endpoint,
		ClientNotificationToken: fapi.NewSecret("notify-token-1"),
		AuthReqID:               "auth-req-1",
	}); err == nil {
		t.Fatalf("Notify(redirect response) = nil error, want error (a redirect is not 2xx)")
	}
	if invalidEndpointCalled {
		t.Fatalf("Notify followed the redirect and called the endpoint it pointed to — must not follow redirects")
	}
}

func TestHTTPBackchannelNotifierReportsNon2xxAsError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	endpoint, err := fapi.ParseEndpointURL(ts.URL)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	notifier := newHTTPBackchannelNotifier()
	if err := notifier.Notify(context.Background(), server.BackchannelNotification{
		Endpoint:                endpoint,
		ClientNotificationToken: fapi.NewSecret("notify-token-1"),
		AuthReqID:               "auth-req-1",
	}); err == nil {
		t.Fatalf("Notify(401 response) = nil error, want error")
	}
}
