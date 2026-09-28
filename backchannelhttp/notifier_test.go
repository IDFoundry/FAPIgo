package backchannelhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/backchannelhttp"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/server"
)

func testNotification(t *testing.T, endpointURL string) server.BackchannelNotification {
	t.Helper()
	endpoint, err := fapi.ParseEndpointURL(endpointURL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return server.BackchannelNotification{
		Endpoint:                endpoint,
		ClientNotificationToken: fapi.NewSecret("notif-token-value"),
		AuthReqID:               "auth-req-id-value",
	}
}

// loopbackTransport lets the notifier reach this test's httptest
// servers, which listen on loopback.
var loopbackTransport = fapihttp.TransportConfig{DialTimeout: time.Second, TLSHandshakeTimeout: time.Second, AllowLoopbackHTTP: true}

func TestNewRejectsZeroTransport(t *testing.T) {
	if _, err := backchannelhttp.New(backchannelhttp.Config{Timeout: time.Second}); err == nil {
		t.Fatal("New(zero Transport) = nil error, want error")
	}
}

func TestNewRejectsNonPositiveTimeout(t *testing.T) {
	if _, err := backchannelhttp.New(backchannelhttp.Config{Timeout: 0, Transport: loopbackTransport}); err == nil {
		t.Fatal("New(..., Timeout: 0) = nil error, want error")
	}
}

// TestNotifySendsCorrectRequestAndSucceedsOn2xx confirms Notify actually
// sends the exact CIBA §10.2 wire shape
// TestNewBackchannelNotificationRequest (server package) already proves
// NewBackchannelNotificationRequest builds, and that a 2xx response is
// treated as success.
func TestNotifySendsCorrectRequestAndSucceedsOn2xx(t *testing.T) {
	var gotMethod, gotAuth, gotContentType string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n, err := backchannelhttp.New(backchannelhttp.Config{Timeout: 5 * time.Second, Transport: loopbackTransport})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := n.Notify(context.Background(), testNotification(t, srv.URL)); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("Method = %q, want %q", gotMethod, http.MethodPost)
	}
	if gotAuth != "Bearer notif-token-value" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer notif-token-value")
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", gotContentType, "application/json")
	}
	if len(gotBody) != 1 || gotBody["auth_req_id"] != "auth-req-id-value" {
		t.Errorf("body = %v, want exactly {auth_req_id: auth-req-id-value}", gotBody)
	}
}

func TestNotifyFailsOnNon2xxStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n, err := backchannelhttp.New(backchannelhttp.Config{Timeout: 5 * time.Second, Transport: loopbackTransport})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := n.Notify(context.Background(), testNotification(t, srv.URL)); err == nil {
		t.Fatal("Notify(500 response) = nil error, want error")
	}
}

func TestNotifyFailsOnTransportError(t *testing.T) {
	n, err := backchannelhttp.New(backchannelhttp.Config{Timeout: 5 * time.Second, Transport: loopbackTransport})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No listener on this port — Do must fail at the transport level.
	if err := n.Notify(context.Background(), testNotification(t, "https://127.0.0.1:1")); err == nil {
		t.Fatal("Notify(unreachable endpoint) = nil error, want error")
	}
}

// erroringBody is an io.ReadCloser whose every Read fails — standing in
// for a connection that drops mid-response-body, to exercise Notify's
// own drain-the-body error path without relying on real network timing.
type erroringBody struct{}

func (erroringBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (erroringBody) Close() error             { return nil }

// erroringBodyClient is a fapihttp.HTTPClient that always returns a 2xx
// response whose body fails to read.
type erroringBodyClient struct{}

func (erroringBodyClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: erroringBody{}}, nil
}

func TestNotifyFailsWhenResponseBodyErrors(t *testing.T) {
	n := backchannelhttp.NewWithClient(erroringBodyClient{}, time.Second)
	if err := n.Notify(context.Background(), testNotification(t, "https://example.com")); err == nil {
		t.Fatal("Notify(erroring response body) = nil error, want error")
	}
}

// TestNotifyRespectsTimeout confirms Config.Timeout actually bounds the
// call, independent of whatever deadline ctx itself carries (here,
// none) — a notification endpoint that never responds must not be able
// to hang Notify indefinitely.
func TestNotifyRespectsTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// Deferred in this order so close(block) — LIFO, so it actually
	// runs first — unblocks the handler goroutine above before
	// srv.Close() (which waits for it to return) is called.
	defer srv.Close()
	defer close(block)

	n, err := backchannelhttp.New(backchannelhttp.Config{Timeout: 50 * time.Millisecond, Transport: loopbackTransport})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	if err := n.Notify(context.Background(), testNotification(t, srv.URL)); err == nil {
		t.Fatal("Notify(never-responding endpoint) = nil error, want error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Notify took %v, want it bounded by Config.Timeout (50ms)", elapsed)
	}
}

// TestNotifyRefusesLoopbackAndRedirects checks the guarantee New exists
// to give: without an explicit loopback exception it refuses to reach a
// loopback endpoint at all, and even with one it doesn't follow a
// redirect — a notification endpoint supplied from outside the
// deployment can't steer this server's own request anywhere else.
func TestNotifyRefusesLoopbackAndRedirects(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	guarded, err := backchannelhttp.New(backchannelhttp.Config{Timeout: 5 * time.Second,
		Transport: fapihttp.TransportConfig{DialTimeout: time.Second, TLSHandshakeTimeout: time.Second}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := guarded.Notify(context.Background(), testNotification(t, target.URL)); err == nil {
		t.Fatal("Notify(loopback endpoint, no loopback exception) = nil error, want the SSRF guard's refusal")
	}

	loopbackOK, err := backchannelhttp.New(backchannelhttp.Config{Timeout: 5 * time.Second, Transport: loopbackTransport})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := loopbackOK.Notify(context.Background(), testNotification(t, redirector.URL)); err == nil {
		t.Fatal("Notify(redirecting endpoint) = nil error, want the 302 treated as a failure")
	}
	if hits != 0 {
		t.Fatalf("redirect target received %d requests, want 0", hits)
	}
}
