package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactJSONHidesOnlySensitiveFields(t *testing.T) {
	got := redactJSON([]byte(`{"access_token":"secret-value","token_type":"Bearer","expires_in":3600}`))
	if strings.Contains(got, "secret-value") {
		t.Fatalf("redactJSON(%q) leaked the sensitive value", got)
	}
	if !strings.Contains(got, `"token_type":"Bearer"`) {
		t.Fatalf("redactJSON(%q) dropped a non-sensitive field", got)
	}
}

func TestRedactFormHidesOnlySensitiveFields(t *testing.T) {
	got := redactForm([]byte("grant_type=authorization_code&client_assertion=secret-value&code=abc123"))
	if strings.Contains(got, "secret-value") {
		t.Fatalf("redactForm(%q) leaked the sensitive value", got)
	}
	if !strings.Contains(got, "code=abc123") {
		t.Fatalf("redactForm(%q) dropped a non-sensitive field", got)
	}
}

func TestBodySummaryEmptyBody(t *testing.T) {
	if got := bodySummary("application/json", nil); got != "" {
		t.Fatalf("bodySummary with no body = %q, want empty", got)
	}
}

func TestLoggingRoundTripperRecordsAndRestoresBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"top-secret","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	rec := &interactionRecorder{}
	cl := &http.Client{Transport: &loggingRoundTripper{next: http.DefaultTransport, rec: rec}}

	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("client_assertion=top-secret&grant_type=authorization_code"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	// The real caller must still be able to read a full, correct body —
	// loggingRoundTripper draining it to build the transcript must not
	// consume it out from under the caller.
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "top-secret") {
		t.Fatalf("response body was not restored intact: %q", body)
	}

	transcript := rec.transcript()
	if strings.Contains(transcript, "top-secret") {
		t.Fatalf("transcript leaked a sensitive value:\n%s", transcript)
	}
	if !strings.Contains(transcript, "grant_type=authorization_code") {
		t.Fatalf("transcript dropped a non-sensitive request field:\n%s", transcript)
	}
	if !strings.Contains(transcript, `"token_type":"Bearer"`) {
		t.Fatalf("transcript dropped a non-sensitive response field:\n%s", transcript)
	}
	if !strings.Contains(transcript, "200 OK") {
		t.Fatalf("transcript missing response status:\n%s", transcript)
	}
}
