package server_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestPushAuthorizationResultWriteJSON covers WriteJSON's own RFC 9126
// §2.2 wire format for a genuinely successful PAR result: HTTP 201,
// Content-Type, and the {"request_uri", "expires_in"} body.
func TestPushAuthorizationResultWriteJSON(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	result, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	rec := httptest.NewRecorder()
	result.WriteJSON(rec)

	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
	var body struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v (body: %s)", err, rec.Body.Bytes())
	}
	if body.RequestURI != result.RequestURI.String() {
		t.Fatalf("request_uri = %q, want %q", body.RequestURI, result.RequestURI.String())
	}
	if body.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d, want positive", body.ExpiresIn)
	}
}

// TestPushAuthorizationResultWriteJSONIncludesDPoPNonceHeader covers
// WriteJSON's other branch: a result carrying NextDPoPNonce (RFC 9449
// §8) sets it as the response's own DPoP-Nonce header.
func TestPushAuthorizationResultWriteJSONIncludesDPoPNonceHeader(t *testing.T) {
	h, _ := newHarnessWithNonces(t)

	result, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: parFormParams(t, h)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if result.NextDPoPNonce == "" {
		t.Fatalf("NextDPoPNonce is empty, want a freshly issued nonce")
	}

	rec := httptest.NewRecorder()
	result.WriteJSON(rec)

	if got := rec.Header().Get("DPoP-Nonce"); got != result.NextDPoPNonce {
		t.Fatalf("DPoP-Nonce header = %q, want %q", got, result.NextDPoPNonce)
	}
}
