package server_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// TestBackchannelInteractionRequiredWriteJSON covers WriteJSON's own
// CIBA §10.2/§10.3 wire format: HTTP 200, Content-Type, and the
// {"auth_req_id", "expires_in", "interval"} body.
func TestBackchannelInteractionRequiredWriteJSON(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	requestObj := h.backchannelRequestObject(t, standardBackchannelParams(t))

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
	}

	rec := httptest.NewRecorder()
	required.WriteJSON(rec)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
	var body struct {
		AuthReqID string `json:"auth_req_id"`
		ExpiresIn int64  `json:"expires_in"`
		Interval  int64  `json:"interval"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v (body: %s)", err, rec.Body.Bytes())
	}
	if body.AuthReqID != required.AuthReqID.String() {
		t.Fatalf("auth_req_id = %q, want %q", body.AuthReqID, required.AuthReqID.String())
	}
	if body.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d, want positive", body.ExpiresIn)
	}
	if want := int64(required.Interval / time.Second); body.Interval != want {
		t.Fatalf("interval = %d, want %d", body.Interval, want)
	}
}
