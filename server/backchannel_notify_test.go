package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// TestNewBackchannelNotificationRequest covers the exact CIBA §10.2
// wire shape the OIDF conformance suite's own verification checks for:
// POST, Authorization: Bearer {token}, Content-Type: application/json,
// and a body of exactly {"auth_req_id": "..."}.
func TestNewBackchannelNotificationRequest(t *testing.T) {
	endpoint, err := fapi.ParseEndpointURL("https://rp.example.com/ciba-notify")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	notification := server.BackchannelNotification{
		Endpoint:                endpoint,
		ClientNotificationToken: fapi.NewSecret("notif-token-value"),
		AuthReqID:               "auth-req-id-value",
	}

	req, err := server.NewBackchannelNotificationRequest(context.Background(), notification)
	if err != nil {
		t.Fatalf("NewBackchannelNotificationRequest: %v", err)
	}

	if req.Method != http.MethodPost {
		t.Fatalf("Method = %q, want %q", req.Method, http.MethodPost)
	}
	if req.URL.String() != endpoint.String() {
		t.Fatalf("URL = %q, want %q", req.URL.String(), endpoint.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer notif-token-value" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer notif-token-value")
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}

	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal body: %v (body: %s)", err, raw)
	}
	if len(body) != 1 {
		t.Fatalf("body = %s, want exactly one member (auth_req_id)", raw)
	}
	var authReqID string
	if err := json.Unmarshal(body["auth_req_id"], &authReqID); err != nil {
		t.Fatalf("unmarshal auth_req_id: %v", err)
	}
	if authReqID != "auth-req-id-value" {
		t.Fatalf("auth_req_id = %q, want %q", authReqID, "auth-req-id-value")
	}
}
