package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
)

func TestValidCIBAApprovalUIToken(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		supplied   string
		want       bool
	}{
		{"matching", "secret-1", "secret-1", true},
		{"mismatched", "secret-1", "secret-2", false},
		{"empty configured (feature off)", "", "anything", false},
		{"empty supplied", "secret-1", "", false},
		{"both empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validCIBAApprovalUIToken(tc.configured, tc.supplied); got != tc.want {
				t.Errorf("validCIBAApprovalUIToken(%q, %q) = %v, want %v", tc.configured, tc.supplied, got, tc.want)
			}
		})
	}
}

// TestCIBAApproveUIRouteNotRegisteredWhenTokenEmpty confirms the UI is
// truly off by default: even with -ciba enabled, GET /ciba-approve
// must 404 (route never registered at all) when no
// -ciba-approval-ui-token was configured — mirroring how every other
// optional capability in this binary defaults off.
func TestCIBAApproveUIRouteNotRegisteredWhenTokenEmpty(t *testing.T) {
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true, "")

	// h.cibaApproveUI is "" when the harness was built with an empty
	// cibaApprovalUIToken (feature off) — derive the base origin from
	// another known endpoint URL instead.
	origin := strings.TrimSuffix(h.token, "/token")
	res, err := h.httpClient.Get(origin + "/ciba-approve?token=anything")
	if err != nil {
		t.Fatalf("GET /ciba-approve: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /ciba-approve with token feature off = %d, want %d (route should not be registered)", res.StatusCode, http.StatusNotFound)
	}
}

func TestCIBAApproveFormRequiresToken(t *testing.T) {
	const realToken = "correct-horse-battery-staple"
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true, realToken)

	t.Run("no token", func(t *testing.T) {
		res, err := h.httpClient.Get(h.cibaApproveUI)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want %d", res.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		res, err := h.httpClient.Get(h.cibaApproveUI + "?token=wrong")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want %d", res.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("right token", func(t *testing.T) {
		res, err := h.httpClient.Get(h.cibaApproveUI + "?token=" + realToken)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.Contains(string(body), `name="auth_req_id"`) {
			t.Errorf("body missing auth_req_id form field: %s", body)
		}
	})
}

// TestCIBAApproveUIApprovesRealRequest drives a real
// client.BeginBackchannelAuthentication, approves it through the new
// HTML UI (not h.callBackchannelApprove's own JSON endpoint), and
// confirms client.PollBackchannelAuthentication actually sees a real
// issued token — proving the UI's POST handler and
// backchannelHandler.decide agree end to end, the same way
// TestSmokeCIBAFlow proves the JSON path does.
func TestCIBAApproveUIApprovesRealRequest(t *testing.T) {
	const realToken = "correct-horse-battery-staple"
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true, realToken)
	ctx := context.Background()

	session, err := h.client.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid", "accounts"}, LoginHint: smokeSubject,
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}

	res, err := h.httpClient.PostForm(h.cibaApproveUI, url.Values{
		"token":       {realToken},
		"auth_req_id": {session.AuthReqID()},
		"action":      {"allow"},
	})
	if err != nil {
		t.Fatalf("POST /ciba-approve: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("POST /ciba-approve status = %d, want %d, body: %s", res.StatusCode, http.StatusOK, body)
	}

	time.Sleep(session.Interval())
	result, err := h.client.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication (after UI approval): %v", err)
	}
	approved, ok := result.(client.BackchannelAuthenticationApproved)
	if !ok {
		t.Fatalf("PollBackchannelAuthentication (after UI approval) = %T, want client.BackchannelAuthenticationApproved", result)
	}
	if approved.Tokens.AccessToken.Reveal() == "" {
		t.Fatalf("access token is empty")
	}
}

// TestCIBAApproveUIDeniesRealRequest mirrors
// TestCIBAApproveUIApprovesRealRequest for action=deny.
func TestCIBAApproveUIDeniesRealRequest(t *testing.T) {
	const realToken = "correct-horse-battery-staple"
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true, realToken)
	ctx := context.Background()

	session, err := h.client.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid", "accounts"}, LoginHint: smokeSubject,
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}

	res, err := h.httpClient.PostForm(h.cibaApproveUI, url.Values{
		"token":       {realToken},
		"auth_req_id": {session.AuthReqID()},
		"action":      {"deny"},
	})
	if err != nil {
		t.Fatalf("POST /ciba-approve: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("POST /ciba-approve status = %d, want %d, body: %s", res.StatusCode, http.StatusOK, body)
	}

	time.Sleep(session.Interval())
	result, err := h.client.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication (after UI denial): %v", err)
	}
	if _, ok := result.(client.BackchannelAuthenticationDenied); !ok {
		t.Fatalf("PollBackchannelAuthentication (after UI denial) = %T, want client.BackchannelAuthenticationDenied", result)
	}
}

func TestCIBAApproveUIUnknownAuthReqID(t *testing.T) {
	const realToken = "correct-horse-battery-staple"
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true, realToken)

	res, err := h.httpClient.PostForm(h.cibaApproveUI, url.Values{
		"token":       {realToken},
		"auth_req_id": {"no-such-auth-req-id"},
		"action":      {"allow"},
	})
	if err != nil {
		t.Fatalf("POST /ciba-approve: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusNotFound)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "unknown auth_req_id") {
		t.Errorf("body = %s, want it to mention the unknown-auth_req_id error", body)
	}
}

// TestCIBAApproveUISubmitRequiresToken confirms a wrong token on the
// POST path is rejected (404) without ever touching the pending
// request — the same request must still be approvable afterward with
// the right token, proving the wrong-token attempt was a true no-op,
// not a partial/silent consumption of it.
func TestCIBAApproveUISubmitRequiresToken(t *testing.T) {
	const realToken = "correct-horse-battery-staple"
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true, realToken)
	ctx := context.Background()

	session, err := h.client.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid", "accounts"}, LoginHint: smokeSubject,
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}

	badRes, err := h.httpClient.PostForm(h.cibaApproveUI, url.Values{
		"token":       {"wrong-token"},
		"auth_req_id": {session.AuthReqID()},
		"action":      {"allow"},
	})
	if err != nil {
		t.Fatalf("POST /ciba-approve (wrong token): %v", err)
	}
	badRes.Body.Close()
	if badRes.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /ciba-approve (wrong token) status = %d, want %d", badRes.StatusCode, http.StatusNotFound)
	}

	goodRes, err := h.httpClient.PostForm(h.cibaApproveUI, url.Values{
		"token":       {realToken},
		"auth_req_id": {session.AuthReqID()},
		"action":      {"allow"},
	})
	if err != nil {
		t.Fatalf("POST /ciba-approve (right token): %v", err)
	}
	defer goodRes.Body.Close()
	if goodRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(goodRes.Body)
		t.Fatalf("POST /ciba-approve (right token, after a wrong-token attempt) status = %d, want %d, body: %s", goodRes.StatusCode, http.StatusOK, body)
	}
}
