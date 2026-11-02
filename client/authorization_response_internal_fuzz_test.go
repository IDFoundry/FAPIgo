package client

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"
	"unicode/utf8"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// callbackFuzzState is the state of the session the plain-mode callback
// fuzz target and its regression test bind their callbacks to.
const callbackFuzzState = "c3RhdGVzdGF0ZXN0YXRlc3RhdGVzdGF0ZXN0YXRlc3Q"

// plainCallbackClient is a Client in plain (non-JARM) response mode with
// one session, for callbackFuzzState, waiting for its callback.
func plainCallbackClient(t *testing.T, iss fapi.URL, requireIss, deviceLocal bool) *Client {
	t.Helper()
	c := &Client{}
	c.cfg.Issuer, c.cfg.ClientID = iss, fapi.ClientID("client-a")
	c.cfg.Profile = ProfileFAPISecurity
	c.cfg.AuthorizationResponseIssPolicy = TolerateAbsentAuthorizationResponseIss
	if requireIss {
		c.cfg.AuthorizationResponseIssPolicy = RequireAuthorizationResponseIss
	}
	if deviceLocal {
		c.cfg.CallbackBinding = CallbackBindingDeviceLocalStore
	}
	c.cfg.Limits.SessionLifetime = time.Minute
	c.deps.Sessions = memstore.NewSessionStore()
	c.deps.Clock = SystemClock{}
	rec := sessionRecord{Nonce: "n", PKCEVerifier: "v", Issuer: iss.String(), ClientID: "client-a", RedirectURI: "https://rp.example/cb", ResponseMode: responseModePlain, OpenID: true}
	if err := c.createSession(context.Background(), callbackFuzzState, rec, time.Now()); err != nil {
		t.Fatalf("createSession: %v", err)
	}
	return c
}

// FuzzHandleAuthorizationResponsePlain exercises HandleAuthorizationResponse
// with arbitrary plain-mode callback queries, under both iss policies,
// with and without a SessionHandle, and with either callback binding.
// Unexported state (the session record), so this file lives in package
// client. Its oracle: an accepted callback has exactly one state, equal
// to the bound session's; an iss, when present, equal to the issuer;
// an iss at all under RequireAuthorizationResponseIss; a code exactly as
// the query carries it (never a lossy re-reading); and replaying it is
// refused.
func FuzzHandleAuthorizationResponsePlain(f *testing.F) {
	f.Add("code=abc&state="+callbackFuzzState+"&iss=https%3A%2F%2Fas.example", true, true, false)
	f.Add("error=access_denied&state="+callbackFuzzState, false, true, true)
	f.Add("code=abc&state="+callbackFuzzState+"&state="+callbackFuzzState, true, false, false)
	f.Add("code=abc&state=%63"+callbackFuzzState[1:], true, false, false)
	f.Add("code=abc%80&state="+callbackFuzzState+"&iss=https%3A%2F%2Fas.example", true, true, false)
	f.Fuzz(func(t *testing.T, rawQuery string, requireIss, passHandle, deviceLocal bool) {
		iss, err := fapi.ParseIssuerURL("https://as.example")
		if err != nil {
			t.Fatal(err)
		}
		c := plainCallbackClient(t, iss, requireIss, deviceLocal)
		cb := AuthorizationCallback{RawQuery: rawQuery}
		if passHandle {
			cb.Session = SessionHandle{value: callbackFuzzState}
		}
		res, err := c.HandleAuthorizationResponse(context.Background(), cb)
		if err != nil {
			return
		}
		checkAcceptedPlainCallback(t, rawQuery, iss.String(), requireIss, res)
		if _, err := c.HandleAuthorizationResponse(context.Background(), cb); err == nil {
			t.Fatalf("callback replay accepted: %q", rawQuery)
		}
	})
}

// checkAcceptedPlainCallback checks FuzzHandleAuthorizationResponsePlain's
// oracle for a callback HandleAuthorizationResponse accepted.
func checkAcceptedPlainCallback(t *testing.T, rawQuery, issuer string, requireIss bool, res CallbackResult) {
	t.Helper()
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("accepted a query url.ParseQuery refuses: %q", rawQuery)
	}
	if len(q["state"]) != 1 || q.Get("state") != callbackFuzzState {
		t.Fatalf("accepted state %q", q["state"])
	}
	if i, ok := q["iss"]; ok && (len(i) != 1 || i[0] != issuer) {
		t.Fatalf("accepted iss %q", i)
	}
	if requireIss && q.Get("iss") == "" {
		t.Fatalf("accepted a missing iss under RequireAuthorizationResponseIss: %q", rawQuery)
	}
	if s, ok := res.(CallbackSuccess); ok && (s.Response.code == "" || !utf8.ValidString(s.Response.code) || s.Response.code != q.Get("code")) {
		t.Fatalf("accepted code %q, query carries %q", s.Response.code, q.Get("code"))
	}
}

// TestHandleAuthorizationResponseRefusesInvalidUTF8: a plain-mode
// callback parameter that isn't valid UTF-8 is refused with
// ErrorInvalidRequest, not decoded lossily (U+FFFD) and sent on, which
// would read different codes back as one.
func TestHandleAuthorizationResponseRefusesInvalidUTF8(t *testing.T) {
	iss, err := fapi.ParseIssuerURL("https://as.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"code=abc%80&state=" + callbackFuzzState + "&iss=https%3A%2F%2Fas.example",
		"code=abc%FF&state=" + callbackFuzzState + "&iss=https%3A%2F%2Fas.example",
		"code=abc%C3&state=" + callbackFuzzState + "&iss=https%3A%2F%2Fas.example",
		"code=abc&state=" + callbackFuzzState + "&iss=https%3A%2F%2Fas.example&x%FF=1",
	} {
		c := plainCallbackClient(t, iss, true, false)
		res, err := c.HandleAuthorizationResponse(context.Background(), AuthorizationCallback{
			RawQuery: query, Session: SessionHandle{value: callbackFuzzState},
		})
		var cerr *Error
		if !errors.As(err, &cerr) || cerr.Code() != ErrorInvalidRequest {
			t.Errorf("HandleAuthorizationResponse(%q) = %v, %v, want ErrorInvalidRequest", query, res, err)
		}
	}
}
