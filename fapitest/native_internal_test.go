package fapitest

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// authorizationRedirect follows session's authorization URL through the
// auto-approving endpoint and returns where it redirects the user agent.
func authorizationRedirect(t *testing.T, h *Harness, session client.AuthorizationSession) *url.URL {
	t.Helper()
	authorizeURL := session.URL().URL()
	res, err := h.httpClient.Do((&http.Request{Method: http.MethodGet, URL: &authorizeURL, Header: http.Header{}}).WithContext(context.Background()))
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want %d", res.StatusCode, http.StatusFound)
	}
	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location %q: %v", res.Header.Get("Location"), err)
	}
	return location
}

// TestNativeLoopbackRedirectGoesToRequestedPort checks where the server
// sends the user agent, not only that the flow completes: each flow's
// redirect goes to the loopback port that flow asked for.
func TestNativeLoopbackRedirectGoesToRequestedPort(t *testing.T) {
	h := New(t, Config{
		Profile: server.ProfileFAPISecurity, RedirectURI: "http://127.0.0.1/callback", ApplicationType: storage.ApplicationTypeNative,
	})
	for _, port := range []uint16{51004, 61023} {
		session, err := h.Client.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
			Scope: []string{"openid", "accounts"}, RedirectPort: port,
		})
		if err != nil {
			t.Fatalf("port %d: BeginAuthorization: %v", port, err)
		}
		location := authorizationRedirect(t, h, session)
		want := url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(int(port)), Path: "/callback"}
		if location.Scheme != want.Scheme || location.Host != want.Host || location.Path != want.Path {
			t.Errorf("port %d: redirected to %s, want %s", port, location.Redacted(), want.String())
		}
		if location.Query().Get("code") == "" {
			t.Errorf("port %d: redirect carries no code", port)
		}
	}
}

// TestNativeRelaunchCompletesFromCallbackAlone stands in for a mobile
// app the operating system stops while the user is at the authorization
// server: the app starts the flow, a new client built from the same
// on-device storage receives the callback, and it completes from the
// callback's query alone, under both profiles.
func TestNativeRelaunchCompletesFromCallbackAlone(t *testing.T) {
	for name, profile := range map[string]server.Profile{
		"security":        server.ProfileFAPISecurity,
		"message signing": server.ProfileFAPISecurityWithMessageSigning,
	} {
		t.Run(name, func(t *testing.T) {
			h := New(t, Config{
				Profile: profile, RedirectURI: "com.example.wallet:/callback", ApplicationType: storage.ApplicationTypeNative,
			})
			cfg := h.clientConfig
			cfg.CallbackBinding = client.CallbackBindingDeviceLocalStore
			launched, err := client.New(cfg, h.clientDeps)
			if err != nil {
				t.Fatalf("client.New: %v", err)
			}
			session, err := launched.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			location := authorizationRedirect(t, h, session)
			if location.Scheme != "com.example.wallet" {
				t.Fatalf("redirected to scheme %q, want the app's own", location.Scheme)
			}

			relaunched, err := client.New(cfg, h.clientDeps)
			if err != nil {
				t.Fatalf("client.New after relaunch: %v", err)
			}
			result, err := relaunched.CompleteAuthorization(context.Background(), client.AuthorizationCallback{RawQuery: location.RawQuery})
			if err != nil {
				t.Fatalf("CompleteAuthorization after relaunch: %v", err)
			}
			success, ok := result.(client.CompletionSuccess)
			if !ok || success.Tokens.AccessToken.Reveal() == "" {
				t.Fatalf("CompleteAuthorization = %T, want tokens", result)
			}

			// The callback is single-use, relaunch or not.
			if _, err := relaunched.CompleteAuthorization(context.Background(), client.AuthorizationCallback{RawQuery: location.RawQuery}); err == nil {
				t.Error("replayed callback accepted")
			}
		})
	}
}

// TestNativeCallbackNeedsSessionUnderDefaultBinding checks the default:
// without CallbackBindingDeviceLocalStore, a callback with no session
// handle is refused, so a browser-based client stays bound to its own
// user agent.
func TestNativeCallbackNeedsSessionUnderDefaultBinding(t *testing.T) {
	h := New(t, Config{
		Profile: server.ProfileFAPISecurity, RedirectURI: "com.example.wallet:/callback", ApplicationType: storage.ApplicationTypeNative,
	})
	session, err := h.Client.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	location := authorizationRedirect(t, h, session)
	if _, err := h.Client.CompleteAuthorization(context.Background(), client.AuthorizationCallback{RawQuery: location.RawQuery}); err == nil {
		t.Fatal("callback without a session handle accepted under the default binding")
	}
	if _, err := h.RunAuthorizationCodeFlowWithCallback(context.Background(), session.Handle(), location.RawQuery); err != nil {
		t.Fatalf("callback with its session handle: %v", err)
	}
}
