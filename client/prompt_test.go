package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
)

// TestBeginAuthorizationSendsPrompt checks Prompt's encoding: one
// space-separated "prompt" (OIDC Core §3.1.2.1), as a plain PAR
// parameter or inside the signed request object, and none at all when
// Prompt is empty.
func TestBeginAuthorizationSendsPrompt(t *testing.T) {
	for name, tc := range map[string]struct {
		prompt []string
		want   string
	}{
		"none set":    {nil, ""},
		"one":         {[]string{client.PromptConsent}, "consent"},
		"several":     {[]string{client.PromptLogin, client.PromptConsent}, "login consent"},
		"other spec":  {[]string{"create"}, "create"},
		"prompt none": {[]string{client.PromptNone}, "none"},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
				Scope: []string{"openid", "offline_access"}, Prompt: tc.prompt,
			}); err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			if got, has := as.lastPARForm.Get("prompt"), as.lastPARForm.Has("prompt"); got != tc.want || has != (tc.want != "") {
				t.Errorf("prompt = %q (sent %v), want %q", got, has, tc.want)
			}
		})
	}
	t.Run("request object", func(t *testing.T) {
		c, as, _ := newTestClient(t, true)
		if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
			Scope: []string{"openid"}, Prompt: []string{client.PromptLogin, client.PromptConsent},
		}); err != nil {
			t.Fatalf("BeginAuthorization: %v", err)
		}
		if got := requestObjectParameter(t, as.lastPARForm.Get("request"), "prompt"); got != `"login consent"` {
			t.Errorf("request object prompt = %s, want \"login consent\"", got)
		}
		if as.lastPARForm.Has("prompt") {
			t.Error("PAR form also carries prompt beside the request object")
		}
	})
}

// TestBeginAuthorizationRefusesBadPrompt covers Prompt's own checks,
// made before anything is pushed.
func TestBeginAuthorizationRefusesBadPrompt(t *testing.T) {
	for name, prompt := range map[string][]string{
		"none with another": {client.PromptNone, client.PromptLogin},
		"another with none": {client.PromptConsent, client.PromptNone},
		"repeated":          {client.PromptConsent, client.PromptConsent},
		"empty":             {client.PromptLogin, ""},
		"space":             {"login consent"},
		"control":           {"login\n"},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}, Prompt: prompt})
			var cerr *client.Error
			if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
				t.Fatalf("BeginAuthorization = %v, want invalid_request", err)
			}
			if as.lastPARForm != nil {
				t.Error("the request was pushed anyway")
			}
		})
	}
}

// TestBeginAuthorizationRefusesPromptTwice checks that an Extensions
// value named "prompt" can't replace or duplicate Prompt.
func TestBeginAuthorizationRefusesPromptTwice(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	req := client.BeginAuthorizationRequest{Scope: []string{"openid"}, Prompt: []string{client.PromptConsent}}
	if err := extension.Set(&req.Extensions, extension.Definition[string]{Name: "prompt", MaxBytes: 64}, "login"); err != nil {
		t.Fatalf("extension.Set: %v", err)
	}
	_, err := c.BeginAuthorization(context.Background(), req)
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("BeginAuthorization = %v, want invalid_request", err)
	}
	if as.lastPARForm != nil {
		t.Error("the request was pushed anyway")
	}
}
