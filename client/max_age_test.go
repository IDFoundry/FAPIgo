package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
)

func TestBeginAuthorizationSendsMaxAge(t *testing.T) {
	for _, tc := range []struct {
		name   string
		req    client.BeginAuthorizationRequest
		want   string
		absent bool
	}{
		{"five minutes", client.BeginAuthorizationRequest{MaxAge: 5 * time.Minute, HasMaxAge: true}, "300", false},
		{"zero: authenticate every time", client.BeginAuthorizationRequest{HasMaxAge: true}, "0", false},
		{"rounded down to whole seconds", client.BeginAuthorizationRequest{MaxAge: 1500 * time.Millisecond, HasMaxAge: true}, "1", false},
		{"not requested", client.BeginAuthorizationRequest{MaxAge: time.Minute}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			tc.req.Scope = []string{"openid"}
			if _, err := c.BeginAuthorization(context.Background(), tc.req); err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			got, present := as.lastPARForm["max_age"]
			if present == tc.absent || (present && got[0] != tc.want) {
				t.Errorf("PAR form max_age = %q (present %v), want %q (present %v)", got, present, tc.want, !tc.absent)
			}
		})
	}
}

// TestBeginAuthorizationSendsMaxAgeAsNumberInRequestObject covers a
// signed request object, which carries max_age as a JSON number.
func TestBeginAuthorizationSendsMaxAgeAsNumberInRequestObject(t *testing.T) {
	c, as, _ := newTestClient(t, true)
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}, MaxAge: time.Hour, HasMaxAge: true}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	parts := strings.Split(as.lastPARForm.Get("request"), ".")
	if len(parts) != 3 {
		t.Fatalf("PAR form carries no signed request object")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if got := string(claims["max_age"]); got != "3600" {
		t.Errorf("request object max_age = %s, want the number 3600", got)
	}
}

func TestBeginAuthorizationRejectsNegativeMaxAge(t *testing.T) {
	c, _, _ := newTestClient(t, false)
	_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}, MaxAge: -time.Second, HasMaxAge: true})
	if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, client.ErrorInvalidRequest)
	}
}
