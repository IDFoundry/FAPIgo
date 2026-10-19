package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/server"
)

// pushWithAssertionClaims pushes an authorization request authenticated
// by a client assertion with claims.
func pushWithAssertionClaims(t *testing.T, h harness, claims map[string]any) error {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := jose.Sign(h.key, jose.Header{Algorithm: fapi.ES256}, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
	})
	return err
}

// The client-assertion time rules, through PAR: FAPI 2.0 Security
// Profile §5.3.2.1 item 13 for iat and nbf, a full lifetime from a client
// whose clock runs ahead within the skew, and RFC 7519 §2's non-integer
// NumericDates.
func TestClientAssertionTimesAtPAR(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims func(h harness) map[string]any
		ok     bool
	}{
		{"iat an hour ahead", func(h harness) map[string]any {
			return map[string]any{"exp": h.now.Add(30 * time.Second).Unix(), "iat": h.now.Add(time.Hour).Unix()}
		}, false},
		{"nbf an hour ahead", func(h harness) map[string]any {
			return map[string]any{"exp": h.now.Add(30 * time.Second).Unix(), "nbf": h.now.Add(time.Hour).Unix()}
		}, false},
		{"full lifetime from a client within the skew ahead", func(h harness) map[string]any {
			ahead := h.now.Add(h.cfg.Limits.MaxClockSkew)
			return map[string]any{"exp": ahead.Add(h.cfg.Limits.MaxClientAssertionLifetime).Unix(), "iat": ahead.Unix()}
		}, true},
		{"fractional exp and iat", func(h harness) map[string]any {
			return map[string]any{"exp": float64(h.now.Add(30*time.Second).Unix()) + 0.5, "iat": float64(h.now.Unix()) + 0.25}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			claims := tc.claims(h)
			claims["iss"], claims["sub"], claims["aud"], claims["jti"] = testClientID.String(), testClientID.String(), testIssuer, "time-checks"
			err := pushWithAssertionClaims(t, h, claims)
			switch {
			case tc.ok && err != nil:
				t.Errorf("PushAuthorizationRequest = %v, want success", err)
			case !tc.ok && serverErrorCode(t, err) != server.ErrorInvalidClient:
				t.Errorf("PushAuthorizationRequest = %v, want invalid_client", err)
			}
		})
	}
}
