package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// TestPushAuthorizationRequestBoundsHandBuiltForm checks that a
// FormRequest built by hand — never passing through FormRequestFromHTTP's
// own body limit — is still bounded in parameter count and total size.
func TestPushAuthorizationRequestBoundsHandBuiltForm(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	base := plainFormParameters(t, h.clientAssertion(t), nil)

	tooMany := append([]server.FormParameter{}, base...)
	for i := len(tooMany); i <= 100; i++ {
		tooMany = append(tooMany, formParam(fmt.Sprintf("x%d", i), "v"))
	}
	tooLarge := append(append([]server.FormParameter{}, base...), formParam("x_large", strings.Repeat("a", 1<<20)))

	for name, params := range map[string][]server.FormParameter{"too many parameters": tooMany, "too large": tooLarge} {
		t.Run(name, func(t *testing.T) {
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: params},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
			}
		})
	}

	// At the parameter-count limit, the request is still processed (an
	// unregistered extra parameter is ignored, not rejected).
	atLimit := append([]server.FormParameter{}, base...)
	for i := len(atLimit); i < 100; i++ {
		atLimit = append(atLimit, formParam(fmt.Sprintf("x%d", i), "v"))
	}
	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: atLimit},
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest(%d parameters): %v", len(atLimit), err)
	}
}

// TestClientAssertionRejectsMismatchedClientID checks RFC 7521 §4.2: a
// client_id sent alongside a client assertion must name the assertion's
// own client.
func TestClientAssertionRejectsMismatchedClientID(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	params = append(params, formParam("client_id", "some-other-client"))
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

// TestBackchannelRequestedExpiryClampedWithoutOverflow checks that a
// requested_expiry too large to convert to a time.Duration is clamped to
// the configured lifetime, not wrapped into a negative one; and that a
// small one is honoured.
func TestBackchannelRequestedExpiryClampedWithoutOverflow(t *testing.T) {
	for name, tc := range map[string]struct {
		requested json.RawMessage
		clamped   bool
	}{
		"overflowing": {json.RawMessage(`9223372037`), true},
		"huge":        {json.RawMessage(`9223372036854775807`), true},
		"small":       {json.RawMessage(`30`), false},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			params := standardBackchannelParams(t)
			params["requested_expiry"] = tc.requested
			required := beginBackchannel(t, h, params)
			if required.ExpiresIn <= 0 {
				t.Fatalf("ExpiresIn = %v, want positive", required.ExpiresIn)
			}
			if tc.clamped && required.ExpiresIn < 30*time.Second {
				t.Fatalf("ExpiresIn = %v, want the configured maximum", required.ExpiresIn)
			}
			if !tc.clamped && required.ExpiresIn != 30*time.Second {
				t.Fatalf("ExpiresIn = %v, want 30s", required.ExpiresIn)
			}
		})
	}
}
