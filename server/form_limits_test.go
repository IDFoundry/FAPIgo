package server_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

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
