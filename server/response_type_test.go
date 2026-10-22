package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestPushAuthorizationRequestRefusesResponseTypesOtherThanCode: FAPI 2.0
// Security Profile §5.3.2.2 allows only the authorization code flow, so
// a pushed request whose response_type is anything but exactly "code"
// is refused: as unsupported_response_type for an implicit or hybrid
// type, or a miscased one (RFC 6749 §4.1.2.1), and as invalid_request
// when it's empty or missing.
func TestPushAuthorizationRequestRefusesResponseTypesOtherThanCode(t *testing.T) {
	missing := "\x00missing"
	for name, responseType := range map[string]string{
		"token":         "token",
		"id_token":      "id_token",
		"code id_token": "code id_token",
		"code token":    "code token",
		"miscased":      "Code",
		"padded":        " code",
		"empty":         "",
		"missing":       missing,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			err := pushResponseType(t, h, responseType, responseType == missing)
			want := server.ErrorUnsupportedResponseType
			if responseType == "" || responseType == missing {
				want = server.ErrorInvalidRequest
			}
			if code := serverErrorCode(t, err); code != want {
				t.Fatalf("PushAuthorizationRequest error code = %q, want %q", code, want)
			}
		})
	}
}

// pushResponseType pushes a plain request whose response_type is
// responseType, or that has none if omit.
func pushResponseType(t *testing.T, h harness, responseType string, omit bool) error {
	t.Helper()
	var params []server.FormParameter
	for _, p := range plainFormParameters(t, h.clientAssertion(t), nil) {
		if p.Name != "response_type" {
			params = append(params, p)
		}
	}
	if !omit {
		params = append(params, formParam("response_type", responseType))
	}
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	return err
}
