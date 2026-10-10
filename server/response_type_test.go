package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestPushAuthorizationRequestRefusesResponseTypesOtherThanCode: FAPI 2.0
// Security Profile §5.3.2.2 allows only the authorization code flow, so
// a pushed request whose response_type is anything but exactly "code"
// (an implicit or hybrid type, a miscased or empty value, or none at
// all) is refused as invalid_request.
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
			var params []server.FormParameter
			for _, p := range plainFormParameters(t, h.clientAssertion(t), nil) {
				if p.Name != "response_type" {
					params = append(params, p)
				}
			}
			if responseType != missing {
				params = append(params, formParam("response_type", responseType))
			}
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: params},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("PushAuthorizationRequest error code = %q, want invalid_request", code)
			}
		})
	}
}
