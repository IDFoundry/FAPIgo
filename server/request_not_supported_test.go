package server_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// OIDC Core §6.1: an OP that doesn't support the request parameter at
// the authorization endpoint answers request_not_supported. This server
// takes request objects only by PAR.
func TestBeginAuthorizationRefusesARequestObjectWithRequestNotSupported(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	r := httptest.NewRequest("GET", "/authorize?client_id="+testClientID.String()+"&request=eyJhbGciOiJFUzI1NiJ9.e30.c2ln", nil)
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("BeginAuthorizationRequestFromHTTP: %v", err)
	}
	if req.Request == "" {
		t.Fatal("BeginAuthorizationRequestFromHTTP dropped the request parameter")
	}
	action, err := h.server.BeginAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	local, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	if local.Error.Code() != server.ErrorRequestNotSupported {
		t.Fatalf("error code = %q, want %q", local.Error.Code(), server.ErrorRequestNotSupported)
	}
}

func TestBeginAuthorizationRequestFromHTTPRefusesARepeatedRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/authorize?client_id=c&request=a&request=b", nil)
	_, err := server.BeginAuthorizationRequestFromHTTP(r)
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}
