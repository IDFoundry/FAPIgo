package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

func emptyScopeSubject(t *testing.T) (server.AuthenticatedSubject, server.AuthenticationContext) {
	t.Helper()
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(time.Now(), "acr-1", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	return subject, authCtx
}

// RFC 6749 §5.1: a token response omits scope only when it is "identical
// to the scope requested", and §3.3's scope has at least one value, so an
// empty grant of a request with a scope can't be told to the client: it
// would take the whole request as granted. CompleteAuthorization refuses
// it.
func TestCompleteAuthorizationRefusesEmptyScopeGrant(t *testing.T) {
	for name, scope := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			handle := beginInteractionRequestingScope(t, h, "openid accounts offline_access")
			subject, authCtx := emptyScopeSubject(t)
			result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
				Handle: handle,
				Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: scope}),
			})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			localErr, ok := result.(server.AuthorizationLocalError)
			if !ok {
				t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
			}
			if localErr.Error.Code() != server.ErrorInvalidRequest {
				t.Fatalf("Error.Code() = %v, want %v", localErr.Error.Code(), server.ErrorInvalidRequest)
			}
		})
	}
}

func TestCompleteBackchannelAuthenticationRefusesEmptyScopeGrant(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	subject, authCtx := emptyScopeSubject(t)
	err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{}),
	})
	if err == nil {
		t.Fatal("CompleteBackchannelAuthentication = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %v, want %v", code, server.ErrorInvalidRequest)
	}
}

// A refresh request's scope of only spaces names no scope, which would
// issue an access token without any and a response omitting scope.
func TestRefreshAccessTokenRefusesBlankScope(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	tokens, _ := exchangeForTokensWithOfflineAccess(t, h)
	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), tokens.RefreshToken.Reveal(), "   ")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err == nil {
		t.Fatal("RefreshAccessToken succeeded, want invalid_scope")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidScope {
		t.Fatalf("error code = %v, want %v", code, server.ErrorInvalidScope)
	}
}
