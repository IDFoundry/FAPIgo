package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/internal/clientassertion"
	"github.com/osanderson/go-fapi/internal/jarm"
	"github.com/osanderson/go-fapi/server"
)

func beginInteraction(t *testing.T, h harness) server.InteractionHandle {
	t.Helper()
	action := pushAndBegin(t, h, nil)
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	return required.Handle
}

// beginInteractionViaRequestObject pushes and begins an authorization
// using a signed request object, for profiles that require one.
func beginInteractionViaRequestObject(t *testing.T, h harness) server.InteractionHandle {
	t.Helper()
	requestObj := h.requestObject(t, standardAuthParams(t))
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", requestObj),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(),
		ClientID:   testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	return required.Handle
}

func authorizeResult(t *testing.T) server.InteractionResult {
	t.Helper()
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(time.Now(), "urn:mace:incommon:iap:silver", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	return server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}})
}

func TestCompleteAuthorizationSuccessPlainProfile(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}

	dest := redirect.Destination().URL()
	if dest.Scheme != "https" || dest.Host != "rp.example" || dest.Path != "/callback" {
		t.Fatalf("Destination = %q, want to start with %q", dest.String(), testRedirectURI)
	}
	q := dest.Query()
	if q.Get("code") == "" {
		t.Fatalf("Destination missing code parameter: %q", dest.String())
	}
	if q.Get("state") != "opaque-state" {
		t.Fatalf("Destination state = %q, want %q", q.Get("state"), "opaque-state")
	}
	if q.Get("iss") != testIssuer {
		t.Fatalf("Destination iss = %q, want %q (RFC 9207)", q.Get("iss"), testIssuer)
	}

	codes := h.grants.all()
	if len(codes) != 1 {
		t.Fatalf("len(codes) = %d, want 1", len(codes))
	}
	if codes[0].Subject != "user-1" {
		t.Fatalf("codes[0].Subject = %q, want %q", codes[0].Subject, "user-1")
	}
	if codes[0].ClientID != testClientID {
		t.Fatalf("codes[0].ClientID = %q, want %q", codes[0].ClientID, testClientID)
	}
}

func TestCompleteAuthorizationSuccessMessageSigningProfile(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)
	handle := beginInteractionViaRequestObject(t, h)

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		if localErr, ok2 := result.(server.AuthorizationLocalError); ok2 {
			t.Fatalf("result = AuthorizationLocalError: code=%s desc=%s underlying=%v", localErr.Error.Code(), localErr.Error.PublicDescription(), localErr.Error)
		}
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}

	dest := redirect.Destination().URL()
	responseJWT := dest.Query().Get("response")
	if responseJWT == "" {
		t.Fatalf("Destination missing response parameter: %q", dest.String())
	}

	parsed, err := jarm.Parse(responseJWT)
	if err != nil {
		t.Fatalf("jarm.Parse: %v", err)
	}
	verified, err := parsed.Verify(&h.serverKey.PublicKey, jarm.VerifyPolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testClientID.String(),
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("jarm Verify: %v", err)
	}
	var code, state string
	if err := json.Unmarshal(verified.Parameters["code"], &code); err != nil {
		t.Fatalf("unmarshal code: %v", err)
	}
	if err := json.Unmarshal(verified.Parameters["state"], &state); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if code == "" {
		t.Fatalf("JARM response missing code claim")
	}
	if state != "opaque-state" {
		t.Fatalf("JARM response state = %q, want %q", state, "opaque-state")
	}
}

func TestCompleteAuthorizationDeny(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: server.Deny("user declined consent"),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	denyDest := redirect.Destination().URL()
	q := denyDest.Query()
	if q.Get("error") != "access_denied" {
		t.Fatalf("error = %q, want %q", q.Get("error"), "access_denied")
	}
	if q.Get("error_description") != "user declined consent" {
		t.Fatalf("error_description = %q, want %q", q.Get("error_description"), "user declined consent")
	}
	if q.Get("iss") != testIssuer {
		t.Fatalf("iss = %q, want %q (RFC 9207)", q.Get("iss"), testIssuer)
	}
	if len(h.grants.all()) != 0 {
		t.Fatalf("len(codes) = %d, want 0 (no code should be issued on denial)", len(h.grants.all()))
	}
}

func TestCompleteAuthorizationAuthenticationFailed(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: server.AuthenticationFailed("mfa timeout"),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	authFailedDest := redirect.Destination().URL()
	if got := authFailedDest.Query().Get("error"); got != "login_required" {
		t.Fatalf("error = %q, want %q", got, "login_required")
	}
	if got := authFailedDest.Query().Get("iss"); got != testIssuer {
		t.Fatalf("iss = %q, want %q (RFC 9207)", got, testIssuer)
	}
}

func TestCompleteAuthorizationRejectsInvalidHandle(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: server.InteractionHandle{}, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	localErr, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestCompleteAuthorizationHandleIsSingleUse(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)

	first, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("first CompleteAuthorization: %v", err)
	}
	if _, ok := first.(server.AuthorizationRedirect); !ok {
		t.Fatalf("first result = %T, want AuthorizationRedirect", first)
	}

	second, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("second CompleteAuthorization: %v", err)
	}
	localErr, ok := second.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("second result = %T, want AuthorizationLocalError", second)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestCompleteAuthorizationRejectsScopeExceedingRequest(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)

	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(time.Now(), "", nil)
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	overGrant := server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "payments"}})

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: overGrant,
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	localErr, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestCompleteAuthorizationRejectsZeroValueSubject(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)

	authCtx, err := server.NewAuthenticationContext(time.Now(), "", nil)
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	// A zero-value AuthenticatedSubject bypasses NewAuthenticatedSubject.
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle,
		Result: server.Authorize(server.AuthenticatedSubject{}, authCtx, server.GrantedAuthorization{}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	localErr, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	if localErr.Error.Code() != server.ErrorServerError {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorServerError)
	}
}

func TestCompleteAuthorizationAuditsOutcomes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)

	if _, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}

	var success, failure int
	for _, e := range h.audit.all() {
		if e.Type != server.AuditEventCompleteAuthorization {
			continue
		}
		if e.Outcome == server.AuditOutcomeSuccess {
			success++
		} else {
			failure++
		}
	}
	if success != 1 || failure != 0 {
		t.Fatalf("CompleteAuthorization audit events: success=%d failure=%d, want success=1 failure=0", success, failure)
	}
}

func TestNewSubjectIDRejectsEmpty(t *testing.T) {
	if _, err := server.NewSubjectID(""); err == nil {
		t.Fatalf("NewSubjectID(\"\") = nil error, want error")
	}
}

func TestNewAuthenticatedSubjectRejectsZeroValueID(t *testing.T) {
	if _, err := server.NewAuthenticatedSubject(server.SubjectID{}); err == nil {
		t.Fatalf("NewAuthenticatedSubject(zero SubjectID) = nil error, want error")
	}
}

func TestNewAuthenticationContextRejectsZeroAuthTime(t *testing.T) {
	if _, err := server.NewAuthenticationContext(time.Time{}, "", nil); err == nil {
		t.Fatalf("NewAuthenticationContext(zero authTime) = nil error, want error")
	}
}
