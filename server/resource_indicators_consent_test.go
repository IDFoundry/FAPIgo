package server_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// beginForResources pushes a request naming resources and begins its
// interaction.
func beginForResources(t *testing.T, h harness, resources ...string) server.InteractionRequired {
	t.Helper()
	pushed, err := pushWithResources(t, h, resources...)
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushed.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	return required
}

// completeGrantingResources approves required as user-1, granting
// resources, and returns the code, or the local error.
func completeGrantingResources(t *testing.T, h harness, required server.InteractionRequired, resources []string) (string, *server.Error) {
	t.Helper()
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: authorizedAsGranting(t, h, "user-1", server.GrantedAuthorization{
			Scope: []string{"openid", "accounts", "offline_access"}, Resources: resources,
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	switch r := result.(type) {
	case server.AuthorizationRedirect:
		dest := r.Destination().URL()
		return dest.Query().Get("code"), nil
	case server.AuthorizationLocalError:
		return "", r.Error
	default:
		t.Fatalf("result = %T", result)
		return "", nil
	}
}

func authorizedAsGranting(t *testing.T, h harness, subject string, grant server.GrantedAuthorization) server.InteractionResult {
	t.Helper()
	subjectID, err := server.NewSubjectID(subject)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatal(err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "", []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	return server.Authorize(authenticated, authCtx, grant)
}

// The consent step sees the resources a token would be for, the
// client's default among them, and can narrow them to a subset of what
// was requested, never widen them.
func TestInteractionRequestResources(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB, resourceC}, nil)

	if got := beginForResources(t, h).Interaction.Resources; got != nil {
		t.Errorf("Resources of a request naming none = %q, want nil", got)
	}
	required := beginForResources(t, h, resourceA, resourceB, resourceA)
	if want := []string{resourceA, resourceB}; !reflect.DeepEqual(required.Interaction.Resources, want) {
		t.Errorf("Resources = %q, want %q", required.Interaction.Resources, want)
	}
	restrictClientResources(t, h, resourceC)
	if got, want := beginForResources(t, h).Interaction.Resources, []string{resourceC}; !reflect.DeepEqual(got, want) {
		t.Errorf("Resources of a confined client's request = %q, want its default %q", got, want)
	}
}

func TestCompleteAuthorizationNarrowsResources(t *testing.T) {
	for name, tc := range map[string]struct {
		requested, granted []string
		want               any
	}{
		"omitted grants all": {requested: []string{resourceA, resourceB}, want: []any{resourceA, resourceB}},
		"narrowed":           {requested: []string{resourceA, resourceB}, granted: []string{resourceB, resourceB}, want: resourceB},
		"none requested":     {want: testIssuer},
	} {
		t.Run(name, func(t *testing.T) {
			h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
			code, localErr := completeGrantingResources(t, h, beginForResources(t, h, tc.requested...), tc.granted)
			if localErr != nil {
				t.Fatalf("CompleteAuthorization: %v", localErr)
			}
			result, err := exchangeWithResources(t, h, code)
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			wantAudience(t, result, tc.want)
			// The grant is what was approved: a refresh can't name what
			// the user left out.
			if tc.granted != nil {
				_, err := refreshWithResources(t, h, result.RefreshToken.Reveal(), resourceA)
				wantErrorCode(t, err, server.ErrorInvalidTarget)
			}
		})
	}
}

func TestCompleteAuthorizationRefusesUnrequestedResources(t *testing.T) {
	for name, tc := range map[string]struct {
		requested, granted []string
	}{
		"another":        {requested: []string{resourceA}, granted: []string{resourceB}},
		"one more":       {requested: []string{resourceA}, granted: []string{resourceA, resourceB}},
		"none requested": {granted: []string{resourceA}},
	} {
		t.Run(name, func(t *testing.T) {
			h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
			_, localErr := completeGrantingResources(t, h, beginForResources(t, h, tc.requested...), tc.granted)
			if localErr == nil || localErr.Code() != server.ErrorInvalidRequest {
				t.Fatalf("CompleteAuthorization error = %v, want invalid_request", localErr)
			}
		})
	}
}

func TestBackchannelInteractionResources(t *testing.T) {
	for name, tc := range map[string]struct {
		granted []string
		want    any
		wantErr server.ErrorCode
	}{
		"omitted grants all": {want: []any{resourceA, resourceB}},
		"narrowed":           {granted: []string{resourceA}, want: resourceA},
		"not requested":      {granted: []string{resourceC}, wantErr: server.ErrorInvalidRequest},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
				cfg.Resources = []string{resourceA, resourceB, resourceC}
			})
			required, ok := beginResourceCIBA(t, h, []string{resourceA, resourceB}).(server.BackchannelInteractionRequired)
			if !ok {
				t.Fatal("BeginBackchannelAuthentication didn't require an interaction")
			}
			want := []string{resourceA, resourceB}
			if !reflect.DeepEqual(required.Interaction.Resources, want) {
				t.Errorf("Interaction.Resources = %q, want %q", required.Interaction.Resources, want)
			}
			looked, err := h.server.LookupBackchannelInteraction(context.Background(), required.Handle)
			if err != nil {
				t.Fatalf("LookupBackchannelInteraction: %v", err)
			}
			if !reflect.DeepEqual(looked.Resources, want) {
				t.Errorf("looked-up Resources = %q, want %q", looked.Resources, want)
			}

			err = h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
				Handle: required.Handle,
				Result: authorizedAsGranting(t, h, "user-1", server.GrantedAuthorization{Scope: []string{"openid", "accounts"}, Resources: tc.granted}),
			})
			if tc.wantErr != "" {
				wantErrorCode(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("CompleteBackchannelAuthentication: %v", err)
			}
			result, err := cibaTokenWithResources(t, h, required.AuthReqID.String())
			if err != nil {
				t.Fatalf("ExchangeBackchannelAuthentication: %v", err)
			}
			wantAudience(t, result, tc.want)
		})
	}
}
