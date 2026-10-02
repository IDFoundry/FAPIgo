package server_test

import (
	"context"
	"encoding/json"
	"reflect"
	"sync/atomic"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// countingRARPolicy is fakeRARPolicy, counting the times it's asked.
type countingRARPolicy struct {
	fakeRARPolicy
	calls *atomic.Int32
}

func (p countingRARPolicy) Authorize(ctx context.Context, clientID fapi.ClientID, requested []json.RawMessage) ([]json.RawMessage, error) {
	p.calls.Add(1)
	return p.fakeRARPolicy.Authorize(ctx, clientID, requested)
}

func newCountingPolicy() countingRARPolicy {
	return countingRARPolicy{fakeRARPolicy: fakeRARPolicy{allow: map[string]bool{"payment": true}}, calls: &atomic.Int32{}}
}

const paymentDetails = `[{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`

// unregisteredTypes are registrations under which "payment" isn't
// allowed: none at all, which is the default, and another type only.
var unregisteredTypes = map[string][]string{"no types": nil, "another type": {"account_information"}}

// TestPushAuthorizationRequestRefusesUnregisteredRARType covers RFC 9396
// §10's authorization_details_types at PAR: a type the client isn't
// registered for is invalid_authorization_details, and the RARPolicy is
// never asked.
func TestPushAuthorizationRequestRefusesUnregisteredRARType(t *testing.T) {
	for name, types := range unregisteredTypes {
		t.Run(name, func(t *testing.T) {
			policy := newCountingPolicy()
			h := newHarnessWithRARTypes(t, server.ProfileFAPISecurity, newTestRARRegistry(t), policy, policy, types)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"authorization_details": paymentDetails})},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidAuthorizationDetails {
				t.Fatalf("error code %q, want %q", code, server.ErrorInvalidAuthorizationDetails)
			}
			if n := policy.calls.Load(); n != 0 {
				t.Errorf("RARPolicy asked %d times, want never", n)
			}
		})
	}
}

func TestBeginBackchannelAuthenticationRefusesUnregisteredRARType(t *testing.T) {
	for name, types := range unregisteredTypes {
		t.Run(name, func(t *testing.T) {
			policy := newCountingPolicy()
			h := newHarnessWithRARTypes(t, server.ProfileFAPISecurity, newTestRARRegistry(t), policy, policy, types)
			params := standardBackchannelParams(t)
			params["authorization_details"] = json.RawMessage(paymentDetails)
			action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
				HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			refused, ok := action.(server.BackchannelAuthenticationLocalError)
			if !ok || refused.Error.Code() != server.ErrorInvalidAuthorizationDetails {
				t.Fatalf("action = %#v, want a local %s error", action, server.ErrorInvalidAuthorizationDetails)
			}
			if n := policy.calls.Load(); n != 0 {
				t.Errorf("RARPolicy asked %d times, want never", n)
			}
		})
	}
}

func TestRequestClientCredentialsTokenRefusesUnregisteredRARType(t *testing.T) {
	for name, types := range unregisteredTypes {
		t.Run(name, func(t *testing.T) {
			policy := newCountingPolicy()
			h := newHarnessWithClientCredentialsGrantAndRARTypes(t, newTestRARRegistry(t), policy, types)
			params := append(clientCredentialsFormParams(h.clientAssertion(t), "accounts"), formParam("authorization_details", paymentDetails))
			_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
				HTTP: server.FormRequest{Parameters: params}, DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidAuthorizationDetails {
				t.Fatalf("error code %q, want %q", code, server.ErrorInvalidAuthorizationDetails)
			}
			if n := policy.calls.Load(); n != 0 {
				t.Errorf("RARPolicy asked %d times, want never", n)
			}
		})
	}
}

// TestAllowRequestedAuthorizationDetails covers the pass-through policy
// granting a registered type exactly as requested.
func TestAllowRequestedAuthorizationDetails(t *testing.T) {
	h := newHarnessWithClientCredentialsGrantAndRAR(t, newTestRARRegistry(t), server.AllowRequestedAuthorizationDetails{})
	params := append(clientCredentialsFormParams(h.clientAssertion(t), "accounts"), formParam("authorization_details", paymentDetails))
	result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: params}, DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if !sameJSON(t, result.AuthorizationDetails, json.RawMessage(paymentDetails)) {
		t.Errorf("granted %s, want exactly what was requested", result.AuthorizationDetails)
	}
}

// sameJSON reports whether a and b are the same JSON value.
func sameJSON(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		t.Fatalf("decode %s: %v", a, err)
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return reflect.DeepEqual(va, vb)
}
