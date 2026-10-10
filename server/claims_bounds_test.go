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

// claimsWithNames is a "claims" parameter requesting n distinct claims,
// each null, at location.
func claimsWithNames(location string, n int) string {
	var b strings.Builder
	b.WriteString(`{"` + location + `":{`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"c%d":null`, i)
	}
	b.WriteString(`}}`)
	return b.String()
}

// essentialACRWithValues is a "claims" parameter requesting acr as
// essential with n distinct values.
func essentialACRWithValues(n int) string {
	values := make([]string, n)
	for i := range values {
		values[i] = fmt.Sprintf(`"%x"`, i)
	}
	return acrClaims(`{"essential":true,"values":[` + strings.Join(values, ",") + `]}`)
}

func pushClaims(t *testing.T, h harness, claims string) error {
	t.Helper()
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"claims": claims})},
	})
	return err
}

// TestPushAuthorizationRequestBoundsClaimsParameter: a plain-form PAR
// request's claims parameter is bounded in size, in claims requested per
// location, and in essential acr values, each refused as invalid_request
// at the bound plus one and accepted at the bound.
func TestPushAuthorizationRequestBoundsClaimsParameter(t *testing.T) {
	tests := []struct {
		name          string
		atBound, over string
	}{
		{"id_token names", claimsWithNames("id_token", 256), claimsWithNames("id_token", 257)},
		{"userinfo names", claimsWithNames("userinfo", 256), claimsWithNames("userinfo", 257)},
		{"essential acr values", essentialACRWithValues(32), essentialACRWithValues(33)},
		{"size", `{"userinfo":{"c":{"value":"` + strings.Repeat("a", 16<<10-len(`{"userinfo":{"c":{"value":""}}}`)) + `"}}}`,
			`{"userinfo":{"c":{"value":"` + strings.Repeat("a", 16<<10-len(`{"userinfo":{"c":{"value":""}}}`)+1) + `"}}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			if err := pushClaims(t, h, tc.atBound); err != nil {
				t.Fatalf("PushAuthorizationRequest(at the bound): %v", err)
			}
			if code := serverErrorCode(t, pushClaims(t, h, tc.over)); code != server.ErrorInvalidRequest {
				t.Fatalf("PushAuthorizationRequest(over the bound) error code = %q, want invalid_request", code)
			}
		})
	}
}

// TestPushAuthorizationRequestClaimsDoSRegression: deduplicating many
// essential acr values used to be quadratic — 20,000 of them (132 KiB)
// took 13 s in one PAR request. They're now refused before parsing.
func TestPushAuthorizationRequestClaimsDoSRegression(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	start := time.Now()
	err := pushClaims(t, h, essentialACRWithValues(20000))
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("PushAuthorizationRequest error code = %q, want invalid_request", code)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("PushAuthorizationRequest took %v, want well under a second", elapsed)
	}
}

// TestCIBABoundsClaimsParameter: the backchannel endpoint applies the
// same bounds, from inside its request object.
func TestCIBABoundsClaimsParameter(t *testing.T) {
	for name, claims := range map[string]string{
		"names":                claimsWithNames("id_token", 257),
		"essential acr values": essentialACRWithValues(33),
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			params := standardBackchannelParams(t)
			params["claims"] = json.RawMessage(claims)
			action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
				HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			local, ok := action.(server.BackchannelAuthenticationLocalError)
			if !ok || local.Error.Code() != server.ErrorInvalidRequest {
				t.Fatalf("action = %#v, want an invalid_request local error", action)
			}
		})
	}
}
