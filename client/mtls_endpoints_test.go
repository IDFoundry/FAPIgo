package client_test

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

func mustEndpointURL(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(raw)
	if err != nil {
		t.Fatalf("ParseEndpointURL(%q): %v", raw, err)
	}
	return u
}

// TestMTLSEndpointsApplyForSenderConstrainOverridesTokenAndBackchannel
// covers ApplyForSenderConstrain's own field selection: Token and
// BackchannelAuthentication move to their mTLS alias; every other
// endpoint (Authorization, PushedAuthorizationRequest) is untouched.
func TestMTLSEndpointsApplyForSenderConstrainOverridesTokenAndBackchannel(t *testing.T) {
	aliases := &client.MTLSEndpoints{
		Token:                     mustEndpointURL(t, "https://mtls.example.com/token"),
		BackchannelAuthentication: mustEndpointURL(t, "https://mtls.example.com/backchannel"),
	}
	endpoints := client.Endpoints{
		Authorization:              mustEndpointURL(t, "https://as.example.com/authorize"),
		Token:                      mustEndpointURL(t, "https://as.example.com/token"),
		PushedAuthorizationRequest: mustEndpointURL(t, "https://as.example.com/par"),
		BackchannelAuthentication:  mustEndpointURL(t, "https://as.example.com/backchannel"),
	}

	if ok := aliases.ApplyForSenderConstrain(&endpoints); !ok {
		t.Fatal("ApplyForSenderConstrain() = false, want true")
	}
	if got, want := endpoints.Token.String(), aliases.Token.String(); got != want {
		t.Errorf("Token = %s, want alias %s", got, want)
	}
	if got, want := endpoints.BackchannelAuthentication.String(), aliases.BackchannelAuthentication.String(); got != want {
		t.Errorf("BackchannelAuthentication = %s, want alias %s", got, want)
	}
	if got, want := endpoints.Authorization.String(), "https://as.example.com/authorize"; got != want {
		t.Errorf("Authorization = %s, want untouched %s", got, want)
	}
	if got, want := endpoints.PushedAuthorizationRequest.String(), "https://as.example.com/par"; got != want {
		t.Errorf("PushedAuthorizationRequest = %s, want untouched %s", got, want)
	}
}

// TestMTLSEndpointsApplyForClientAuthOverridesTokenAndPAR covers
// ApplyForClientAuth's own field selection: Token and
// PushedAuthorizationRequest move to their mTLS alias;
// BackchannelAuthentication is untouched (only ApplyForSenderConstrain
// ever moves it).
func TestMTLSEndpointsApplyForClientAuthOverridesTokenAndPAR(t *testing.T) {
	aliases := &client.MTLSEndpoints{
		Token:                      mustEndpointURL(t, "https://mtls.example.com/token"),
		PushedAuthorizationRequest: mustEndpointURL(t, "https://mtls.example.com/par"),
	}
	endpoints := client.Endpoints{
		Token:                      mustEndpointURL(t, "https://as.example.com/token"),
		PushedAuthorizationRequest: mustEndpointURL(t, "https://as.example.com/par"),
		BackchannelAuthentication:  mustEndpointURL(t, "https://as.example.com/backchannel"),
	}

	if ok := aliases.ApplyForClientAuth(&endpoints); !ok {
		t.Fatal("ApplyForClientAuth() = false, want true")
	}
	if got, want := endpoints.Token.String(), aliases.Token.String(); got != want {
		t.Errorf("Token = %s, want alias %s", got, want)
	}
	if got, want := endpoints.PushedAuthorizationRequest.String(), aliases.PushedAuthorizationRequest.String(); got != want {
		t.Errorf("PushedAuthorizationRequest = %s, want alias %s", got, want)
	}
	if got, want := endpoints.BackchannelAuthentication.String(), "https://as.example.com/backchannel"; got != want {
		t.Errorf("BackchannelAuthentication = %s, want untouched %s", got, want)
	}
}

// TestMTLSEndpointsApplyNilReportsFalseAndLeavesEndpointsUntouched
// covers both methods' nil-receiver branch: a server that never
// advertised mtls_endpoint_aliases at all leaves endpoints exactly as
// given and reports false, letting the caller decide whether that's
// fatal.
func TestMTLSEndpointsApplyNilReportsFalseAndLeavesEndpointsUntouched(t *testing.T) {
	var aliases *client.MTLSEndpoints
	newEndpoints := func() client.Endpoints {
		return client.Endpoints{
			Token:                      mustEndpointURL(t, "https://as.example.com/token"),
			PushedAuthorizationRequest: mustEndpointURL(t, "https://as.example.com/par"),
			BackchannelAuthentication:  mustEndpointURL(t, "https://as.example.com/backchannel"),
		}
	}

	endpoints := newEndpoints()
	if ok := aliases.ApplyForSenderConstrain(&endpoints); ok {
		t.Error("ApplyForSenderConstrain(nil) = true, want false")
	}
	if endpoints != newEndpoints() {
		t.Errorf("ApplyForSenderConstrain(nil) changed endpoints: got %+v", endpoints)
	}

	endpoints = newEndpoints()
	if ok := aliases.ApplyForClientAuth(&endpoints); ok {
		t.Error("ApplyForClientAuth(nil) = true, want false")
	}
	if endpoints != newEndpoints() {
		t.Errorf("ApplyForClientAuth(nil) changed endpoints: got %+v", endpoints)
	}
}

// TestMTLSEndpointsApplyPartialLeavesUnadvertisedFieldsUntouched
// covers the case where only one of the two relevant fields was
// advertised: the other stays whatever endpoints already had.
func TestMTLSEndpointsApplyPartialLeavesUnadvertisedFieldsUntouched(t *testing.T) {
	aliases := &client.MTLSEndpoints{
		Token: mustEndpointURL(t, "https://mtls.example.com/token"),
	}
	endpoints := client.Endpoints{
		Token:                     mustEndpointURL(t, "https://as.example.com/token"),
		BackchannelAuthentication: mustEndpointURL(t, "https://as.example.com/backchannel"),
	}

	if ok := aliases.ApplyForSenderConstrain(&endpoints); !ok {
		t.Fatal("ApplyForSenderConstrain() = false, want true")
	}
	if got, want := endpoints.Token.String(), aliases.Token.String(); got != want {
		t.Errorf("Token = %s, want alias %s", got, want)
	}
	if got, want := endpoints.BackchannelAuthentication.String(), "https://as.example.com/backchannel"; got != want {
		t.Errorf("BackchannelAuthentication = %s, want untouched %s (alias never advertised one)", got, want)
	}
}
