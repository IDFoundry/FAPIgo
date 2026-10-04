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

// TestMTLSEndpointsApplyEveryAdvertisedAlias covers RFC 8705 §5: a client
// doing mutual TLS, for client authentication or for certificate-bound
// tokens alike, uses every alias the server advertises for an endpoint it
// calls directly. Authorization, which the user agent calls, is never
// aliased.
func TestMTLSEndpointsApplyEveryAdvertisedAlias(t *testing.T) {
	for name, apply := range map[string]func(*client.MTLSEndpoints, *client.Endpoints) bool{
		"ApplyForSenderConstrain": (*client.MTLSEndpoints).ApplyForSenderConstrain,
		"ApplyForClientAuth":      (*client.MTLSEndpoints).ApplyForClientAuth,
	} {
		t.Run(name, func(t *testing.T) {
			aliases := &client.MTLSEndpoints{
				Token:                      mustEndpointURL(t, "https://mtls.example.com/token"),
				PushedAuthorizationRequest: mustEndpointURL(t, "https://mtls.example.com/par"),
				BackchannelAuthentication:  mustEndpointURL(t, "https://mtls.example.com/backchannel"),
				Revocation:                 mustEndpointURL(t, "https://mtls.example.com/revoke"),
			}
			endpoints := client.Endpoints{
				Authorization:              mustEndpointURL(t, "https://as.example.com/authorize"),
				Token:                      mustEndpointURL(t, "https://as.example.com/token"),
				PushedAuthorizationRequest: mustEndpointURL(t, "https://as.example.com/par"),
				BackchannelAuthentication:  mustEndpointURL(t, "https://as.example.com/backchannel"),
				Revocation:                 mustEndpointURL(t, "https://as.example.com/revoke"),
			}
			if !apply(aliases, &endpoints) {
				t.Fatalf("%s() = false, want true", name)
			}
			for field, got := range map[string][2]string{
				"Token":                      {endpoints.Token.String(), aliases.Token.String()},
				"PushedAuthorizationRequest": {endpoints.PushedAuthorizationRequest.String(), aliases.PushedAuthorizationRequest.String()},
				"BackchannelAuthentication":  {endpoints.BackchannelAuthentication.String(), aliases.BackchannelAuthentication.String()},
				"Revocation":                 {endpoints.Revocation.String(), aliases.Revocation.String()},
				"Authorization":              {endpoints.Authorization.String(), "https://as.example.com/authorize"},
			} {
				if got[0] != got[1] {
					t.Errorf("%s = %s, want %s", field, got[0], got[1])
				}
			}
		})
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
	if aliases.ApplyForSenderConstrain(&endpoints) {
		t.Error("ApplyForSenderConstrain(nil) = true, want false")
	}
	if endpoints != newEndpoints() {
		t.Errorf("ApplyForSenderConstrain(nil) changed endpoints: got %+v", endpoints)
	}

	endpoints = newEndpoints()
	if aliases.ApplyForClientAuth(&endpoints) {
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

	if !aliases.ApplyForSenderConstrain(&endpoints) {
		t.Fatal("ApplyForSenderConstrain() = false, want true")
	}
	if got, want := endpoints.Token.String(), aliases.Token.String(); got != want {
		t.Errorf("Token = %s, want alias %s", got, want)
	}
	if got, want := endpoints.BackchannelAuthentication.String(), "https://as.example.com/backchannel"; got != want {
		t.Errorf("BackchannelAuthentication = %s, want untouched %s (alias never advertised one)", got, want)
	}
}
