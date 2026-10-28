package client_test

import (
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestNewCapsCIBARequestLifetime: FAPI-CIBA §5.2.3 (via FAPI 1.0
// Advanced §5.2.3) caps the signed authentication request's exp at 60
// minutes after nbf, as New already does for PAR's request object.
func TestNewCapsCIBARequestLifetime(t *testing.T) {
	cases := map[string]struct {
		lifetime time.Duration
		wantErr  bool
	}{
		"24 hours":          {24 * time.Hour, true},
		"just over an hour": {time.Hour + time.Second, true},
		"exactly an hour":   {time.Hour, false},
		"one minute":        {time.Minute, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Endpoints.BackchannelAuthentication = mustParseEndpointURL(t, testIssuer+"/backchannel-authenticate")
			cfg.Algorithms.BackchannelAuthenticationRequest = fapi.ES256
			cfg.Limits.BackchannelAuthenticationRequestLifetime = tc.lifetime
			_, err := client.New(cfg, validDependencies(t))
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("New = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "limits.backchannel_authentication_request_lifetime") {
				t.Fatalf("New = %v, want an error naming limits.backchannel_authentication_request_lifetime", err)
			}
		})
	}
}
