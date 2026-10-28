package server_test

import (
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestNewRequiresWholeSecondCIBAIntervalAndLifetime: CIBA §7.3 sends
// interval and expires_in as integer seconds, so a value that isn't a
// whole number of seconds would be advertised truncated — an interval
// shorter than the one slow_down enforces, or even 0.
func TestNewRequiresWholeSecondCIBAIntervalAndLifetime(t *testing.T) {
	cases := map[string]struct {
		interval, lifetime time.Duration
		wantErr            string
	}{
		"fractional interval":    {1500 * time.Millisecond, 2 * time.Minute, "limits.backchannel_authentication_poll_interval"},
		"sub-second interval":    {time.Millisecond, 2 * time.Minute, "limits.backchannel_authentication_poll_interval"},
		"negative interval":      {-time.Second, 2 * time.Minute, "limits.backchannel_authentication_poll_interval"},
		"sub-second lifetime":    {time.Second, 900 * time.Millisecond, "limits.backchannel_authentication_request_lifetime"},
		"fractional lifetime":    {time.Second, 90500 * time.Millisecond, "limits.backchannel_authentication_request_lifetime"},
		"whole seconds accepted": {2 * time.Second, 2 * time.Minute, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := server.New(wholeSecondsCIBAConfig(t, tc.interval, tc.lifetime), wholeSecondsCIBADependencies())
			assertConfigError(t, err, tc.wantErr)
		})
	}
}

func wholeSecondsCIBAConfig(t *testing.T, interval, lifetime time.Duration) server.Config {
	t.Helper()
	backchannelEndpoint, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cfg := validConfig(t)
	cfg.Endpoints.BackchannelAuthentication = backchannelEndpoint
	cfg.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
	cfg.Limits.BackchannelAuthenticationRequestLifetime = lifetime
	cfg.Limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
	cfg.Limits.BackchannelAuthenticationPollInterval = interval
	return cfg
}

func wholeSecondsCIBADependencies() server.Dependencies {
	deps := validDependencies()
	deps.Backchannel = memstore.NewBackchannelAuthenticationStore()
	deps.BackchannelNotifier = server.NoBackchannelNotifications{}
	return deps
}

func assertConfigError(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("New = %v, want nil", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("New = %v, want an error naming %s", err, want)
	}
}
