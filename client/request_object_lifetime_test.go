package client_test

import (
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestNewCapsRequestObjectLifetime: FAPI 2.0 Message Signing §5.3.2
// item 4 has a client send a request object whose exp is at most 60
// minutes away, and a server following §5.3.1 item 4 refuses a longer
// one, so New refuses a longer configured lifetime.
func TestNewCapsRequestObjectLifetime(t *testing.T) {
	for lifetime, wantOK := range map[time.Duration]bool{
		time.Minute:                  true,
		60 * time.Minute:             true,
		60*time.Minute + time.Second: false,
	} {
		cfg := validConfig(t)
		cfg.PushedRequestEncoding = client.PushedRequestEncodingRequestObject
		cfg.Algorithms.RequestObject = fapi.ES256
		cfg.Limits.RequestObjectLifetime = lifetime
		_, err := client.New(cfg, validDependencies(t))
		if wantOK && err != nil {
			t.Errorf("New(lifetime %v) = %v, want accepted", lifetime, err)
		}
		if !wantOK && (err == nil || !strings.Contains(err.Error(), "request_object_lifetime")) {
			t.Errorf("New(lifetime %v) = %v, want refused", lifetime, err)
		}
	}
}
