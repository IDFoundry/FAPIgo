package backchannelhttp

import (
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
)

// NewWithClient exposes newWithClient to this package's tests, for a
// fake client whose failure modes a real transport can't produce.
func NewWithClient(client fapihttp.HTTPClient, timeout time.Duration) *Notifier {
	return newWithClient(client, timeout)
}
