package resource_test

import (
	"net/http"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

func TestSetDPoPNonce(t *testing.T) {
	h := http.Header{}
	resource.AuthorizationContext{NextDPoPNonce: "n-2"}.SetDPoPNonce(h)
	if got := h.Get("DPoP-Nonce"); got != "n-2" {
		t.Errorf("DPoP-Nonce = %q, want n-2", got)
	}
	h = http.Header{}
	resource.AuthorizationContext{}.SetDPoPNonce(h)
	if _, set := h["Dpop-Nonce"]; set {
		t.Error("SetDPoPNonce set a header with no nonce issued")
	}
}
