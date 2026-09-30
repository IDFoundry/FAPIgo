package union

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

func TestInteractionCookie(t *testing.T) {
	handle, err := server.ParseInteractionHandle("aGFuZGxlLWZvci1hLXNpZ24taW4tdGVzdC0wMDAwMDAwMDAwMDA")
	if err != nil {
		t.Skipf("handle format: %v", err)
	}
	in := server.InteractionRequest{ClientID: "https://bank.southport.localhost", Scope: []string{"openid"},
		RequestedClaims: server.RequestedClaims{IDToken: []string{"given_name"}}}
	now := time.Now()
	issuer := &identityProvider{cookieKey: []byte("key-shared-by-every-instance-000")}
	sealed, err := issuer.sealInteraction(handle, in, now)
	if err != nil {
		t.Fatal(err)
	}

	// Another instance of the same provider, holding the same key.
	other := &identityProvider{cookieKey: []byte("key-shared-by-every-instance-000")}
	gotHandle, gotIn, err := other.openInteraction(sealed, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("openInteraction: %v", err)
	}
	if gotHandle.String() != handle.String() || !reflect.DeepEqual(gotIn, in) {
		t.Errorf("opened %v, %+v; want %v, %+v", gotHandle, gotIn, handle, in)
	}

	payload, mac, _ := cutLast(sealed, "~")
	for name, tc := range map[string]struct {
		value string
		key   string
		at    time.Time
	}{
		"altered interaction": {strings.Replace(payload, "v1.", "v1.A", 1) + "~" + mac, "key-shared-by-every-instance-000", now},
		"another provider":    {sealed, "a-different-providers-key-000000", now},
		"expired":             {sealed, "key-shared-by-every-instance-000", now.Add(pendingLifetime + time.Minute)},
		"no signature":        {payload, "key-shared-by-every-instance-000", now},
	} {
		p := &identityProvider{cookieKey: []byte(tc.key)}
		if _, _, err := p.openInteraction(tc.value, tc.at); err == nil {
			t.Errorf("openInteraction(%s) = nil error, want error", name)
		}
	}
}
