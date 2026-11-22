package client_test

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

const (
	// testFederatedClientID is the client ID, and Entity Identifier, of
	// newEverySliceClient's Relying Party.
	testFederatedClientID = "https://rp.example.org"
	// testPartnerAudience is the one audience beside itself
	// newEverySliceClient trusts in an ID token's aud.
	testPartnerAudience = "https://partner.example.org"
	// testUntrustedAudience is an audience newEverySliceClient doesn't
	// trust.
	testUntrustedAudience = "https://untrusted.example.org"
	// testAuthorityHint is newEverySliceClient's one authority hint.
	testAuthorityHint = "https://ta.example.org"
)

// TestNewCopiesConfigSlices: editing an element of one of Config's
// slices in place after New, as code reusing a settings buffer does,
// changes neither the ID token audiences the Client trusts nor the
// authority_hints it publishes. Each case edits one slice of the Config
// already passed to New; the Client must still accept an ID token also
// naming the partner it trusts, refuse one naming an audience it
// doesn't, and publish its one authority hint.
func TestNewCopiesConfigSlices(t *testing.T) {
	for name, edit := range map[string]func(*client.Config){
		"TrustedIDTokenAudiences": func(c *client.Config) { c.TrustedIDTokenAudiences[0] = testUntrustedAudience },
		"Federation.AuthorityHints": func(c *client.Config) {
			c.Federation.AuthorityHints[0] = "https://other-ta.example.org"
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, cfg := newEverySliceClient(t)
			edit(cfg)
			if got, want := viewOfClient(t, c, as), everySliceClientView(); !reflect.DeepEqual(got, want) {
				t.Errorf("after the Config passed to New was edited, the client shows %+v, want %+v", got, want)
			}
		})
	}
}

// TestNewConfigEditedWhileInUseNoRace edits both slices of the Config
// passed to New, storing back the values already there, until the
// Client has validated ID tokens naming another audience and signed
// Entity Configurations: under -race, this fails if the Client still
// shares either with the caller. The edits go on until then, since the
// race detector can miss a race with a goroutine that has already
// exited. Each round must also show what the Client was set up with,
// the partner's ID token accepted: an authorization that stopped
// completing would never reach the audience check this races, and so
// would pass without testing anything.
func TestNewConfigEditedWhileInUseNoRace(t *testing.T) {
	c, as, cfg := newEverySliceClient(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(stop)
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				cfg.TrustedIDTokenAudiences[0] = testPartnerAudience
				cfg.Federation.AuthorityHints[0] = testAuthorityHint
			}
		}
	})
	for range 3 {
		if got, want := viewOfClient(t, c, as), everySliceClientView(); !reflect.DeepEqual(got, want) {
			t.Fatalf("while the Config passed to New was rewritten in place, the client shows %+v, want %+v", got, want)
		}
	}
}

// everySliceClientView is what newEverySliceClient's Client shows: it
// accepts an ID token also naming testPartnerAudience, refuses one
// naming testUntrustedAudience, and publishes testAuthorityHint.
func everySliceClientView() clientView {
	return clientView{
		Accepts:        map[string]bool{testPartnerAudience: true, testUntrustedAudience: false},
		AuthorityHints: []string{testAuthorityHint},
	}
}

// newEverySliceClient is newTestClient (baseline profile) for a
// federation Relying Party with a value in each of Config's slices: it
// trusts testPartnerAudience beside itself in an ID token's aud, and
// publishes testAuthorityHint. It also returns the Config passed to New.
func newEverySliceClient(t *testing.T) (*client.Client, *fakeAS, *client.Config) {
	t.Helper()
	var passed *client.Config
	c, as, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) {
		cfg.ClientID = testFederatedClientID
		cfg.TrustedIDTokenAudiences = []string{testPartnerAudience}
		cfg.Federation = client.FederationConfig{
			EntityID: testFederatedClientID, AuthorityHints: []string{testAuthorityHint},
			Lifetime: time.Hour, Algorithm: fapi.ES256,
		}
		passed = cfg
	})
	return c, as, passed
}

// clientView is what a Client shows of the slices in its Config.
type clientView struct {
	// Accepts is, for testPartnerAudience and testUntrustedAudience,
	// whether the Client accepts an ID token naming it beside itself.
	Accepts map[string]bool
	// AuthorityHints is the authority_hints of its Entity Configuration.
	AuthorityHints []string
}

func viewOfClient(t *testing.T, c *client.Client, as *fakeAS) clientView {
	t.Helper()
	view := clientView{Accepts: map[string]bool{}}
	for _, audience := range []string{testPartnerAudience, testUntrustedAudience} {
		as.idTokenAudience = []string{testFederatedClientID, audience}
		view.Accepts[audience] = completeAuthorization(t, c, as) == nil
	}
	statement, err := c.EntityConfiguration(context.Background(), nil)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}
	parsed, err := intfed.Parse(statement)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	view.AuthorityHints = parsed.ClaimedAuthorityHints()
	return view
}

// completeAuthorization runs one authorization of c through as, and
// returns CompleteAuthorization's error.
func completeAuthorization(t *testing.T, c *client.Client, as *fakeAS) error {
	t.Helper()
	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	_, err = c.CompleteAuthorization(ctx, client.AuthorizationCallback{
		RawQuery: as.callbackFor(t, as.lastState, "auth-code-123", ""), Session: session.Handle(),
	})
	return err
}
