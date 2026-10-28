package server_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestBackchannelDeliveryModesFollowNotifier: ping (CIBA §10.2) is
// advertised only when a BackchannelNotifier can send it;
// NoBackchannelNotifications declines it, so only poll is.
func TestBackchannelDeliveryModesFollowNotifier(t *testing.T) {
	declined, _ := newHarnessWithBackchannel(t) // NoBackchannelNotifications{}
	if got := declined.server.Metadata(context.Background()).BackchannelTokenDeliveryModesSupported; !slices.Equal(got, []string{"poll"}) {
		t.Errorf("NoBackchannelNotifications: BackchannelTokenDeliveryModesSupported = %v, want [poll]", got)
	}
	notifying, _, _ := newHarnessWithBackchannelPing(t)
	if got := notifying.server.Metadata(context.Background()).BackchannelTokenDeliveryModesSupported; !slices.Equal(got, []string{"poll", "ping"}) {
		t.Errorf("real notifier: BackchannelTokenDeliveryModesSupported = %v, want [poll ping]", got)
	}
}

// TestPingClientRefusedWhenNotificationsDeclined: a ping client under
// NoBackchannelNotifications used to get an auth_req_id whose
// notification could never be sent. It now gets unauthorized_client,
// and CheckClientRegistration reports the registration up front.
func TestPingClientRefusedWhenNotificationsDeclined(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t) // NoBackchannelNotifications{}
	ping := pingClientForDeclinedNotifier(t)
	h.clients.clients[testClientID] = ping

	if err := h.server.CheckClientRegistration(ping); err == nil || !strings.Contains(err.Error(), "ping") {
		t.Errorf("CheckClientRegistration = %v, want an error naming ping", err)
	}

	params := standardBackchannelParams(t)
	params["client_notification_token"] = jsonRaw(t, "notify-me-0123456789abcdef")
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	le, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want BackchannelAuthenticationLocalError", action)
	}
	if le.Error.Code() != server.ErrorUnauthorizedClient {
		t.Fatalf("error = %v, want unauthorized_client", le.Error.Code())
	}
}

func pingClientForDeclinedNotifier(t *testing.T) storage.RegisteredClient {
	t.Helper()
	ep, err := fapi.ParseEndpointURL(testBackchannelClientNotificationEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	ping, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: testClientID, RedirectURIs: []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid", "accounts"},
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		BackchannelTokenDeliveryMode:              storage.BackchannelTokenDeliveryModePing,
		BackchannelClientNotificationEndpoint:     ep,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ping
}
