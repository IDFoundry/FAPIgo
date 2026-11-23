package federation_test

import (
	"maps"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/storage"
)

// grantsConfig is validAutomaticRegistrationConfig with the operator
// allowing client_credentials and CIBA for every automatically
// registered client.
func grantsConfig() federation.AutomaticRegistrationConfig {
	cfg := validAutomaticRegistrationConfig()
	cfg.AllowsClientCredentialsGrant = true
	cfg.AllowsCIBA = true
	return cfg
}

// cibaMetadata is the metadata members an RP publishes to register for
// CIBA with poll delivery, with extra's members in their place (a nil
// one leaving that member out; see rpMetadataWith).
func cibaMetadata(extra map[string]any) map[string]any {
	members := map[string]any{
		"grant_types": []string{"authorization_code", cibaGrantType},
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode":                "poll",
	}
	maps.Copy(members, extra)
	return members
}

// checkRegisteredGrants fails t unless client is registered for the
// authorization code flow, and for client_credentials and CIBA exactly
// when wantClientCreds and wantCIBA say.
func checkRegisteredGrants(t *testing.T, client storage.RegisteredClient, wantClientCreds, wantCIBA bool) {
	t.Helper()
	if !client.AllowsAuthorizationCodeGrant() {
		t.Error("AllowsAuthorizationCodeGrant() = false, want the authorization code flow registered")
	}
	if got := client.AllowsClientCredentialsGrant(); got != wantClientCreds {
		t.Errorf("AllowsClientCredentialsGrant() = %v, want %v", got, wantClientCreds)
	}
	if _, got := client.BackchannelAuthenticationRequestAlgorithm(); got != wantCIBA {
		t.Errorf("BackchannelAuthenticationRequestAlgorithm permitted = %v, want %v", got, wantCIBA)
	}
}

// TestAutomaticRegistrationOmittedGrantTypesMeansCodeFlowOnly: a Relying
// Party whose resolved metadata leaves grant_types out is registered for
// the authorization code flow alone, the default OpenID Connect Dynamic
// Client Registration 1.0 §2 and RFC 7591 §2 give an omitted
// grant_types, though the operator allows client_credentials and CIBA,
// no policy bounds grant_types, and the RP publishes CIBA's signing
// algorithm and delivery mode. A grant_types listing neither grant
// registers neither; one listing a grant registers it.
func TestAutomaticRegistrationOmittedGrantTypesMeansCodeFlowOnly(t *testing.T) {
	for _, tc := range []struct {
		name            string
		grantTypes      any // the RP's grant_types; nil leaves it out
		policy          string
		wantClientCreds bool
		wantCIBA        bool
	}{
		{name: "left out"},
		{name: "left out, under a policy on another parameter only",
			policy: `{"openid_relying_party":{"token_endpoint_auth_method":{"one_of":["private_key_jwt"]}}}`},
		{name: "empty", grantTypes: []string{}},
		{name: "the authorization code flow", grantTypes: []string{"authorization_code", "refresh_token"}},
		{name: "client_credentials", grantTypes: []string{"client_credentials"}, wantClientCreds: true},
		{name: "CIBA", grantTypes: []string{cibaGrantType}, wantCIBA: true},
		{name: "both", grantTypes: []string{"authorization_code", "client_credentials", cibaGrantType},
			wantClientCreds: true, wantCIBA: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := rpMetadataWith(t, cibaMetadata(map[string]any{"grant_types": tc.grantTypes}))
			f := setupAutomaticRegistrationFixtureWithPolicy(t, metadata, policyOrNil(t, tc.policy))
			client, failure := resolveWith(t, f, grantsConfig())
			if failure != nil {
				t.Fatalf("registration failed: %v", failure)
			}
			checkRegisteredGrants(t, client, tc.wantClientCreds, tc.wantCIBA)
		})
	}
}

// TestAutomaticRegistrationRequiresCIBADeliveryMode: a Relying Party
// registering for CIBA — its grant_types lists the CIBA grant, it names
// the signing algorithm, and the operator and policy allow it — must name
// its backchannel_token_delivery_mode, which CIBA Core 1.0 §4 makes
// REQUIRED. One that doesn't fails to register, with the reason passed to
// OnResolutionFailure, rather than being registered for poll. Where it
// wouldn't get CIBA anyway, the missing delivery mode refuses nothing.
func TestAutomaticRegistrationRequiresCIBADeliveryMode(t *testing.T) {
	noMode := map[string]any{"backchannel_token_delivery_mode": nil}
	withoutCIBA := grantsConfig()
	withoutCIBA.AllowsCIBA = false
	for _, tc := range []struct {
		name    string
		extra   map[string]any
		policy  string
		cfg     federation.AutomaticRegistrationConfig
		refused bool
	}{
		{name: "the CIBA grant listed without a delivery mode", extra: noMode, cfg: grantsConfig(), refused: true},
		{name: "the operator not allowing CIBA", extra: noMode, cfg: withoutCIBA},
		{name: "a superior's policy leaving the CIBA grant out", extra: noMode, cfg: grantsConfig(),
			policy: `{"openid_relying_party":{"grant_types":{"subset_of":["authorization_code","refresh_token"]}}}`},
		{name: "no signing algorithm", cfg: grantsConfig(),
			extra: map[string]any{"backchannel_token_delivery_mode": nil, "backchannel_authentication_request_signing_alg": nil}},
		{name: "grant_types left out", cfg: grantsConfig(),
			extra: map[string]any{"backchannel_token_delivery_mode": nil, "grant_types": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setupAutomaticRegistrationFixtureWithPolicy(t, rpMetadataWith(t, cibaMetadata(tc.extra)), policyOrNil(t, tc.policy))
			client, failure := resolveWith(t, f, tc.cfg)
			if tc.refused {
				if failure == nil || !strings.Contains(failure.Error(), "backchannel_token_delivery_mode") {
					t.Fatalf("registration failure = %v, want the missing backchannel_token_delivery_mode refused", failure)
				}
				return
			}
			if failure != nil {
				t.Fatalf("registration failed: %v", failure)
			}
			checkRegisteredGrants(t, client, false, false)
		})
	}
}

// TestAutomaticRegistrationCIBADeliveryModes: a Relying Party registering
// for CIBA gets the delivery mode it names, with the metadata that mode
// needs (CIBA Core 1.0 §4): poll with no notification endpoint, ping with
// one. Ping without the endpoint, poll with one, and push, which
// FAPI-CIBA doesn't allow, fail to register.
func TestAutomaticRegistrationCIBADeliveryModes(t *testing.T) {
	const endpoint = "https://rp.example.org/notify"
	for _, tc := range []struct {
		name, mode, notify string // notify is the RP's notification endpoint, "" for none
		want               storage.BackchannelTokenDeliveryMode
		wantRefusal        string // in a refused registration's reason; "" when it registers
	}{
		{name: "poll", mode: "poll", want: storage.BackchannelTokenDeliveryModePoll},
		{name: "ping with a notification endpoint", mode: "ping", notify: endpoint, want: storage.BackchannelTokenDeliveryModePing},
		{name: "ping without a notification endpoint", mode: "ping", wantRefusal: "BackchannelClientNotificationEndpoint for ping"},
		{name: "poll with a notification endpoint", mode: "poll", notify: endpoint, wantRefusal: "BackchannelClientNotificationEndpoint for poll"},
		{name: "push", mode: "push", notify: endpoint, wantRefusal: `unrecognized backchannel token delivery mode "push"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]any{"backchannel_token_delivery_mode": tc.mode}
			if tc.notify != "" {
				extra["backchannel_client_notification_endpoint"] = tc.notify
			}
			client, failure := resolveWith(t, setupAutomaticRegistrationFixture(t, rpMetadataWith(t, cibaMetadata(extra))), grantsConfig())
			if tc.wantRefusal != "" {
				if failure == nil || !strings.Contains(failure.Error(), tc.wantRefusal) {
					t.Fatalf("registration failure = %v, want one naming %q", failure, tc.wantRefusal)
				}
				return
			}
			checkDeliveryMode(t, client, failure, tc.want, tc.notify)
		})
	}
}

// checkDeliveryMode fails t unless client was registered (failure is nil)
// for CIBA with mode, notifying endpoint ("" for none).
func checkDeliveryMode(t *testing.T, client storage.RegisteredClient, failure error, mode storage.BackchannelTokenDeliveryMode, endpoint string) {
	t.Helper()
	if failure != nil {
		t.Fatalf("registration failed: %v", failure)
	}
	if _, ok := client.BackchannelAuthenticationRequestAlgorithm(); !ok {
		t.Fatal("CIBA not registered")
	}
	if got := client.BackchannelTokenDeliveryMode(); got != mode {
		t.Errorf("BackchannelTokenDeliveryMode() = %v, want %v", got, mode)
	}
	if got := client.BackchannelClientNotificationEndpoint().String(); got != endpoint {
		t.Errorf("BackchannelClientNotificationEndpoint() = %q, want %q", got, endpoint)
	}
}
