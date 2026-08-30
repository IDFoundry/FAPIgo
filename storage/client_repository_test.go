package storage

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func TestNewRegisteredClient(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.ID() != "client-123" {
		t.Fatalf("ID() = %q, want %q", c.ID(), "client-123")
	}
	if !c.HasRedirectURI("https://rp.example/callback") {
		t.Fatalf("HasRedirectURI(registered) = false, want true")
	}
	if c.HasRedirectURI("https://rp.example/callback/") {
		t.Fatalf("HasRedirectURI(trailing slash) = true, want false")
	}
	if !c.AllowsScope("openid") {
		t.Fatalf("AllowsScope(openid) = false, want true")
	}
	if c.AllowsScope("payments") {
		t.Fatalf("AllowsScope(payments) = true, want false")
	}
	alg, ok := c.RequestObjectAlgorithm()
	if !ok || alg != fapi.ES256 {
		t.Fatalf("RequestObjectAlgorithm() = (%v, %v), want (ES256, true)", alg, ok)
	}
	if c.ClientAssertionAlgorithm() != fapi.ES256 {
		t.Fatalf("ClientAssertionAlgorithm() = %v, want ES256", c.ClientAssertionAlgorithm())
	}
	if c.AllowsClientCredentialsGrant() {
		t.Fatalf("AllowsClientCredentialsGrant() = true, want false (not set)")
	}
}

func TestNewRegisteredClientAllowsClientCredentialsGrant(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                           "client-123",
		RedirectURIs:                 []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm:     fapi.ES256,
		AllowedScopes:                []string{"accounts"},
		AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if !c.AllowsClientCredentialsGrant() {
		t.Fatalf("AllowsClientCredentialsGrant() = false, want true")
	}
}

func TestNewRegisteredClientRequestObjectAlgorithmOptional(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	_, ok := c.RequestObjectAlgorithm()
	if ok {
		t.Fatalf("RequestObjectAlgorithm() permitted = true, want false")
	}
}

func TestNewRegisteredClientBackchannelAuthenticationRequestAlgorithmOptional(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	_, ok := c.BackchannelAuthenticationRequestAlgorithm()
	if ok {
		t.Fatalf("BackchannelAuthenticationRequestAlgorithm() permitted = true, want false")
	}
}

func TestNewRegisteredClientBackchannelAuthenticationRequestAlgorithmConfigured(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	alg, ok := c.BackchannelAuthenticationRequestAlgorithm()
	if !ok || alg != fapi.ES256 {
		t.Fatalf("BackchannelAuthenticationRequestAlgorithm() = (%v, %v), want (ES256, true)", alg, ok)
	}
}

// TestNewRegisteredClientSenderConstrainDefaultsToDPoP confirms the
// zero value keeps every client config that predates this field
// behaving exactly as before.
func TestNewRegisteredClientSenderConstrainDefaultsToDPoP(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.SenderConstrain() != SenderConstrainDPoP {
		t.Fatalf("SenderConstrain() = %v, want SenderConstrainDPoP", c.SenderConstrain())
	}
}

func TestNewRegisteredClientSenderConstrainMTLS(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		SenderConstrain:          SenderConstrainMTLS,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.SenderConstrain() != SenderConstrainMTLS {
		t.Fatalf("SenderConstrain() = %v, want SenderConstrainMTLS", c.SenderConstrain())
	}
}

// TestNewRegisteredClientAuthMethodDefaultsToPrivateKeyJWT confirms the
// zero value keeps every client config that predates this field
// behaving exactly as before.
func TestNewRegisteredClientAuthMethodDefaultsToPrivateKeyJWT(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.ClientAuthMethod() != ClientAuthMethodPrivateKeyJWT {
		t.Fatalf("ClientAuthMethod() = %v, want ClientAuthMethodPrivateKeyJWT", c.ClientAuthMethod())
	}
}

func TestNewRegisteredClientAuthMethodSelfSignedTLSClientAuth(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                            "client-123",
		RedirectURIs:                  []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAuthMethod:              ClientAuthMethodSelfSignedTLSClientAuth,
		ExpectedCertificateThumbprint: "thumbprint-value",
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.ClientAuthMethod() != ClientAuthMethodSelfSignedTLSClientAuth {
		t.Fatalf("ClientAuthMethod() = %v, want ClientAuthMethodSelfSignedTLSClientAuth", c.ClientAuthMethod())
	}
	if c.ExpectedCertificateThumbprint() != "thumbprint-value" {
		t.Fatalf("ExpectedCertificateThumbprint() = %q, want %q", c.ExpectedCertificateThumbprint(), "thumbprint-value")
	}
}

func TestNewRegisteredClientAuthMethodTLSClientAuth(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                "client-123",
		RedirectURIs:      []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAuthMethod:  ClientAuthMethodTLSClientAuth,
		ExpectedSubjectDN: "CN=client-123",
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.ClientAuthMethod() != ClientAuthMethodTLSClientAuth {
		t.Fatalf("ClientAuthMethod() = %v, want ClientAuthMethodTLSClientAuth", c.ClientAuthMethod())
	}
	if c.ExpectedSubjectDN() != "CN=client-123" {
		t.Fatalf("ExpectedSubjectDN() = %q, want %q", c.ExpectedSubjectDN(), "CN=client-123")
	}
}

func TestNewRegisteredClientAuthMethodTLSClientAuthSAN(t *testing.T) {
	cases := []struct {
		name     string
		method   ClientAuthMethod
		cfg      RegisteredClientConfig
		accessor func(RegisteredClient) string
	}{
		{
			name: "SANDNS", method: ClientAuthMethodTLSClientAuthSANDNS,
			cfg:      RegisteredClientConfig{ExpectedSANDNS: "client.example.com"},
			accessor: RegisteredClient.ExpectedSANDNS,
		},
		{
			name: "SANURI", method: ClientAuthMethodTLSClientAuthSANURI,
			cfg:      RegisteredClientConfig{ExpectedSANURI: "https://client.example.com/id"},
			accessor: RegisteredClient.ExpectedSANURI,
		},
		{
			name: "SANIP", method: ClientAuthMethodTLSClientAuthSANIP,
			cfg:      RegisteredClientConfig{ExpectedSANIP: "203.0.113.5"},
			accessor: RegisteredClient.ExpectedSANIP,
		},
		{
			name: "SANEmail", method: ClientAuthMethodTLSClientAuthSANEmail,
			cfg:      RegisteredClientConfig{ExpectedSANEmail: "client@example.com"},
			accessor: RegisteredClient.ExpectedSANEmail,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.ID = "client-123"
			cfg.RedirectURIs = []fapi.RegisteredRedirectURI{"https://rp.example/callback"}
			cfg.ClientAuthMethod = tc.method
			c, err := NewRegisteredClient(cfg)
			if err != nil {
				t.Fatalf("NewRegisteredClient: %v", err)
			}
			if c.ClientAuthMethod() != tc.method {
				t.Fatalf("ClientAuthMethod() = %v, want %v", c.ClientAuthMethod(), tc.method)
			}
			if got := tc.accessor(c); got == "" {
				t.Fatalf("accessor returned empty string")
			}
		})
	}
}

func TestNewRegisteredClientRejectsInvalid(t *testing.T) {
	cases := []RegisteredClientConfig{
		{RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"}, ClientAssertionAlgorithm: fapi.ES256},
		{ID: "client-123", ClientAssertionAlgorithm: fapi.ES256},
		{ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"}},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{""},
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, RequestObjectAlgorithm: fapi.SignatureAlgorithm(99),
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, IDTokenEncryptionKeyManagement: fapi.RSAOAEP256,
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, IDTokenEncryptionContentEncryption: fapi.A256GCM,
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm:           fapi.ES256,
			IDTokenEncryptionKeyManagement:     fapi.KeyManagementAlgorithm(99),
			IDTokenEncryptionContentEncryption: fapi.A256GCM,
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm:           fapi.ES256,
			IDTokenEncryptionKeyManagement:     fapi.RSAOAEP256,
			IDTokenEncryptionContentEncryption: fapi.ContentEncryptionAlgorithm(99),
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, UserInfoEncryptionKeyManagement: fapi.RSAOAEP256,
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, UserInfoEncryptionContentEncryption: fapi.A256GCM,
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm:            fapi.ES256,
			UserInfoEncryptionKeyManagement:     fapi.KeyManagementAlgorithm(99),
			UserInfoEncryptionContentEncryption: fapi.A256GCM,
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm:            fapi.ES256,
			UserInfoEncryptionKeyManagement:     fapi.RSAOAEP256,
			UserInfoEncryptionContentEncryption: fapi.ContentEncryptionAlgorithm(99),
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, BackchannelAuthenticationRequestAlgorithm: fapi.SignatureAlgorithm(99),
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, SenderConstrain: SenderConstrain(99),
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAuthMethod: ClientAuthMethod(99),
		},
		{
			// ClientAuthMethodSelfSignedTLSClientAuth without ExpectedCertificateThumbprint.
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAuthMethod: ClientAuthMethodSelfSignedTLSClientAuth,
		},
		{
			// ClientAuthMethodTLSClientAuth without ExpectedSubjectDN.
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAuthMethod: ClientAuthMethodTLSClientAuth,
		},
		{
			// ClientAuthMethodTLSClientAuthSANDNS without ExpectedSANDNS.
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAuthMethod: ClientAuthMethodTLSClientAuthSANDNS,
		},
		{
			// ClientAuthMethodTLSClientAuthSANURI without ExpectedSANURI.
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAuthMethod: ClientAuthMethodTLSClientAuthSANURI,
		},
		{
			// ClientAuthMethodTLSClientAuthSANIP without ExpectedSANIP.
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAuthMethod: ClientAuthMethodTLSClientAuthSANIP,
		},
		{
			// ClientAuthMethodTLSClientAuthSANIP with an unparseable ExpectedSANIP.
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAuthMethod: ClientAuthMethodTLSClientAuthSANIP, ExpectedSANIP: "not-an-ip",
		},
		{
			// ClientAuthMethodTLSClientAuthSANEmail without ExpectedSANEmail.
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAuthMethod: ClientAuthMethodTLSClientAuthSANEmail,
		},
	}
	for i, c := range cases {
		if _, err := NewRegisteredClient(c); err == nil {
			t.Fatalf("case %d: NewRegisteredClient(%+v) = nil error, want error", i, c)
		}
	}
}

func TestNewRegisteredClientIDTokenEncryptionOptional(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	keyMgmt, contentEnc, enabled := c.IDTokenEncryption()
	if enabled {
		t.Fatalf("IDTokenEncryption() enabled = true, want false")
	}
	if keyMgmt != 0 || contentEnc != 0 {
		t.Fatalf("IDTokenEncryption() = (%v, %v), want (0, 0)", keyMgmt, contentEnc)
	}
}

func TestNewRegisteredClientIDTokenEncryptionConfigured(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                                 "client-123",
		RedirectURIs:                       []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm:           fapi.ES256,
		IDTokenEncryptionKeyManagement:     fapi.RSAOAEP256,
		IDTokenEncryptionContentEncryption: fapi.A256GCM,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	keyMgmt, contentEnc, enabled := c.IDTokenEncryption()
	if !enabled {
		t.Fatalf("IDTokenEncryption() enabled = false, want true")
	}
	if keyMgmt != fapi.RSAOAEP256 || contentEnc != fapi.A256GCM {
		t.Fatalf("IDTokenEncryption() = (%v, %v), want (RSAOAEP256, A256GCM)", keyMgmt, contentEnc)
	}
}

// TestNewRegisteredClientUserInfoEncryptionOptional and
// TestNewRegisteredClientUserInfoEncryptionConfigured mirror the
// IDTokenEncryption pair above, confirming UserInfoEncryption is a real,
// independent field pair — not a reuse of the ID token one.
func TestNewRegisteredClientUserInfoEncryptionOptional(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	keyMgmt, contentEnc, enabled := c.UserInfoEncryption()
	if enabled {
		t.Fatalf("UserInfoEncryption() enabled = true, want false")
	}
	if keyMgmt != 0 || contentEnc != 0 {
		t.Fatalf("UserInfoEncryption() = (%v, %v), want (0, 0)", keyMgmt, contentEnc)
	}
}

func TestNewRegisteredClientUserInfoEncryptionConfigured(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                                  "client-123",
		RedirectURIs:                        []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm:            fapi.ES256,
		UserInfoEncryptionKeyManagement:     fapi.RSAOAEP256,
		UserInfoEncryptionContentEncryption: fapi.A256GCM,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	keyMgmt, contentEnc, enabled := c.UserInfoEncryption()
	if !enabled {
		t.Fatalf("UserInfoEncryption() enabled = false, want true")
	}
	if keyMgmt != fapi.RSAOAEP256 || contentEnc != fapi.A256GCM {
		t.Fatalf("UserInfoEncryption() = (%v, %v), want (RSAOAEP256, A256GCM)", keyMgmt, contentEnc)
	}
	// IDTokenEncryption is unaffected — the two field pairs are
	// independent.
	idKeyMgmt, idContentEnc, idEnabled := c.IDTokenEncryption()
	if idEnabled || idKeyMgmt != 0 || idContentEnc != 0 {
		t.Fatalf("IDTokenEncryption() = (%v, %v, %v), want (0, 0, false)", idKeyMgmt, idContentEnc, idEnabled)
	}
}

// TestNewRegisteredClientBackchannelTokenDeliveryModeDefaultsToPoll
// confirms the zero value keeps every client config that predates this
// field behaving exactly as before.
func TestNewRegisteredClientBackchannelTokenDeliveryModeDefaultsToPoll(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.BackchannelTokenDeliveryMode() != BackchannelTokenDeliveryModePoll {
		t.Fatalf("BackchannelTokenDeliveryMode() = %v, want BackchannelTokenDeliveryModePoll", c.BackchannelTokenDeliveryMode())
	}
	if !c.BackchannelClientNotificationEndpoint().IsZero() {
		t.Fatalf("BackchannelClientNotificationEndpoint() = %v, want zero", c.BackchannelClientNotificationEndpoint())
	}
}

func TestNewRegisteredClientBackchannelTokenDeliveryModePollRejectsNotificationEndpoint(t *testing.T) {
	endpoint, err := fapi.ParseEndpointURL("https://rp.example/ciba/notify")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	_, err = NewRegisteredClient(RegisteredClientConfig{
		ID:                                    "client-123",
		RedirectURIs:                          []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm:              fapi.ES256,
		BackchannelClientNotificationEndpoint: endpoint,
	})
	if err == nil {
		t.Fatalf("NewRegisteredClient(poll mode with notification endpoint) = nil error, want error")
	}
}

func TestNewRegisteredClientBackchannelTokenDeliveryModePingConfigured(t *testing.T) {
	endpoint, err := fapi.ParseEndpointURL("https://rp.example/ciba/notify")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		BackchannelTokenDeliveryMode:              BackchannelTokenDeliveryModePing,
		BackchannelClientNotificationEndpoint:     endpoint,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.BackchannelTokenDeliveryMode() != BackchannelTokenDeliveryModePing {
		t.Fatalf("BackchannelTokenDeliveryMode() = %v, want BackchannelTokenDeliveryModePing", c.BackchannelTokenDeliveryMode())
	}
	if c.BackchannelClientNotificationEndpoint().String() != endpoint.String() {
		t.Fatalf("BackchannelClientNotificationEndpoint() = %v, want %v", c.BackchannelClientNotificationEndpoint(), endpoint)
	}
}

func TestNewRegisteredClientBackchannelTokenDeliveryModePingRequiresNotificationEndpoint(t *testing.T) {
	_, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		BackchannelTokenDeliveryMode:              BackchannelTokenDeliveryModePing,
	})
	if err == nil {
		t.Fatalf("NewRegisteredClient(ping mode with no notification endpoint) = nil error, want error")
	}
}

func TestNewRegisteredClientBackchannelTokenDeliveryModePingRequiresCIBAPermitted(t *testing.T) {
	endpoint, err := fapi.ParseEndpointURL("https://rp.example/ciba/notify")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	_, err = NewRegisteredClient(RegisteredClientConfig{
		ID:                                    "client-123",
		RedirectURIs:                          []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm:              fapi.ES256,
		BackchannelTokenDeliveryMode:          BackchannelTokenDeliveryModePing,
		BackchannelClientNotificationEndpoint: endpoint,
	})
	if err == nil {
		t.Fatalf("NewRegisteredClient(ping mode, no CIBA opt-in) = nil error, want error")
	}
}

func TestNewRegisteredClientRejectsInvalidBackchannelTokenDeliveryMode(t *testing.T) {
	_, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                           "client-123",
		RedirectURIs:                 []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm:     fapi.ES256,
		BackchannelTokenDeliveryMode: BackchannelTokenDeliveryMode(99),
	})
	if err == nil {
		t.Fatalf("NewRegisteredClient(invalid backchannel token delivery mode) = nil error, want error")
	}
}
