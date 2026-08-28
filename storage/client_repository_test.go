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
