package main

import "testing"

func validTopLevelConfig() Config {
	return Config{
		ListenAddr:     "127.0.0.1:8443",
		Issuer:         "https://as.example.org",
		Profile:        "fapi2-security",
		DefaultSubject: "test-user",
		Clients:        []ClientConfig{validClientConfig()},
	}
}

func validFederationConfig() *FederationConfig {
	return &FederationConfig{
		EntityID: "https://as.example.org",
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta.example.org", JWKS: []byte(`{"keys":[]}`)},
		},
		AllowedScopes: []string{"openid"},
	}
}

func TestResolveAcceptsValidConfig(t *testing.T) {
	cfg := validTopLevelConfig()
	resolved, err := cfg.Resolve(true, AccessTokenFormatJWT)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Federation != nil {
		t.Errorf("Federation = %+v, want nil (no federation block in cfg)", resolved.Federation)
	}
}

func TestResolveAcceptsValidFederationConfig(t *testing.T) {
	cfg := validTopLevelConfig()
	cfg.Federation = validFederationConfig()
	resolved, err := cfg.Resolve(true, AccessTokenFormatJWT)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Federation == nil {
		t.Fatalf("Federation = nil, want non-nil")
	}
	if resolved.Federation.EntityID != "https://as.example.org" {
		t.Errorf("Federation.EntityID = %q", resolved.Federation.EntityID)
	}
	if len(resolved.Federation.TrustAnchors) != 1 || resolved.Federation.TrustAnchors[0].EntityID != "https://ta.example.org" {
		t.Errorf("Federation.TrustAnchors = %v", resolved.Federation.TrustAnchors)
	}
	if len(resolved.Federation.AllowedScopes) != 1 || resolved.Federation.AllowedScopes[0] != "openid" {
		t.Errorf("Federation.AllowedScopes = %v", resolved.Federation.AllowedScopes)
	}
}

func TestResolveRejectsInvalidFederationConfig(t *testing.T) {
	cases := map[string]func(*FederationConfig){
		"empty entity_id":           func(f *FederationConfig) { f.EntityID = "" },
		"no trust anchors":          func(f *FederationConfig) { f.TrustAnchors = nil },
		"trust anchor missing id":   func(f *FederationConfig) { f.TrustAnchors[0].EntityID = "" },
		"trust anchor missing jwks": func(f *FederationConfig) { f.TrustAnchors[0].JWKS = nil },
		"empty allowed_scopes":      func(f *FederationConfig) { f.AllowedScopes = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validTopLevelConfig()
			fedCfg := validFederationConfig()
			mutate(fedCfg)
			cfg.Federation = fedCfg
			if _, err := cfg.Resolve(true, AccessTokenFormatJWT); err == nil {
				t.Fatalf("Resolve(%s) = nil error, want error", name)
			}
		})
	}
}

func TestResolveRejectsInvalidAccessTokenFormat(t *testing.T) {
	cfg := validTopLevelConfig()
	if _, err := cfg.Resolve(true, AccessTokenFormat("bogus")); err == nil {
		t.Fatalf("Resolve(bogus access token format) = nil error, want error")
	}
}

func TestResolveRejectsMissingListenAddr(t *testing.T) {
	cfg := validTopLevelConfig()
	cfg.ListenAddr = ""
	if _, err := cfg.Resolve(true, AccessTokenFormatJWT); err == nil {
		t.Fatalf("Resolve(no listen_addr) = nil error, want error")
	}
}

func TestResolveRejectsMissingDefaultSubject(t *testing.T) {
	cfg := validTopLevelConfig()
	cfg.DefaultSubject = ""
	if _, err := cfg.Resolve(true, AccessTokenFormatJWT); err == nil {
		t.Fatalf("Resolve(no default_subject) = nil error, want error")
	}
}

func TestResolveRejectsInvalidProfile(t *testing.T) {
	cfg := validTopLevelConfig()
	cfg.Profile = "bogus"
	if _, err := cfg.Resolve(true, AccessTokenFormatJWT); err == nil {
		t.Fatalf("Resolve(invalid profile) = nil error, want error")
	}
}

func TestResolveRejectsNoClients(t *testing.T) {
	cfg := validTopLevelConfig()
	cfg.Clients = nil
	if _, err := cfg.Resolve(true, AccessTokenFormatJWT); err == nil {
		t.Fatalf("Resolve(no clients) = nil error, want error")
	}
}

func TestResolveRejectsMissingTLSWithoutLoopback(t *testing.T) {
	cfg := validTopLevelConfig()
	if _, err := cfg.Resolve(false, AccessTokenFormatJWT); err == nil {
		t.Fatalf("Resolve(no TLS cert/key, allowLoopbackHTTP=false) = nil error, want error")
	}
}
