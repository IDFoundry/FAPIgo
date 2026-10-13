package storage

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func subjectClient(t *testing.T, mutate func(*RegisteredClientConfig)) (RegisteredClient, error) {
	t.Helper()
	cfg := RegisteredClientConfig{
		ID: "c", ClientAssertionAlgorithm: fapi.ES256,
		RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/cb"},
	}
	mutate(&cfg)
	return NewRegisteredClient(cfg)
}

func TestClientSubjectTypeDefaultsToInherit(t *testing.T) {
	c, err := subjectClient(t, func(*RegisteredClientConfig) {})
	if err != nil {
		t.Fatal(err)
	}
	if c.SubjectType() != 0 {
		t.Errorf("SubjectType() = %v, want zero (inherit)", c.SubjectType())
	}
	for _, st := range []fapi.SubjectType{fapi.SubjectTypePublic, fapi.SubjectTypePairwise} {
		c, err := subjectClient(t, func(cfg *RegisteredClientConfig) { cfg.SubjectType = st })
		if err != nil || c.SubjectType() != st {
			t.Errorf("SubjectType %v: %v, %v", st, c.SubjectType(), err)
		}
	}
	if _, err := subjectClient(t, func(cfg *RegisteredClientConfig) { cfg.SubjectType = 7 }); err == nil {
		t.Error("an invalid SubjectType was accepted")
	}
}

func TestClientSectorDerivation(t *testing.T) {
	tests := map[string]struct {
		mutate func(*RegisteredClientConfig)
		want   string
	}{
		"single https host": {func(*RegisteredClientConfig) {}, "rp.example"},
		"same host, several URIs, case-insensitive": {func(cfg *RegisteredClientConfig) {
			cfg.RedirectURIs = []fapi.RegisteredRedirectURI{"https://rp.example/cb", "https://RP.example:8443/other"}
		}, "rp.example"},
		"several hosts": {func(cfg *RegisteredClientConfig) {
			cfg.RedirectURIs = []fapi.RegisteredRedirectURI{"https://rp.example/cb", "https://app.rp.example/cb"}
		}, ""},
		"http loopback (development)": {func(cfg *RegisteredClientConfig) {
			cfg.RedirectURIs = []fapi.RegisteredRedirectURI{"http://127.0.0.1:8080/cb"}
		}, ""},
		"native": {func(cfg *RegisteredClientConfig) {
			cfg.ApplicationType = ApplicationTypeNative
			cfg.RedirectURIs = []fapi.RegisteredRedirectURI{"https://wallet.example/cb"}
		}, ""},
		"no redirect URIs": {func(cfg *RegisteredClientConfig) {
			cfg.RedirectURIs = nil
			cfg.AllowsClientCredentialsGrant = true
		}, ""},
		// A client permitted CIBA receives tokens with no redirect proving
		// it's served on its redirect URIs' host, so it derives none.
		"permitted CIBA": {func(cfg *RegisteredClientConfig) {
			cfg.BackchannelAuthenticationRequestAlgorithm = fapi.ES256
		}, ""},
		"explicit wins": {func(cfg *RegisteredClientConfig) { cfg.Sector = "bank-group" }, "bank-group"},
	}
	for name, tc := range tests {
		c, err := subjectClient(t, tc.mutate)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Sector() != tc.want {
			t.Errorf("%s: Sector() = %q, want %q", name, c.Sector(), tc.want)
		}
	}
}

func TestPairwiseClientNeedsASector(t *testing.T) {
	without := map[string]func(*RegisteredClientConfig){
		"several hosts": func(cfg *RegisteredClientConfig) {
			cfg.RedirectURIs = []fapi.RegisteredRedirectURI{"https://rp.example/cb", "https://other.example/cb"}
		},
		"native": func(cfg *RegisteredClientConfig) {
			cfg.ApplicationType = ApplicationTypeNative
			cfg.RedirectURIs = []fapi.RegisteredRedirectURI{"org.example.app:/cb"}
		},
		"CIBA with redirect URIs on another client's host": func(cfg *RegisteredClientConfig) {
			cfg.RedirectURIs = []fapi.RegisteredRedirectURI{"https://victim-rp.example/cb"}
			cfg.BackchannelAuthenticationRequestAlgorithm = fapi.ES256
		},
		"CIBA only": func(cfg *RegisteredClientConfig) {
			cfg.RedirectURIs = nil
			cfg.BackchannelAuthenticationRequestAlgorithm = fapi.ES256
			cfg.BackchannelTokenDeliveryMode = BackchannelTokenDeliveryModePoll
		},
	}
	for name, mutate := range without {
		_, err := subjectClient(t, func(cfg *RegisteredClientConfig) {
			mutate(cfg)
			cfg.SubjectType = fapi.SubjectTypePairwise
		})
		if err == nil {
			t.Errorf("%s: a pairwise client with no sector was accepted", name)
		}
		c, err := subjectClient(t, func(cfg *RegisteredClientConfig) {
			mutate(cfg)
			cfg.SubjectType = fapi.SubjectTypePairwise
			cfg.Sector = "app.example"
		})
		if err != nil || c.Sector() != "app.example" {
			t.Errorf("%s with an explicit sector: %q, %v", name, c.Sector(), err)
		}
	}
}

func TestClientSectorValidation(t *testing.T) {
	for _, bad := range []string{
		"has space", "tab\t", "ünicode", strings.Repeat("a", 256), "nul\x00",
		"https://rp.example", "rp.example/cb", "rp.example:8443", "user@rp.example",
		"rp.example?x", "rp.example#x", "[::1]", ".rp.example", "rp.example.", "rp..example", ".",
	} {
		if _, err := subjectClient(t, func(cfg *RegisteredClientConfig) { cfg.Sector = bad }); err == nil {
			t.Errorf("Sector %.20q was accepted", bad)
		}
	}
	if _, err := subjectClient(t, func(cfg *RegisteredClientConfig) { cfg.Sector = strings.Repeat("a", 255) }); err != nil {
		t.Errorf("a 255-byte sector: %v", err)
	}
}

// TestClientSectorIsLowercased: a set Sector names a host, so it is
// lowercased like a derived one, and "RP.example" is the same sector as
// the "rp.example" a client with redirect URIs there derives.
func TestClientSectorIsLowercased(t *testing.T) {
	for _, set := range []string{"RP.example", "rp.EXAMPLE", "Rp.Example"} {
		c, err := subjectClient(t, func(cfg *RegisteredClientConfig) { cfg.Sector = set })
		if err != nil {
			t.Fatalf("Sector %q: %v", set, err)
		}
		if got := c.Sector(); got != "rp.example" {
			t.Errorf("Sector %q gives sector %q, want rp.example", set, got)
		}
	}
	for _, ok := range []string{"192.0.2.1", "my_rp.example", "xn--bcher-kva.example", "rp-1.example"} {
		if _, err := subjectClient(t, func(cfg *RegisteredClientConfig) { cfg.Sector = ok }); err != nil {
			t.Errorf("Sector %q: %v", ok, err)
		}
	}
}

func FuzzDerivedSector(f *testing.F) {
	f.Add("https://rp.example/cb", "https://rp.example/other")
	f.Add("https://rp.example/cb", "https://other.example/cb")
	f.Add("http://127.0.0.1/cb", "https://rp.example/cb")
	f.Fuzz(func(t *testing.T, a, b string) {
		cfg := RegisteredClientConfig{RedirectURIs: []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(a), fapi.RegisteredRedirectURI(b)}}
		sector := derivedSector(cfg)
		if sector == "" {
			return
		}
		for _, raw := range []string{a, b} {
			// The scheme is case-insensitive (RFC 3986 §3.1).
			if !strings.HasPrefix(strings.ToLower(raw), "https://") {
				t.Fatalf("sector %q derived from non-https %q", sector, raw)
			}
		}
		if sector != strings.ToLower(sector) {
			t.Fatalf("sector %q isn't lower case", sector)
		}
	})
}
