// Command conformance-as is a standalone FAPI 2.0 authorization server,
// exposing the server package's PAR/authorize/token/JWKS/metadata
// endpoints over real HTTPS with a minimal HTML consent page. It exists
// so the OpenID Foundation conformance suite — which drives real HTTPS
// traffic, not Go function calls — has something to test against. See
// ARCHITECTURE.md's conformance strategy section.
//
// mTLS (tls_client_auth / self_signed_tls_client_auth / cnf.x5t#S256) is
// out of scope: nothing in this module implements it, and this binary
// only targets the profile the library actually supports —
// private_key_jwt client authentication, under either the FAPI2 Security
// Profile baseline or its message-signing variant.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// Config is this binary's on-disk configuration.
//
// Deliberately has no algorithms/limits fields: this AS's conformance
// testing runs on server.RecommendedAlgorithms()/server.RecommendedLimits()
// unconditionally (see Resolve) — those are the FAPI 2.0-grounded values
// conformance certification should actually be exercised against, not a
// hand-tunable knob that can drift from them. See GETTING_STARTED.md if
// you're building your own AS and want a different starting point;
// that's a legitimate choice for a real deployment in a way it isn't
// for this repo's own conformance testing.
type Config struct {
	ListenAddr     string `json:"listen_addr"`
	Issuer         string `json:"issuer"`
	Profile        string `json:"profile"` // "fapi2-security" | "fapi2-security-message-signing"
	DefaultSubject string `json:"default_subject"`

	Clients []ClientConfig `json:"clients"`

	TLS struct {
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"tls"`
}

// AccessTokenFormat selects which server.AccessTokenIssuer/
// resource.AccessTokenResolver pair newServerMux wires up — see
// main.go's -access-token-format flag. Deliberately not a Config field
// (same reasoning as Config's own doc comment: this binary's
// conformance testing shouldn't grow a JSON-file knob for something
// that's a test-run dimension, not a deployment setting) — threaded
// through Resolve as an explicit parameter instead, the same way
// allowLoopbackHTTP already is.
type AccessTokenFormat string

const (
	AccessTokenFormatJWT    AccessTokenFormat = "jwt"
	AccessTokenFormatOpaque AccessTokenFormat = "opaque"
)

// ClientConfig registers one OIDF-suite-driven test client. Exactly one
// of JWKS or JWKSURI must be set — see conformance/server/oidf-config/
// for how each test plan's client config populates this.
type ClientConfig struct {
	ID                       string   `json:"id"`
	RedirectURIs             []string `json:"redirect_uris"`
	ClientAssertionAlgorithm string   `json:"client_assertion_algorithm"`
	RequestObjectAlgorithm   string   `json:"request_object_algorithm,omitempty"`
	AllowedScopes            []string `json:"allowed_scopes"`

	JWKS    json.RawMessage `json:"jwks,omitempty"`
	JWKSURI string          `json:"jwks_uri,omitempty"`
}

// LoadConfig reads and parses the JSON config file at path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// ResolvedConfig is Config translated into the typed values server.Config,
// the storage/key implementations, and main's own listener setup need.
type ResolvedConfig struct {
	ListenAddr        string
	Issuer            fapi.URL
	Profile           server.Profile
	DefaultSubject    string
	Algorithms        server.AlgorithmPolicy
	Limits            server.Limits
	AccessTokenFormat AccessTokenFormat

	// Clients and ClientKeys are two parallel slices, joined by
	// ClientID: Clients feeds memstore.NewClientRepository (is this
	// client registered at all), ClientKeys feeds
	// ephemeral.NewClientKeySource (what verification keys does it
	// present) — deliberately separate, since those are two different
	// interfaces' concerns, not one combined "client config" concept.
	Clients    []storage.RegisteredClient
	ClientKeys []ephemeral.ClientKeySpec

	// AdvertisedScopes is the union of every registered client's allowed
	// scopes, published at the metadata endpoint's scopes_supported.
	AdvertisedScopes []string

	TLSCertFile string
	TLSKeyFile  string
}

// Resolve validates cfg and converts it into a ResolvedConfig, or a
// descriptive error identifying the first problem found.
func (cfg Config) Resolve(allowLoopbackHTTP bool, accessTokenFormat AccessTokenFormat) (ResolvedConfig, error) {
	var out ResolvedConfig
	out.ListenAddr = cfg.ListenAddr
	out.DefaultSubject = cfg.DefaultSubject
	out.TLSCertFile = cfg.TLS.CertFile
	out.TLSKeyFile = cfg.TLS.KeyFile

	switch accessTokenFormat {
	case AccessTokenFormatJWT, AccessTokenFormatOpaque:
		out.AccessTokenFormat = accessTokenFormat
	default:
		return ResolvedConfig{}, fmt.Errorf("access token format must be %q or %q, got %q", AccessTokenFormatJWT, AccessTokenFormatOpaque, accessTokenFormat)
	}

	if out.ListenAddr == "" {
		return ResolvedConfig{}, fmt.Errorf("listen_addr is required")
	}
	if out.DefaultSubject == "" {
		return ResolvedConfig{}, fmt.Errorf("default_subject is required")
	}

	var issuerOpts []fapi.URLOption
	if allowLoopbackHTTP {
		issuerOpts = append(issuerOpts, fapi.AllowLoopbackHTTP())
	}
	issuer, err := fapi.ParseIssuerURL(cfg.Issuer, issuerOpts...)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("issuer: %w", err)
	}
	out.Issuer = issuer

	switch cfg.Profile {
	case "fapi2-security":
		out.Profile = server.ProfileFAPISecurity
	case "fapi2-security-message-signing":
		out.Profile = server.ProfileFAPISecurityWithMessageSigning
	default:
		return ResolvedConfig{}, fmt.Errorf("profile must be %q or %q, got %q", "fapi2-security", "fapi2-security-message-signing", cfg.Profile)
	}

	// Not configurable from the JSON file — see Config's own doc
	// comment for why. RecommendedAlgorithms already sets JARM
	// regardless of profile (harmless where it goes unused), so there's
	// no profile-conditional parsing needed here the way the old
	// JSON-driven path required.
	out.Algorithms = server.RecommendedAlgorithms()
	out.Limits = server.RecommendedLimits()
	if out.Profile == server.ProfileFAPISecurityWithMessageSigning {
		// The one deliberate, code-level exception to "conformance
		// runs on the unmodified recommended defaults" — a test-
		// harness accommodation, not a relaxation of what FAPI2
		// itself requires. The OIDF suite's own AddExpToRequestObject
		// condition hardcodes a 300s exp-nbf window on every ordinary
		// (non-negative-test) module's request object; the
		// recommended default (60s) is fine under the baseline
		// profile, where a request object is never actually sent
		// (fapi_request_method=unsigned), but message-signing
		// requires one on every request and needs real headroom above
		// the suite's own window. See oidf-config/README.md for the
		// full rationale, including why 600s specifically.
		out.Limits.MaxRequestObjectLifetime = 600 * time.Second
	}

	if len(cfg.Clients) == 0 {
		return ResolvedConfig{}, fmt.Errorf("clients: at least one registered client is required")
	}
	seenScope := make(map[string]struct{})
	for _, c := range cfg.Clients {
		registered, keySpec, err := resolveClient(c)
		if err != nil {
			return ResolvedConfig{}, fmt.Errorf("clients[%s]: %w", c.ID, err)
		}
		out.Clients = append(out.Clients, registered)
		out.ClientKeys = append(out.ClientKeys, keySpec)
		for _, s := range c.AllowedScopes {
			if _, ok := seenScope[s]; !ok {
				seenScope[s] = struct{}{}
				out.AdvertisedScopes = append(out.AdvertisedScopes, s)
			}
		}
	}

	if out.TLSCertFile == "" || out.TLSKeyFile == "" {
		if !allowLoopbackHTTP {
			return ResolvedConfig{}, fmt.Errorf("tls.cert_file and tls.key_file are required unless -insecure-http is set")
		}
	}

	return out, nil
}

func resolveClient(c ClientConfig) (storage.RegisteredClient, ephemeral.ClientKeySpec, error) {
	if c.ID == "" {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("id is required")
	}
	if len(c.RedirectURIs) == 0 {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("redirect_uris must not be empty")
	}
	assertionAlg, err := fapi.ParseSignatureAlgorithm(c.ClientAssertionAlgorithm)
	if err != nil {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("client_assertion_algorithm: %w", err)
	}
	var requestObjectAlg fapi.SignatureAlgorithm
	if c.RequestObjectAlgorithm != "" {
		requestObjectAlg, err = fapi.ParseSignatureAlgorithm(c.RequestObjectAlgorithm)
		if err != nil {
			return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("request_object_algorithm: %w", err)
		}
	}

	hasJWKS := len(c.JWKS) > 0
	hasJWKSURI := c.JWKSURI != ""
	if hasJWKS == hasJWKSURI {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("exactly one of jwks or jwks_uri must be set")
	}

	redirectURIs := make([]fapi.RegisteredRedirectURI, len(c.RedirectURIs))
	for i, u := range c.RedirectURIs {
		redirectURIs[i] = fapi.RegisteredRedirectURI(u)
	}

	clientID := fapi.ClientID(c.ID)
	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       clientID,
		RedirectURIs:             redirectURIs,
		ClientAssertionAlgorithm: assertionAlg,
		RequestObjectAlgorithm:   requestObjectAlg,
		AllowedScopes:            c.AllowedScopes,
	})
	if err != nil {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, err
	}

	return registered, ephemeral.ClientKeySpec{ClientID: clientID, JWKS: c.JWKS, JWKSURI: c.JWKSURI}, nil
}
