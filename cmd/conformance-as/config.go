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
type Config struct {
	ListenAddr     string `json:"listen_addr"`
	Issuer         string `json:"issuer"`
	Profile        string `json:"profile"` // "fapi2-security" | "fapi2-security-message-signing"
	DefaultSubject string `json:"default_subject"`

	Algorithms struct {
		ClientAssertion []string `json:"client_assertion"`
		RequestObject   []string `json:"request_object"`
		JARM            string   `json:"jarm,omitempty"`
		AccessToken     string   `json:"access_token"`
		IDToken         string   `json:"id_token"`
	} `json:"algorithms"`

	Limits struct {
		PushedRequestLifetimeSeconds      int `json:"pushed_request_lifetime_seconds"`
		MaxClientAssertionLifetimeSeconds int `json:"max_client_assertion_lifetime_seconds"`
		MaxRequestObjectLifetimeSeconds   int `json:"max_request_object_lifetime_seconds"`
		InteractionLifetimeSeconds        int `json:"interaction_lifetime_seconds"`
		AuthorizationCodeLifetimeSeconds  int `json:"authorization_code_lifetime_seconds"`
		JARMResponseLifetimeSeconds       int `json:"jarm_response_lifetime_seconds,omitempty"`
		AccessTokenLifetimeSeconds        int `json:"access_token_lifetime_seconds"`
		IDTokenLifetimeSeconds            int `json:"id_token_lifetime_seconds"`
		RefreshTokenLifetimeSeconds       int `json:"refresh_token_lifetime_seconds"`
		MaxDPoPProofAgeSeconds            int `json:"max_dpop_proof_age_seconds"`
		MaxClockSkewSeconds               int `json:"max_clock_skew_seconds"`
	} `json:"limits"`

	Clients []ClientConfig `json:"clients"`

	TLS struct {
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"tls"`
}

// ClientConfig registers one OIDF-suite-driven test client. Exactly one
// of JWKS or JWKSURI must be set.
//
// TODO(conformance): the exact OIDF test-plan client JWKS delivery
// mechanism isn't chosen yet — populate conformance/server/oidf-config/
// and point this config at it once a specific test plan is selected.
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
	ListenAddr     string
	Issuer         fapi.URL
	Profile        server.Profile
	DefaultSubject string
	Algorithms     server.AlgorithmPolicy
	Limits         server.Limits

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
func (cfg Config) Resolve(allowLoopbackHTTP bool) (ResolvedConfig, error) {
	var out ResolvedConfig
	out.ListenAddr = cfg.ListenAddr
	out.DefaultSubject = cfg.DefaultSubject
	out.TLSCertFile = cfg.TLS.CertFile
	out.TLSKeyFile = cfg.TLS.KeyFile

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

	clientAssertionAlgs, err := parseAlgorithmSet(cfg.Algorithms.ClientAssertion)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("algorithms.client_assertion: %w", err)
	}
	requestObjectAlgs, err := parseAlgorithmSet(cfg.Algorithms.RequestObject)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("algorithms.request_object: %w", err)
	}
	accessTokenAlg, err := fapi.ParseSignatureAlgorithm(cfg.Algorithms.AccessToken)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("algorithms.access_token: %w", err)
	}
	idTokenAlg, err := fapi.ParseSignatureAlgorithm(cfg.Algorithms.IDToken)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("algorithms.id_token: %w", err)
	}
	out.Algorithms = server.AlgorithmPolicy{
		ClientAssertion: clientAssertionAlgs,
		RequestObject:   requestObjectAlgs,
		AccessToken:     accessTokenAlg,
		IDToken:         idTokenAlg,
	}
	if out.Profile == server.ProfileFAPISecurityWithMessageSigning {
		jarmAlg, err := fapi.ParseSignatureAlgorithm(cfg.Algorithms.JARM)
		if err != nil {
			return ResolvedConfig{}, fmt.Errorf("algorithms.jarm: %w", err)
		}
		out.Algorithms.JARM = jarmAlg
	}

	out.Limits = server.Limits{
		PushedRequestLifetime:      seconds(cfg.Limits.PushedRequestLifetimeSeconds),
		MaxClientAssertionLifetime: seconds(cfg.Limits.MaxClientAssertionLifetimeSeconds),
		MaxRequestObjectLifetime:   seconds(cfg.Limits.MaxRequestObjectLifetimeSeconds),
		InteractionLifetime:        seconds(cfg.Limits.InteractionLifetimeSeconds),
		AuthorizationCodeLifetime:  seconds(cfg.Limits.AuthorizationCodeLifetimeSeconds),
		JARMResponseLifetime:       seconds(cfg.Limits.JARMResponseLifetimeSeconds),
		AccessTokenLifetime:        seconds(cfg.Limits.AccessTokenLifetimeSeconds),
		IDTokenLifetime:            seconds(cfg.Limits.IDTokenLifetimeSeconds),
		RefreshTokenLifetime:       seconds(cfg.Limits.RefreshTokenLifetimeSeconds),
		MaxDPoPProofAge:            seconds(cfg.Limits.MaxDPoPProofAgeSeconds),
		MaxClockSkew:               seconds(cfg.Limits.MaxClockSkewSeconds),
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

func parseAlgorithmSet(values []string) (server.AlgorithmSet, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("must not be empty")
	}
	out := make(server.AlgorithmSet, len(values))
	for i, v := range values {
		alg, err := fapi.ParseSignatureAlgorithm(v)
		if err != nil {
			return nil, err
		}
		out[i] = alg
	}
	return out, nil
}

func seconds(n int) time.Duration {
	return time.Duration(n) * time.Second
}
