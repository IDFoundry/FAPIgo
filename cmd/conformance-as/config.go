// Command conformance-as is a standalone FAPI 2.0 authorization server,
// exposing the server package's PAR/authorize/token/JWKS/metadata
// endpoints over real HTTPS with a minimal HTML consent page. It exists
// so the OpenID Foundation conformance suite — which drives real HTTPS
// traffic, not Go function calls — has something to test against. See
// ARCHITECTURE.md's conformance strategy section.
//
// Client authentication supports private_key_jwt (the default),
// self_signed_tls_client_auth, and tls_client_auth (subject_dn variant
// only — see storage.ClientAuthMethodTLSClientAuth's own doc comment);
// see ClientConfig.ClientAuthMethod. This binary does not stand up a CA
// trust store, so tls_client_auth here is DN-matching only, with no
// certificate-chain trust enforcement — a real tls_client_auth
// deployment would configure tls.Config.ClientCAs in its own adapter.
// mTLS sender-constrained access tokens (RFC 8705 §3, cnf.x5t#S256) are
// a separate, orthogonal capability, supported as an alternative to
// DPoP: see -mtls and ClientConfig.SenderConstrain.
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
	ListenAddr string `json:"listen_addr"`
	// MTLSListenAddr is the second listener's bind address, required
	// only when -mtls is passed — see main.go's own flag doc comment.
	// It reuses the same TLS.CertFile/KeyFile as the primary listener
	// (this server's own identity certificate doesn't change; only
	// whether a client certificate is requested does) and is advertised
	// via mtls_endpoint_aliases (RFC 8705 §5) at the same host as Issuer,
	// with this listener's own port.
	MTLSListenAddr string `json:"mtls_listen_addr,omitempty"`
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
	ID                                        string   `json:"id"`
	RedirectURIs                              []string `json:"redirect_uris"`
	ClientAssertionAlgorithm                  string   `json:"client_assertion_algorithm"`
	RequestObjectAlgorithm                    string   `json:"request_object_algorithm,omitempty"`
	BackchannelAuthenticationRequestAlgorithm string   `json:"backchannel_authentication_request_algorithm,omitempty"`
	AllowedScopes                             []string `json:"allowed_scopes"`

	// SenderConstrain selects how this client's access tokens are
	// sender-constrained: "dpop" (the default, applied when empty) or
	// "mtls" (RFC 8705 §3 — requires this binary to be running with
	// -mtls). Independent of ClientAuthMethod — a client can be
	// sender-constrained either way regardless of how it authenticates.
	SenderConstrain string `json:"sender_constrain,omitempty"`

	// BackchannelTokenDeliveryMode selects how this server tells this
	// client a CIBA decision was reached: "poll" (the default, applied
	// when empty) or "ping" (CIBA §10.2 — requires
	// BackchannelClientNotificationEndpoint and this binary running with
	// -ciba). Independent of SenderConstrain and ClientAuthMethod.
	BackchannelTokenDeliveryMode string `json:"backchannel_token_delivery_mode,omitempty"`

	// BackchannelClientNotificationEndpoint is where this server POSTs
	// a bearer-authenticated ping notification once a CIBA decision is
	// reached. Required exactly when BackchannelTokenDeliveryMode is
	// "ping"; must be left unset for "poll".
	BackchannelClientNotificationEndpoint string `json:"backchannel_client_notification_endpoint,omitempty"`

	// ClientAuthMethod selects how this client authenticates:
	// "private_key_jwt" (the default, applied when empty),
	// "self_signed_tls_client_auth", or "tls_client_auth" (requires this
	// binary to be running with -mtls, same as SenderConstrain "mtls" —
	// either requires a client certificate to be presented, so both need
	// the mTLS listener).
	ClientAuthMethod string `json:"client_auth_method,omitempty"`

	// ExpectedCertificateThumbprint / ExpectedSubjectDN are required
	// exactly when ClientAuthMethod is self_signed_tls_client_auth /
	// tls_client_auth respectively — see
	// storage.RegisteredClientConfig's identically-named fields.
	ExpectedCertificateThumbprint string `json:"expected_certificate_thumbprint,omitempty"`
	ExpectedSubjectDN             string `json:"expected_subject_dn,omitempty"`

	JWKS    json.RawMessage `json:"jwks,omitempty"`
	JWKSURI string          `json:"jwks_uri,omitempty"`

	// AllowsClientCredentialsGrant permits this client to use the RFC
	// 6749 §4.4 client_credentials grant — false (the default, applied
	// when omitted) means it cannot, even when this binary is running
	// with -client-credentials-grant. See
	// storage.RegisteredClientConfig.AllowsClientCredentialsGrant's own
	// doc comment for why both this and -client-credentials-grant must
	// be set.
	AllowsClientCredentialsGrant bool `json:"allows_client_credentials_grant,omitempty"`
}

// LoadConfig reads and parses the JSON config file at path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator's own -config flag value, not untrusted input
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
	MTLSListenAddr    string
	Issuer            fapi.URL
	Profile           server.Profile
	DefaultSubject    string
	Algorithms        server.AlgorithmPolicy
	Limits            server.Limits
	AccessTokenFormat AccessTokenFormat

	// MTLSEndpoints is not populated by Resolve — it depends on
	// -mtls/-mtls-listen, runtime flags Resolve never sees (the same
	// reason AccessTokenFormat is threaded as an explicit Resolve
	// parameter rather than a Config field). main.go fills it in after
	// Resolve returns, once it knows whether -mtls was passed.
	MTLSEndpoints server.MTLSEndpoints

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
	out.MTLSListenAddr = cfg.MTLSListenAddr
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

// parseClientAuthMethod maps a config-file client_auth_method string to
// its storage.ClientAuthMethod, defaulting to private_key_jwt when
// unset.
func parseClientAuthMethod(raw string) (storage.ClientAuthMethod, error) {
	switch raw {
	case "", "private_key_jwt":
		return storage.ClientAuthMethodPrivateKeyJWT, nil
	case "self_signed_tls_client_auth":
		return storage.ClientAuthMethodSelfSignedTLSClientAuth, nil
	case "tls_client_auth":
		return storage.ClientAuthMethodTLSClientAuth, nil
	default:
		return 0, fmt.Errorf("client_auth_method must be %q, %q, or %q, got %q", "private_key_jwt", "self_signed_tls_client_auth", "tls_client_auth", raw)
	}
}

// parseSenderConstrain maps a config-file sender_constrain string to
// its storage.SenderConstrain, defaulting to dpop when unset.
func parseSenderConstrain(raw string) (storage.SenderConstrain, error) {
	switch raw {
	case "", "dpop":
		return storage.SenderConstrainDPoP, nil
	case "mtls":
		return storage.SenderConstrainMTLS, nil
	default:
		return 0, fmt.Errorf("sender_constrain must be %q or %q, got %q", "dpop", "mtls", raw)
	}
}

// parseBackchannelTokenDeliveryMode maps a config-file
// backchannel_token_delivery_mode string to its
// storage.BackchannelTokenDeliveryMode, defaulting to poll when unset.
func parseBackchannelTokenDeliveryMode(raw string) (storage.BackchannelTokenDeliveryMode, error) {
	switch raw {
	case "", "poll":
		return storage.BackchannelTokenDeliveryModePoll, nil
	case "ping":
		return storage.BackchannelTokenDeliveryModePing, nil
	default:
		return 0, fmt.Errorf("backchannel_token_delivery_mode must be %q or %q, got %q", "poll", "ping", raw)
	}
}

func resolveClient(c ClientConfig) (storage.RegisteredClient, ephemeral.ClientKeySpec, error) {
	if c.ID == "" {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("id is required")
	}
	if len(c.RedirectURIs) == 0 {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("redirect_uris must not be empty")
	}
	clientAuthMethod, err := parseClientAuthMethod(c.ClientAuthMethod)
	if err != nil {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, err
	}

	var assertionAlg fapi.SignatureAlgorithm
	if clientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
		assertionAlg, err = fapi.ParseSignatureAlgorithm(c.ClientAssertionAlgorithm)
		if err != nil {
			return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("client_assertion_algorithm: %w", err)
		}
	}
	if clientAuthMethod == storage.ClientAuthMethodSelfSignedTLSClientAuth && c.ExpectedCertificateThumbprint == "" {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("expected_certificate_thumbprint is required when client_auth_method is self_signed_tls_client_auth")
	}
	if clientAuthMethod == storage.ClientAuthMethodTLSClientAuth && c.ExpectedSubjectDN == "" {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("expected_subject_dn is required when client_auth_method is tls_client_auth")
	}

	var requestObjectAlg fapi.SignatureAlgorithm
	if c.RequestObjectAlgorithm != "" {
		requestObjectAlg, err = fapi.ParseSignatureAlgorithm(c.RequestObjectAlgorithm)
		if err != nil {
			return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("request_object_algorithm: %w", err)
		}
	}
	var backchannelAuthenticationRequestAlg fapi.SignatureAlgorithm
	if c.BackchannelAuthenticationRequestAlgorithm != "" {
		backchannelAuthenticationRequestAlg, err = fapi.ParseSignatureAlgorithm(c.BackchannelAuthenticationRequestAlgorithm)
		if err != nil {
			return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("backchannel_authentication_request_algorithm: %w", err)
		}
	}

	// A client needs a discoverable JWKS iff it does any JWS signing at
	// all: private_key_jwt client assertions, signed request objects, or
	// signed CIBA backchannel authentication requests. A client
	// registered for certificate-based authentication that does neither
	// of the latter two has no key material to publish.
	needsJWKS := clientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT || requestObjectAlg != 0 || backchannelAuthenticationRequestAlg != 0
	hasJWKS := len(c.JWKS) > 0
	hasJWKSURI := c.JWKSURI != ""
	switch {
	case needsJWKS && hasJWKS == hasJWKSURI:
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("exactly one of jwks or jwks_uri must be set")
	case !needsJWKS && (hasJWKS || hasJWKSURI):
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("jwks/jwks_uri must not be set: this client does no JWS signing (client_auth_method is not private_key_jwt, and neither request_object_algorithm nor backchannel_authentication_request_algorithm is set)")
	}

	senderConstrain, err := parseSenderConstrain(c.SenderConstrain)
	if err != nil {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, err
	}

	backchannelTokenDeliveryMode, err := parseBackchannelTokenDeliveryMode(c.BackchannelTokenDeliveryMode)
	if err != nil {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, err
	}
	var backchannelClientNotificationEndpoint fapi.URL
	if c.BackchannelClientNotificationEndpoint != "" {
		backchannelClientNotificationEndpoint, err = fapi.ParseEndpointURL(c.BackchannelClientNotificationEndpoint)
		if err != nil {
			return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, fmt.Errorf("backchannel_client_notification_endpoint: %w", err)
		}
	}

	redirectURIs := make([]fapi.RegisteredRedirectURI, len(c.RedirectURIs))
	for i, u := range c.RedirectURIs {
		redirectURIs[i] = fapi.RegisteredRedirectURI(u)
	}

	clientID := fapi.ClientID(c.ID)
	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                            clientID,
		RedirectURIs:                  redirectURIs,
		ClientAuthMethod:              clientAuthMethod,
		ClientAssertionAlgorithm:      assertionAlg,
		ExpectedCertificateThumbprint: c.ExpectedCertificateThumbprint,
		ExpectedSubjectDN:             c.ExpectedSubjectDN,
		RequestObjectAlgorithm:        requestObjectAlg,
		BackchannelAuthenticationRequestAlgorithm: backchannelAuthenticationRequestAlg,
		AllowedScopes:                         c.AllowedScopes,
		SenderConstrain:                       senderConstrain,
		BackchannelTokenDeliveryMode:          backchannelTokenDeliveryMode,
		BackchannelClientNotificationEndpoint: backchannelClientNotificationEndpoint,
		AllowsClientCredentialsGrant:          c.AllowsClientCredentialsGrant,
	})
	if err != nil {
		return storage.RegisteredClient{}, ephemeral.ClientKeySpec{}, err
	}

	return registered, ephemeral.ClientKeySpec{ClientID: clientID, JWKS: c.JWKS, JWKSURI: c.JWKSURI}, nil
}
