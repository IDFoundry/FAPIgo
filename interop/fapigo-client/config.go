package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// runConfig is the driver's configuration, written by the suite's
// runner (interop/oidc-provider/setup.mjs, interop/keycloak/setup.mjs).
// Nothing in it is specific to one authorization server: the issuer,
// the CA its TLS certificate chains to, the test user, the CIBA
// approval hook, and one entry per leg with that leg's client
// registration.
type runConfig struct {
	// Issuer is the authorization server's issuer identifier; the
	// driver discovers everything else from its metadata.
	Issuer string `json:"issuer"`

	// CAFile is the PEM certificate of the CA the authorization
	// server's TLS certificate chains to.
	CAFile string `json:"ca_file"`

	// Subject is the sub the server issues for the test user.
	Subject string `json:"subject"`

	// CIBALoginHint is the login_hint naming the test user.
	CIBALoginHint string `json:"ciba_login_hint"`

	// CIBAApprovalURL is the server's test hook standing in for the
	// user's authentication device: a POST with form parameter
	// auth_req_id approves that request.
	CIBAApprovalURL string `json:"ciba_approval_url"`

	// LoginForm, if set, signs the test user in through the server's
	// own HTML pages: when the authorization request lands on a page
	// with a form instead of a redirect, the user agent fills in these
	// fields (name to value), keeps the form's hidden inputs, and posts
	// it (see userAgent.authorize). Unset for a server whose test
	// fixture signs the user in without a form.
	LoginForm map[string]string `json:"login_form,omitempty"`

	// Notification is the HTTPS listener the CIBA ping leg serves its
	// client_notification_endpoint on.
	Notification notificationConfig `json:"notification"`

	// Legs maps a leg name (see legs in main.go) to its client. A leg
	// missing here fails; one with Skip set is reported as skipped.
	Legs map[string]legConfig `json:"legs"`
}

type notificationConfig struct {
	ListenAddr string `json:"listen_addr"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
}

type legConfig struct {
	// Skip, if set, is why this leg can't run against this server.
	Skip string `json:"skip,omitempty"`

	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri,omitempty"`

	// SigningKeyFile is the PKCS #8 PEM ES256 private key whose public
	// half is registered for this client (private_key_jwt, request
	// objects, CIBA requests).
	SigningKeyFile string `json:"signing_key_file,omitempty"`

	// SigningKeyID is that key's registered kid.
	SigningKeyID string `json:"signing_key_id,omitempty"`

	// TLSClient is the client certificate this client presents, for
	// mutual-TLS client authentication or certificate-bound tokens.
	TLSClient *tlsFiles `json:"tls_client,omitempty"`

	// TLSClientAuth is the mutual-TLS client authentication method of a
	// leg that authenticates with its certificate (RFC 8705 §2):
	// "self_signed_tls_client_auth" (the default) or "tls_client_auth".
	TLSClientAuth string `json:"tls_client_auth,omitempty"`

	// IDTokenSignedResponseAlg is the ID token signing algorithm
	// registered for this client. Needed only for a server that
	// advertises more than one: NewFromDiscovery takes a single
	// advertised algorithm on its own.
	IDTokenSignedResponseAlg string `json:"id_token_signed_response_alg,omitempty"`

	// UserInfoSignedResponseAlg, if set, is the algorithm this client
	// is registered to receive signed UserInfo responses with (OIDC
	// Core §5.3.2); unset, UserInfo responses are plain JSON.
	UserInfoSignedResponseAlg string `json:"userinfo_signed_response_alg,omitempty"`

	// AuthorizationSignedResponseAlg, if set, is the algorithm this
	// client's JARM responses are registered to be signed with (JARM
	// §3); unset, a Message Signing leg expects ES256.
	AuthorizationSignedResponseAlg string `json:"authorization_signed_response_alg,omitempty"`

	Scope    []string `json:"scope"`
	Resource []string `json:"resource,omitempty"`

	// Prompt, if set, is sent as the authorization request's prompt
	// (OIDC Core §3.1.2.1): "consent" for a server that, following OIDC
	// Core §11, issues a refresh token for offline_access only with it.
	Prompt []string `json:"prompt,omitempty"`
}

type tlsFiles struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

func loadConfig(path string) (runConfig, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the runner's own config file
	if err != nil {
		return runConfig{}, err
	}
	var cfg runConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return runConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Issuer == "" || cfg.CAFile == "" || cfg.Subject == "" {
		return runConfig{}, fmt.Errorf("%s: issuer, ca_file and subject are required", path)
	}
	return cfg, nil
}
