package storage

import (
	"context"
	"fmt"
	"net"

	fapi "github.com/idfoundry/fapigo"
)

// SenderConstrain is the closed set of mechanisms a registered
// client's access (and refresh) tokens are sender-constrained with.
type SenderConstrain uint8

const (
	// SenderConstrainDPoP binds a client's tokens to a DPoP proof key
	// (RFC 9449) — the zero value, so every registered client that
	// predates this field keeps behaving exactly as it did before.
	SenderConstrainDPoP SenderConstrain = iota

	// SenderConstrainMTLS binds a client's tokens to the TLS client
	// certificate presented on the connection that requested them
	// (RFC 8705 §3's "cnf.x5t#S256"), instead of a DPoP proof. Like
	// DPoP, this needs no client registration or CA trust store of its
	// own — sender-constraining only compares thumbprints, it never
	// authenticates the client by its certificate.
	SenderConstrainMTLS
)

// ClientAuthMethod is the closed set of mechanisms a registered client
// authenticates itself to this server with.
type ClientAuthMethod uint8

const (
	// ClientAuthMethodPrivateKeyJWT authenticates via a signed client
	// assertion (RFC 7523) — the zero value, so every registered client
	// that predates this field keeps behaving exactly as it did before.
	ClientAuthMethodPrivateKeyJWT ClientAuthMethod = iota

	// ClientAuthMethodSelfSignedTLSClientAuth authenticates by exact
	// match of the presented TLS client certificate's RFC 8705 §3.1
	// x5t#S256 thumbprint against ExpectedCertificateThumbprint (RFC
	// 8705 §2.2) — no CA trust required; the certificate need only be
	// the one previously registered out of band.
	ClientAuthMethodSelfSignedTLSClientAuth

	// ClientAuthMethodTLSClientAuth authenticates by exact string match
	// of the presented certificate's subject DN against ExpectedSubjectDN
	// — RFC 8705 §2.1's "tls_client_auth_subject_dn", one of the five
	// subject-matching rules §2.1 defines (see the four
	// ClientAuthMethodTLSClientAuthSAN* values below for the others).
	// This package does not itself validate the certificate against a CA
	// trust store — that's a deployment/adapter concern
	// (tls.Config.ClientCAs), the same posture SenderConstrainMTLS
	// already documents for sender-constraining.
	ClientAuthMethodTLSClientAuth

	// ClientAuthMethodTLSClientAuthSANDNS authenticates by exact match
	// of ExpectedSANDNS against one of the presented certificate's
	// subjectAltName dNSName entries — RFC 8705 §2.1's
	// "tls_client_auth_san_dns". Same no-CA-validation posture as
	// ClientAuthMethodTLSClientAuth.
	ClientAuthMethodTLSClientAuthSANDNS

	// ClientAuthMethodTLSClientAuthSANURI authenticates by exact match
	// of ExpectedSANURI against one of the presented certificate's
	// subjectAltName uniformResourceIdentifier entries — RFC 8705
	// §2.1's "tls_client_auth_san_uri". Same no-CA-validation posture as
	// ClientAuthMethodTLSClientAuth.
	ClientAuthMethodTLSClientAuthSANURI

	// ClientAuthMethodTLSClientAuthSANIP authenticates by match of
	// ExpectedSANIP against one of the presented certificate's
	// subjectAltName iPAddress entries — RFC 8705 §2.1's
	// "tls_client_auth_san_ip". Compared as parsed net.IP values (not a
	// bare string), so equivalent representations of the same address
	// (e.g. an IPv4 address written in its IPv4-in-IPv6 form) still
	// match. Same no-CA-validation posture as ClientAuthMethodTLSClientAuth.
	ClientAuthMethodTLSClientAuthSANIP

	// ClientAuthMethodTLSClientAuthSANEmail authenticates by exact
	// match of ExpectedSANEmail against one of the presented
	// certificate's subjectAltName rfc822Name entries — RFC 8705 §2.1's
	// "tls_client_auth_san_email". Same no-CA-validation posture as
	// ClientAuthMethodTLSClientAuth.
	ClientAuthMethodTLSClientAuthSANEmail
)

// BackchannelTokenDeliveryMode is the closed set of mechanisms this
// server uses to tell a registered client that a CIBA backchannel
// authentication request has reached a decision (CIBA Core 1.0 §7–§10).
// FAPI-CIBA permits only poll and ping — push is not implemented.
type BackchannelTokenDeliveryMode uint8

const (
	// BackchannelTokenDeliveryModePoll means the client itself polls
	// the token endpoint on a schedule (CIBA §10.3) — the zero value,
	// so every registered client that predates this field keeps
	// behaving exactly as it did before.
	BackchannelTokenDeliveryModePoll BackchannelTokenDeliveryMode = iota

	// BackchannelTokenDeliveryModePing means this server proactively
	// notifies the client's own BackchannelClientNotificationEndpoint
	// once a decision is reached (CIBA §10.2), so the client can poll
	// immediately instead of on a fixed schedule. The client's backup
	// polling (CIBA §10.3) remains valid regardless — a missed or
	// failed notification is never itself an error condition.
	BackchannelTokenDeliveryModePing
)

// RegisteredClient is the exact, validated configuration of one
// registered OAuth client. It is immutable and can only be constructed
// through NewRegisteredClient — a caller cannot return arbitrary
// discovery or registration JSON in its place.
type RegisteredClient struct {
	id                            fapi.ClientID
	redirectURIs                  []fapi.RegisteredRedirectURI
	clientAssertionAlgorithm      fapi.SignatureAlgorithm
	requestObjectAlgorithm        fapi.SignatureAlgorithm
	senderConstrain               SenderConstrain
	clientAuthMethod              ClientAuthMethod
	expectedCertificateThumbprint string
	expectedSubjectDN             string
	expectedSANDNS                string
	expectedSANURI                string
	expectedSANIP                 string
	expectedSANEmail              string
	allowedScopes                 map[string]struct{}

	idTokenEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	idTokenEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	userInfoEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	userInfoEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	backchannelAuthenticationRequestAlgorithm fapi.SignatureAlgorithm
	backchannelTokenDeliveryMode              BackchannelTokenDeliveryMode
	backchannelClientNotificationEndpoint     fapi.URL

	allowsClientCredentialsGrant bool
}

// RegisteredClientConfig is the input to NewRegisteredClient.
type RegisteredClientConfig struct {
	ID           fapi.ClientID
	RedirectURIs []fapi.RegisteredRedirectURI

	// ClientAuthMethod selects how this client authenticates —
	// ClientAuthMethodPrivateKeyJWT (the zero value/default),
	// ClientAuthMethodSelfSignedTLSClientAuth, or
	// ClientAuthMethodTLSClientAuth.
	ClientAuthMethod ClientAuthMethod

	// ClientAssertionAlgorithm is the only algorithm this client's
	// private_key_jwt client assertions are accepted under. It is never
	// inferred from an assertion's own header. Required only when
	// ClientAuthMethod is ClientAuthMethodPrivateKeyJWT.
	ClientAssertionAlgorithm fapi.SignatureAlgorithm

	// ExpectedCertificateThumbprint is the RFC 8705 §3.1 x5t#S256 value
	// (base64url, no padding — the same shape internal/mtls.Thumbprint
	// produces) this client's TLS certificate must match. Required only
	// when ClientAuthMethod is ClientAuthMethodSelfSignedTLSClientAuth.
	ExpectedCertificateThumbprint string

	// ExpectedSubjectDN is the exact string this client's certificate's
	// subject must match, via Go's own pkix.Name.String() serialization
	// (crypto/x509.Certificate.Subject.String()) — not full RFC 4514
	// canonicalization, so this comparison is case-sensitive and
	// attribute-order-sensitive; register the DN exactly as Go
	// serializes the client's actual certificate. Required only when
	// ClientAuthMethod is ClientAuthMethodTLSClientAuth.
	ExpectedSubjectDN string

	// ExpectedSANDNS/ExpectedSANURI/ExpectedSANEmail are exact-string
	// matches against one of the client's certificate's subjectAltName
	// dNSName/uniformResourceIdentifier/rfc822Name entries (RFC 8705
	// §2.1's "tls_client_auth_san_dns"/"_san_uri"/"_san_email") —
	// required only when ClientAuthMethod is the corresponding
	// ClientAuthMethodTLSClientAuthSANDNS/SANURI/SANEmail. Compared via
	// Go's own crypto/x509.Certificate.URIs[i].String() for the URI
	// case, no further normalization for DNS/email.
	ExpectedSANDNS   string
	ExpectedSANURI   string
	ExpectedSANEmail string

	// ExpectedSANIP is this client's certificate's expected
	// subjectAltName iPAddress entry (RFC 8705 §2.1's
	// "tls_client_auth_san_ip") — any string net.ParseIP accepts.
	// Compared as a parsed net.IP, not a bare string, so equivalent
	// representations of the same address still match. Required only
	// when ClientAuthMethod is ClientAuthMethodTLSClientAuthSANIP.
	ExpectedSANIP string

	// RequestObjectAlgorithm is the only algorithm this client's signed
	// request objects are accepted under. Leave zero if the client is
	// not permitted to submit request objects at all.
	RequestObjectAlgorithm fapi.SignatureAlgorithm

	// SenderConstrain selects how this client's tokens are
	// sender-constrained — SenderConstrainDPoP (the zero value) or
	// SenderConstrainMTLS. Every existing client config that never sets
	// this field keeps using DPoP, unchanged.
	SenderConstrain SenderConstrain

	// IDTokenEncryptionKeyManagement/IDTokenEncryptionContentEncryption,
	// if set (together — both zero, or both set), mean every ID token
	// issued to this client is encrypted (OIDC Core §2) using these
	// algorithms — the local record of this client's own
	// id_token_encrypted_response_alg/enc registration. Leave both zero
	// if the client did not register for encrypted ID tokens. Checked
	// against server.Config.Algorithms' own allow-list at issuance time,
	// not here: this type validates internal consistency only, not
	// server-wide policy, the same way ClientAssertionAlgorithm/
	// RequestObjectAlgorithm are validated for shape here and checked
	// against server-wide policy elsewhere.
	IDTokenEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	IDTokenEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	// UserInfoEncryptionKeyManagement/UserInfoEncryptionContentEncryption
	// mirror IDTokenEncryptionKeyManagement/ContentEncryption exactly,
	// but for this client's own, independent
	// userinfo_encrypted_response_alg/enc registration (OIDC Core
	// §5.3.2) — a client may register for one without the other. Leave
	// both zero if the client did not register for encrypted UserInfo
	// responses.
	UserInfoEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	UserInfoEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	// BackchannelAuthenticationRequestAlgorithm is the only algorithm
	// this client's signed CIBA backchannel authentication requests are
	// accepted under. Leave zero if the client is not permitted to use
	// CIBA at all — since FAPI-CIBA always requires a signed request
	// (unlike RequestObjectAlgorithm, whose signing is profile-dependent
	// for PAR), this single field doubles as this client's CIBA opt-in
	// flag.
	BackchannelAuthenticationRequestAlgorithm fapi.SignatureAlgorithm

	// BackchannelTokenDeliveryMode selects how this server tells this
	// client a CIBA decision was reached — BackchannelTokenDeliveryModePoll
	// (the zero value/default) or BackchannelTokenDeliveryModePing.
	// Meaningless (and must stay the zero value) for a client not
	// permitted to use CIBA at all — see
	// BackchannelAuthenticationRequestAlgorithm's own doc comment.
	BackchannelTokenDeliveryMode BackchannelTokenDeliveryMode

	// BackchannelClientNotificationEndpoint is where this server POSTs
	// a bearer-authenticated notification once a CIBA decision is
	// reached (CIBA §10.2). Required exactly when
	// BackchannelTokenDeliveryMode is BackchannelTokenDeliveryModePing;
	// must be left unset for poll mode, since nothing would ever use it.
	BackchannelClientNotificationEndpoint fapi.URL

	AllowedScopes []string

	// AllowsClientCredentialsGrant permits this client to use the RFC
	// 6749 §4.4 client_credentials grant at the token endpoint —
	// false (the zero value/default) means it cannot, the same
	// explicit-per-client-capability stance
	// BackchannelAuthenticationRequestAlgorithm takes for CIBA. Having
	// AllowedScopes configured does not implicitly permit
	// client_credentials use; this is a separate opt-in. Also requires
	// server.Config.ClientCredentialsGrant to be enabled server-wide —
	// this field alone does not activate the grant if that deployment
	// -wide switch is off.
	AllowsClientCredentialsGrant bool
}

// NewRegisteredClient validates cfg and returns an immutable
// RegisteredClient.
func NewRegisteredClient(cfg RegisteredClientConfig) (RegisteredClient, error) {
	if cfg.ID == "" {
		return RegisteredClient{}, fmt.Errorf("storage: client ID is empty")
	}
	if len(cfg.RedirectURIs) == 0 {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has no registered redirect URIs", cfg.ID)
	}
	switch cfg.ClientAuthMethod {
	case ClientAuthMethodPrivateKeyJWT:
		if !cfg.ClientAssertionAlgorithm.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has no valid client assertion algorithm", cfg.ID)
		}
	case ClientAuthMethodSelfSignedTLSClientAuth:
		if cfg.ExpectedCertificateThumbprint == "" {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must set ExpectedCertificateThumbprint for self_signed_tls_client_auth", cfg.ID)
		}
	case ClientAuthMethodTLSClientAuth:
		if cfg.ExpectedSubjectDN == "" {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must set ExpectedSubjectDN for tls_client_auth", cfg.ID)
		}
	case ClientAuthMethodTLSClientAuthSANDNS:
		if cfg.ExpectedSANDNS == "" {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must set ExpectedSANDNS for tls_client_auth_san_dns", cfg.ID)
		}
	case ClientAuthMethodTLSClientAuthSANURI:
		if cfg.ExpectedSANURI == "" {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must set ExpectedSANURI for tls_client_auth_san_uri", cfg.ID)
		}
	case ClientAuthMethodTLSClientAuthSANIP:
		if cfg.ExpectedSANIP == "" {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must set ExpectedSANIP for tls_client_auth_san_ip", cfg.ID)
		}
		if net.ParseIP(cfg.ExpectedSANIP) == nil {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid ExpectedSANIP %q", cfg.ID, cfg.ExpectedSANIP)
		}
	case ClientAuthMethodTLSClientAuthSANEmail:
		if cfg.ExpectedSANEmail == "" {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must set ExpectedSANEmail for tls_client_auth_san_email", cfg.ID)
		}
	default:
		return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid client auth method", cfg.ID)
	}
	if cfg.RequestObjectAlgorithm != 0 && !cfg.RequestObjectAlgorithm.IsValid() {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid request object algorithm", cfg.ID)
	}
	if cfg.SenderConstrain != SenderConstrainDPoP && cfg.SenderConstrain != SenderConstrainMTLS {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid sender_constrain value", cfg.ID)
	}
	if cfg.BackchannelAuthenticationRequestAlgorithm != 0 && !cfg.BackchannelAuthenticationRequestAlgorithm.IsValid() {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid backchannel authentication request algorithm", cfg.ID)
	}
	switch cfg.BackchannelTokenDeliveryMode {
	case BackchannelTokenDeliveryModePoll:
		if !cfg.BackchannelClientNotificationEndpoint.IsZero() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must not set BackchannelClientNotificationEndpoint for poll delivery", cfg.ID)
		}
	case BackchannelTokenDeliveryModePing:
		if cfg.BackchannelAuthenticationRequestAlgorithm == 0 {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must be permitted to use CIBA (set BackchannelAuthenticationRequestAlgorithm) to use ping delivery", cfg.ID)
		}
		if cfg.BackchannelClientNotificationEndpoint.IsZero() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q must set BackchannelClientNotificationEndpoint for ping delivery", cfg.ID)
		}
	default:
		return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid backchannel token delivery mode", cfg.ID)
	}
	idTokenEncKeyMgmtSet := cfg.IDTokenEncryptionKeyManagement != 0
	idTokenEncContentEncSet := cfg.IDTokenEncryptionContentEncryption != 0
	if idTokenEncKeyMgmtSet != idTokenEncContentEncSet {
		return RegisteredClient{}, fmt.Errorf("storage: client %q must set both IDTokenEncryptionKeyManagement and IDTokenEncryptionContentEncryption, or neither", cfg.ID)
	}
	if idTokenEncKeyMgmtSet {
		if !cfg.IDTokenEncryptionKeyManagement.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid ID token encryption key management algorithm", cfg.ID)
		}
		if !cfg.IDTokenEncryptionContentEncryption.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid ID token encryption content encryption algorithm", cfg.ID)
		}
	}
	userInfoEncKeyMgmtSet := cfg.UserInfoEncryptionKeyManagement != 0
	userInfoEncContentEncSet := cfg.UserInfoEncryptionContentEncryption != 0
	if userInfoEncKeyMgmtSet != userInfoEncContentEncSet {
		return RegisteredClient{}, fmt.Errorf("storage: client %q must set both UserInfoEncryptionKeyManagement and UserInfoEncryptionContentEncryption, or neither", cfg.ID)
	}
	if userInfoEncKeyMgmtSet {
		if !cfg.UserInfoEncryptionKeyManagement.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid UserInfo encryption key management algorithm", cfg.ID)
		}
		if !cfg.UserInfoEncryptionContentEncryption.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid UserInfo encryption content encryption algorithm", cfg.ID)
		}
	}

	scopes := make(map[string]struct{}, len(cfg.AllowedScopes))
	for _, s := range cfg.AllowedScopes {
		if s == "" {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an empty allowed scope", cfg.ID)
		}
		scopes[s] = struct{}{}
	}

	redirectURIs := make([]fapi.RegisteredRedirectURI, len(cfg.RedirectURIs))
	copy(redirectURIs, cfg.RedirectURIs)

	return RegisteredClient{
		id:                                        cfg.ID,
		redirectURIs:                              redirectURIs,
		clientAssertionAlgorithm:                  cfg.ClientAssertionAlgorithm,
		requestObjectAlgorithm:                    cfg.RequestObjectAlgorithm,
		senderConstrain:                           cfg.SenderConstrain,
		clientAuthMethod:                          cfg.ClientAuthMethod,
		expectedCertificateThumbprint:             cfg.ExpectedCertificateThumbprint,
		expectedSubjectDN:                         cfg.ExpectedSubjectDN,
		expectedSANDNS:                            cfg.ExpectedSANDNS,
		expectedSANURI:                            cfg.ExpectedSANURI,
		expectedSANIP:                             cfg.ExpectedSANIP,
		expectedSANEmail:                          cfg.ExpectedSANEmail,
		allowedScopes:                             scopes,
		idTokenEncryptionKeyManagement:            cfg.IDTokenEncryptionKeyManagement,
		idTokenEncryptionContentEncryption:        cfg.IDTokenEncryptionContentEncryption,
		userInfoEncryptionKeyManagement:           cfg.UserInfoEncryptionKeyManagement,
		userInfoEncryptionContentEncryption:       cfg.UserInfoEncryptionContentEncryption,
		backchannelAuthenticationRequestAlgorithm: cfg.BackchannelAuthenticationRequestAlgorithm,
		backchannelTokenDeliveryMode:              cfg.BackchannelTokenDeliveryMode,
		backchannelClientNotificationEndpoint:     cfg.BackchannelClientNotificationEndpoint,
		allowsClientCredentialsGrant:              cfg.AllowsClientCredentialsGrant,
	}, nil
}

// ID returns the client's ID.
func (c RegisteredClient) ID() fapi.ClientID { return c.id }

// HasRedirectURI reports whether candidate is exactly one of this
// client's registered redirect URIs (RegisteredRedirectURI.Equal
// semantics — exact match, no normalization).
func (c RegisteredClient) HasRedirectURI(candidate string) bool {
	for _, u := range c.redirectURIs {
		if u.Equal(candidate) {
			return true
		}
	}
	return false
}

// ClientAssertionAlgorithm returns the algorithm this client's client
// assertions must be signed with.
func (c RegisteredClient) ClientAssertionAlgorithm() fapi.SignatureAlgorithm {
	return c.clientAssertionAlgorithm
}

// RequestObjectAlgorithm returns the algorithm this client's request
// objects must be signed with, and whether the client is permitted to
// submit request objects at all.
func (c RegisteredClient) RequestObjectAlgorithm() (algorithm fapi.SignatureAlgorithm, permitted bool) {
	return c.requestObjectAlgorithm, c.requestObjectAlgorithm != 0
}

// SenderConstrain returns how this client's tokens are
// sender-constrained.
func (c RegisteredClient) SenderConstrain() SenderConstrain {
	return c.senderConstrain
}

// ClientAuthMethod returns how this client authenticates itself.
func (c RegisteredClient) ClientAuthMethod() ClientAuthMethod {
	return c.clientAuthMethod
}

// ExpectedCertificateThumbprint returns the RFC 8705 §3.1 x5t#S256
// value this client's TLS certificate must match under
// ClientAuthMethodSelfSignedTLSClientAuth.
func (c RegisteredClient) ExpectedCertificateThumbprint() string {
	return c.expectedCertificateThumbprint
}

// ExpectedSubjectDN returns the subject DN this client's TLS
// certificate must match under ClientAuthMethodTLSClientAuth.
func (c RegisteredClient) ExpectedSubjectDN() string {
	return c.expectedSubjectDN
}

// ExpectedSANDNS returns the subjectAltName dNSName entry this client's
// TLS certificate must carry under ClientAuthMethodTLSClientAuthSANDNS.
func (c RegisteredClient) ExpectedSANDNS() string {
	return c.expectedSANDNS
}

// ExpectedSANURI returns the subjectAltName uniformResourceIdentifier
// entry this client's TLS certificate must carry under
// ClientAuthMethodTLSClientAuthSANURI.
func (c RegisteredClient) ExpectedSANURI() string {
	return c.expectedSANURI
}

// ExpectedSANIP returns the subjectAltName iPAddress entry this
// client's TLS certificate must carry under
// ClientAuthMethodTLSClientAuthSANIP.
func (c RegisteredClient) ExpectedSANIP() string {
	return c.expectedSANIP
}

// ExpectedSANEmail returns the subjectAltName rfc822Name entry this
// client's TLS certificate must carry under
// ClientAuthMethodTLSClientAuthSANEmail.
func (c RegisteredClient) ExpectedSANEmail() string {
	return c.expectedSANEmail
}

// IDTokenEncryption returns the algorithms this client's ID tokens must
// be encrypted with, and whether the client registered for encrypted ID
// tokens at all.
func (c RegisteredClient) IDTokenEncryption() (keyManagement fapi.KeyManagementAlgorithm, contentEncryption fapi.ContentEncryptionAlgorithm, enabled bool) {
	return c.idTokenEncryptionKeyManagement, c.idTokenEncryptionContentEncryption, c.idTokenEncryptionKeyManagement != 0
}

// UserInfoEncryption returns the algorithms this client's UserInfo
// responses must be encrypted with, and whether the client registered
// for encrypted UserInfo responses at all.
func (c RegisteredClient) UserInfoEncryption() (keyManagement fapi.KeyManagementAlgorithm, contentEncryption fapi.ContentEncryptionAlgorithm, enabled bool) {
	return c.userInfoEncryptionKeyManagement, c.userInfoEncryptionContentEncryption, c.userInfoEncryptionKeyManagement != 0
}

// BackchannelAuthenticationRequestAlgorithm returns the algorithm this
// client's signed CIBA backchannel authentication requests must be
// signed with, and whether the client is permitted to use CIBA at all.
func (c RegisteredClient) BackchannelAuthenticationRequestAlgorithm() (algorithm fapi.SignatureAlgorithm, permitted bool) {
	return c.backchannelAuthenticationRequestAlgorithm, c.backchannelAuthenticationRequestAlgorithm != 0
}

// BackchannelTokenDeliveryMode returns how this server tells this
// client a CIBA decision was reached.
func (c RegisteredClient) BackchannelTokenDeliveryMode() BackchannelTokenDeliveryMode {
	return c.backchannelTokenDeliveryMode
}

// BackchannelClientNotificationEndpoint returns where this server POSTs
// a bearer-authenticated notification once a CIBA decision is reached,
// under BackchannelTokenDeliveryModePing.
func (c RegisteredClient) BackchannelClientNotificationEndpoint() fapi.URL {
	return c.backchannelClientNotificationEndpoint
}

// AllowsClientCredentialsGrant reports whether this client may use the
// RFC 6749 §4.4 client_credentials grant.
func (c RegisteredClient) AllowsClientCredentialsGrant() bool {
	return c.allowsClientCredentialsGrant
}

// AllowsScope reports whether scope is in this client's registered set
// of allowed scopes.
func (c RegisteredClient) AllowsScope(scope string) bool {
	_, ok := c.allowedScopes[scope]
	return ok
}

// ClientRepository resolves a registered client by ID.
type ClientRepository interface {
	ResolveClient(ctx context.Context, id fapi.ClientID) (RegisteredClient, error)
}
