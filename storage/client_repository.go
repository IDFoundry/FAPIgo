package storage

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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

// ApplicationType is what kind of application a client is, which
// decides the redirect URIs it may use (OpenID Connect Dynamic Client
// Registration 1.0 §2's application_type; RFC 8252 §8.4 asks a server
// to record it).
type ApplicationType uint8

const (
	// ApplicationTypeWeb is a web application — the zero value, so every
	// client registered before this field keeps behaving as it did. Its
	// redirect URIs are https, plus loopback http under development
	// assurance.
	ApplicationTypeWeb ApplicationType = iota

	// ApplicationTypeNative is a native app — a mobile or desktop
	// wallet, say — which receives its authorization response at one of
	// RFC 8252's native-app redirect URIs, in production as well:
	//
	//   - a private-use URI scheme (RFC 8252 §7.1), a domain name in
	//     reverse order, then a single slash: com.example.app:/callback,
	//     not com.example.app://callback;
	//   - loopback http (§7.3) to the IP literal 127.0.0.1 or [::1], never
	//     "localhost" (§8.3), matched on any port at request time;
	//   - a claimed https URI (§7.2), as for a web application.
	//
	// NewRegisteredClient refuses a native client's redirect URI of any
	// other form. A native client still authenticates as every client
	// here does: give each app instance credentials of its own, as
	// attestation-based client authentication does.
	ApplicationTypeNative
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
	// (tls.Config.ClientCAs) — and neither does the field match alone:
	// unlike ClientAuthMethodSelfSignedTLSClientAuth's thumbprint (which
	// cryptographically binds the exact certificate), a subject-DN/SAN
	// match by itself proves nothing about who issued the certificate —
	// any self-signed certificate whose subject an attacker chooses to
	// match a registered value would pass unless something also checks
	// the certificate's chain. server.Dependencies.ClientCertificateTrust
	// is that something: server.TrustedClientCAs{...} has this server
	// independently verify the presented certificate before ever
	// comparing subject/SAN fields, for every
	// ClientAuthMethodTLSClientAuth*/SAN* method (not
	// ClientAuthMethodSelfSignedTLSClientAuth, which needs no chain
	// trust); server.NoClientCertificateChainTrust{} instead relies
	// entirely on the deployment's own TLS termination to have already
	// required and verified the chain (tls.Config.ClientAuth:
	// RequireAndVerifyClientCert or VerifyClientCertIfGiven, with
	// ClientCAs set) before this server ever sees the request — get that
	// wrong, on either side, and any self-signed certificate with a
	// matching subject/SAN is accepted as this client.
	ClientAuthMethodTLSClientAuth

	// ClientAuthMethodTLSClientAuthSANDNS authenticates by exact match
	// of ExpectedSANDNS against one of the presented certificate's
	// subjectAltName dNSName entries — RFC 8705 §2.1's
	// "tls_client_auth_san_dns". Same chain-trust posture as
	// ClientAuthMethodTLSClientAuth — see its own doc comment.
	ClientAuthMethodTLSClientAuthSANDNS

	// ClientAuthMethodTLSClientAuthSANURI authenticates by exact match
	// of ExpectedSANURI against one of the presented certificate's
	// subjectAltName uniformResourceIdentifier entries — RFC 8705
	// §2.1's "tls_client_auth_san_uri". Same chain-trust posture as
	// ClientAuthMethodTLSClientAuth — see its own doc comment.
	ClientAuthMethodTLSClientAuthSANURI

	// ClientAuthMethodTLSClientAuthSANIP authenticates by match of
	// ExpectedSANIP against one of the presented certificate's
	// subjectAltName iPAddress entries — RFC 8705 §2.1's
	// "tls_client_auth_san_ip". Compared as parsed net.IP values (not a
	// bare string), so equivalent representations of the same address
	// (e.g. an IPv4 address written in its IPv4-in-IPv6 form) still
	// match. Same chain-trust posture as ClientAuthMethodTLSClientAuth —
	// see its own doc comment.
	ClientAuthMethodTLSClientAuthSANIP

	// ClientAuthMethodTLSClientAuthSANEmail authenticates by exact
	// match of ExpectedSANEmail against one of the presented
	// certificate's subjectAltName rfc822Name entries — RFC 8705 §2.1's
	// "tls_client_auth_san_email". Same chain-trust posture as
	// ClientAuthMethodTLSClientAuth — see its own doc comment.
	ClientAuthMethodTLSClientAuthSANEmail

	// ClientAuthMethodAttestation authenticates via a pair of JWTs — a
	// Client Attestation, signed by a trusted Attester (ExpectedAttesterIssuer)
	// and vouching for this client, plus a Client Attestation PoP signed
	// by the Client Instance Key the Attestation names in its "cnf"
	// claim — per OAuth 2.0 Attestation-Based Client Authentication
	// (draft-ietf-oauth-attestation-based-client-auth-07). Unlike every
	// other ClientAuthMethod, the credential proving this client's
	// identity is issued by a third party (the Attester), not held
	// directly by the client or pre-registered with this server; only
	// the Attester's own trust relationship is registered
	// (ExpectedAttesterIssuer, ClientAttestationAlgorithm); how the
	// Attester's signing key is trusted — a certificate chain to trust
	// anchors, or a registered key — is server.Dependencies.AttesterTrust's
	// choice. Requires
	// server.Config.AttestationBasedClientAuthentication to be enabled
	// server-wide — this value alone does not activate the mechanism if
	// that deployment-wide switch is off, the same relationship
	// AllowsClientCredentialsGrant has with Config.ClientCredentialsGrant.
	ClientAuthMethodAttestation
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
	applicationType               ApplicationType
	clientAssertionAlgorithm      fapi.SignatureAlgorithm
	clientAssertionAlgorithms     []fapi.SignatureAlgorithm
	requestObjectAlgorithm        fapi.SignatureAlgorithm
	senderConstrain               SenderConstrain
	clientAuthMethod              ClientAuthMethod
	clientAuthMethods             []ClientAuthMethod
	expectedCertificateThumbprint string
	expectedSubjectDN             string
	expectedSANDNS                string
	expectedSANURI                string
	expectedSANIP                 string
	expectedSANEmail              string
	expectedAttesterIssuer        string
	clientAttestationAlgorithm    fapi.SignatureAlgorithm
	allowedScopes                 map[string]struct{}
	authorizationDetailsTypes     map[string]struct{}

	idTokenEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	idTokenEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	userInfoEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	userInfoEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	backchannelAuthenticationRequestAlgorithm fapi.SignatureAlgorithm
	backchannelTokenDeliveryMode              BackchannelTokenDeliveryMode
	backchannelClientNotificationEndpoint     fapi.URL

	allowsClientCredentialsGrant    bool
	automaticFederationRegistration bool
	display                         ClientDisplay
}

// RegisteredClientConfig is the input to NewRegisteredClient.
type RegisteredClientConfig struct {
	ID fapi.ClientID

	// RedirectURIs are where the authorization code grant may send its
	// response. Required, unless the client is registered only for
	// grants that never redirect — CIBA
	// (BackchannelAuthenticationRequestAlgorithm set) or client
	// credentials (AllowsClientCredentialsGrant) — in which case, left
	// empty, the client can't use the authorization code grant (see
	// RegisteredClient.AllowsAuthorizationCodeGrant).
	RedirectURIs []fapi.RegisteredRedirectURI

	// ApplicationType is ApplicationTypeWeb (the zero value) or
	// ApplicationTypeNative, which admits a native app's redirect URIs —
	// see ApplicationTypeNative.
	ApplicationType ApplicationType

	// ClientAuthMethod selects how this client authenticates —
	// ClientAuthMethodPrivateKeyJWT (the zero value/default),
	// ClientAuthMethodSelfSignedTLSClientAuth, or
	// ClientAuthMethodTLSClientAuth. Ignored when ClientAuthMethods is
	// set, unless it names a method that list doesn't include, which is
	// an error.
	ClientAuthMethod ClientAuthMethod

	// ClientAuthMethods, when set, is every method this client may
	// authenticate with — e.g. a relying party's own
	// token_endpoint_auth_methods_supported (OpenID Connect RP Metadata
	// Choices 1.0). The server accepts whichever of them a request
	// actually uses. Each listed method needs its own field below
	// (ClientAssertionAlgorithm(s) for private_key_jwt,
	// ExpectedCertificateThumbprint for self_signed_tls_client_auth, and
	// so on). Optional; the zero value means ClientAuthMethod alone.
	ClientAuthMethods []ClientAuthMethod

	// ClientAssertionAlgorithm is the algorithm this client's
	// private_key_jwt client assertions are accepted under. Required when
	// private_key_jwt is among its methods, unless
	// ClientAssertionAlgorithms is set.
	ClientAssertionAlgorithm fapi.SignatureAlgorithm

	// ClientAssertionAlgorithms, when set, is every algorithm this
	// client's private_key_jwt client assertions may be signed with. An
	// assertion's own header "alg" only selects among these — an
	// algorithm not listed here (or not allowed by the server) is
	// rejected, never inferred. ClientAssertionAlgorithm, if also set,
	// must be one of them. Optional.
	ClientAssertionAlgorithms []fapi.SignatureAlgorithm

	// ExpectedCertificateThumbprint is the RFC 8705 §3.1 x5t#S256 value
	// (base64url, no padding — the same shape internal/mtls.Thumbprint
	// produces) this client's TLS certificate must match. Required only
	// when ClientAuthMethod is ClientAuthMethodSelfSignedTLSClientAuth.
	ExpectedCertificateThumbprint string

	// ExpectedSubjectDN is the exact string this client's certificate's
	// subject must match. Either of two forms matches:
	//
	//   - the RFC 4514 string of the certificate's subject as encoded
	//     (pkix.RDNSequence.String() of the certificate's RawSubject),
	//     which keeps every attribute, its order and its RDN grouping.
	//     Prefer this form;
	//   - Go's pkix.Name.String() serialization
	//     (crypto/x509.Certificate.Subject.String()), which rebuilds the
	//     subject in Go's own attribute order and groups repeated
	//     attributes into one RDN, so it doesn't tell apart subjects
	//     that differ only in attribute order or grouping. It keeps one
	//     CN and one serialNumber, and skips an attribute whose value
	//     isn't a string, so a subject with more than one of either, or
	//     with any non-string value, never matches in this form.
	//
	// Neither is RFC 4514 canonicalization: the comparison is
	// case-sensitive, and the string must be registered exactly as the
	// client's actual certificate serializes. Required only when
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

	// ExpectedAttesterIssuer is the "iss" value this client's Client
	// Attestation JWT must carry (OAuth 2.0 Attestation-Based Client
	// Authentication draft-07 §5.1) — the trusted Attester vouching for
	// this Client Instance. Required only when ClientAuthMethod is
	// ClientAuthMethodAttestation. Compared by exact string match, the
	// same way ExpectedSubjectDN/ExpectedSAN* are.
	ExpectedAttesterIssuer string

	// ClientAttestationAlgorithm is the only algorithm this client's
	// Client Attestation JWTs are accepted under (draft-07 §5.1) —
	// never inferred from the Attestation's own header, the same
	// algorithm-confusion protection ClientAssertionAlgorithm provides
	// for private_key_jwt. Required only when ClientAuthMethod is
	// ClientAuthMethodAttestation. The accompanying Client Attestation
	// PoP JWT (draft-07 §5.2) needs no algorithm registered here: its
	// signing key is the Client Instance Key the already-verified
	// Attestation names in its own "cnf" claim, not a pre-registered
	// one — see internal/clientattestation's package doc comment.
	ClientAttestationAlgorithm fapi.SignatureAlgorithm

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

	// AuthorizationDetailsTypes are the Rich Authorization Request types
	// (RFC 9396 §2, the authorization_details "type" member) this client
	// may request, its "authorization_details_types" client metadata
	// (RFC 9396 §10). The server refuses any other type with
	// invalid_authorization_details before consulting its RARPolicy. Empty
	// means none: a client requesting authorization_details must list
	// every type it uses.
	AuthorizationDetailsTypes []string

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

	// AutomaticFederationRegistration marks this client as resolved via
	// OpenID Federation 1.0 §12.1 ("Automatic Registration") rather than
	// statically configured — set only by
	// federation.AutomaticClientRepository, never by a caller
	// configuring a static client by hand. When true, server-side
	// request object handling applies §12.1.1's stricter Request Object
	// rules instead of the generic RFC 9101 ones: see
	// requestobject.VerifyPolicy.AutomaticFederationRegistration's own
	// doc comment for exactly what that changes.
	AutomaticFederationRegistration bool

	// Display is how a consent screen can present this client. Optional:
	// the zero value means nothing beyond ClientID is known.
	Display ClientDisplay
}

// MaxClientNameBytes bounds ClientDisplay.Name.
const MaxClientNameBytes = 200

// ClientDisplay is what a consent screen can show about a client — the
// OpenID Connect Dynamic Client Registration 1.0 §2 client_name,
// logo_uri, policy_uri and tos_uri. For a client registered
// automatically through OpenID Federation it comes from the client's
// own published metadata, as its superiors' metadata policies left it:
// the client chose it, so show it alongside the client ID, never
// instead of it, and escape it like any other untrusted text.
type ClientDisplay struct {
	// Name is at most MaxClientNameBytes of valid UTF-8, with no
	// control or bidirectional-formatting characters (which could make
	// it render as something other than what it is).
	Name string

	// LogoURI, PolicyURI and TermsOfServiceURI are https URLs (fapi.URL
	// guarantees the scheme, so none can be a javascript: or data: URL).
	// They point wherever the client chose: a consent page that loads
	// LogoURI straight from the user's browser tells the client's host
	// that, when and (by IP address) to whom its consent screen was shown,
	// and can aim the browser at an https address on the user's own
	// network. Fetch and cache the logo server-side, or leave it out.
	LogoURI           fapi.URL
	PolicyURI         fapi.URL
	TermsOfServiceURI fapi.URL
}

// IsZero reports whether nothing is known about the client beyond its ID.
func (d ClientDisplay) IsZero() bool {
	return d.Name == "" && d.LogoURI.IsZero() && d.PolicyURI.IsZero() && d.TermsOfServiceURI.IsZero()
}

// ValidateClientName reports whether name is acceptable as
// ClientDisplay.Name.
func ValidateClientName(name string) error {
	if len(name) > MaxClientNameBytes {
		return fmt.Errorf("client name is longer than %d bytes", MaxClientNameBytes)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("client name is not valid UTF-8")
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return fmt.Errorf("client name contains control character %U", r)
		}
	}
	return nil
}

// NeedsJWKS reports whether a client configured this way needs a
// discoverable JWKS at all — true iff it does any JWS signing:
// ClientAuthMethodPrivateKeyJWT client assertions, signed request
// objects (RequestObjectAlgorithm set), or signed CIBA backchannel
// authentication requests (BackchannelAuthenticationRequestAlgorithm
// set). A client registered for certificate-based authentication that
// does neither of the latter two has no key material to publish.
//
// This only answers whether a JWKS is needed at all — not which of
// jwks/jwks_uri (or both, or neither) a specific wire format should
// carry for it; that's a caller's own config-format decision, the same
// division ParseClientAuthMethod's own doc comment draws between
// mechanism and policy.
func (cfg RegisteredClientConfig) NeedsJWKS() bool {
	usesPrivateKeyJWT := cfg.ClientAuthMethod == ClientAuthMethodPrivateKeyJWT && len(cfg.ClientAuthMethods) == 0 ||
		slices.Contains(cfg.ClientAuthMethods, ClientAuthMethodPrivateKeyJWT)
	return usesPrivateKeyJWT || cfg.RequestObjectAlgorithm != 0 || cfg.BackchannelAuthenticationRequestAlgorithm != 0
}

// NewRegisteredClient validates cfg and returns an immutable
// RegisteredClient. Each thematic group of checks is split into its
// own function purely to keep this constructor's own cognitive
// complexity manageable — the checks, their order and their error
// messages are unchanged.
func NewRegisteredClient(cfg RegisteredClientConfig) (RegisteredClient, error) {
	if cfg.ID == "" {
		return RegisteredClient{}, fmt.Errorf("storage: client ID is empty")
	}
	// Only the authorization code grant redirects: a client registered
	// only for CIBA or client credentials needs no redirect URI.
	if len(cfg.RedirectURIs) == 0 && cfg.BackchannelAuthenticationRequestAlgorithm == 0 && !cfg.AllowsClientCredentialsGrant {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has no registered redirect URIs, and isn't registered for CIBA or client credentials", cfg.ID)
	}
	methods, err := clientAuthMethods(cfg)
	if err != nil {
		return RegisteredClient{}, err
	}
	algs, err := clientAssertionAlgorithms(cfg)
	if err != nil {
		return RegisteredClient{}, err
	}
	for _, method := range methods {
		if err := validateClientAuthMethodFields(cfg, method, algs); err != nil {
			return RegisteredClient{}, err
		}
	}
	var primaryAlg fapi.SignatureAlgorithm
	if len(algs) > 0 {
		primaryAlg = algs[0]
	}
	if err := ValidateClientName(cfg.Display.Name); err != nil {
		return RegisteredClient{}, fmt.Errorf("storage: client %q: %w", cfg.ID, err)
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
	if err := validateBackchannelTokenDeliveryMode(cfg); err != nil {
		return RegisteredClient{}, err
	}
	if err := validateIDTokenEncryptionFields(cfg); err != nil {
		return RegisteredClient{}, err
	}
	if err := validateUserInfoEncryptionFields(cfg); err != nil {
		return RegisteredClient{}, err
	}

	scopes, err := stringSet(cfg.ID, "allowed scope", cfg.AllowedScopes)
	if err != nil {
		return RegisteredClient{}, err
	}
	rarTypes, err := stringSet(cfg.ID, "authorization details type", cfg.AuthorizationDetailsTypes)
	if err != nil {
		return RegisteredClient{}, err
	}

	if err := checkApplicationType(cfg); err != nil {
		return RegisteredClient{}, err
	}
	redirectURIs := make([]fapi.RegisteredRedirectURI, len(cfg.RedirectURIs))
	copy(redirectURIs, cfg.RedirectURIs)

	return RegisteredClient{
		id:                                        cfg.ID,
		redirectURIs:                              redirectURIs,
		applicationType:                           cfg.ApplicationType,
		clientAssertionAlgorithm:                  primaryAlg,
		clientAssertionAlgorithms:                 algs,
		requestObjectAlgorithm:                    cfg.RequestObjectAlgorithm,
		senderConstrain:                           cfg.SenderConstrain,
		clientAuthMethod:                          methods[0],
		clientAuthMethods:                         methods,
		expectedCertificateThumbprint:             cfg.ExpectedCertificateThumbprint,
		expectedSubjectDN:                         cfg.ExpectedSubjectDN,
		expectedSANDNS:                            cfg.ExpectedSANDNS,
		expectedSANURI:                            cfg.ExpectedSANURI,
		expectedSANIP:                             cfg.ExpectedSANIP,
		expectedSANEmail:                          cfg.ExpectedSANEmail,
		expectedAttesterIssuer:                    cfg.ExpectedAttesterIssuer,
		clientAttestationAlgorithm:                cfg.ClientAttestationAlgorithm,
		allowedScopes:                             scopes,
		authorizationDetailsTypes:                 rarTypes,
		idTokenEncryptionKeyManagement:            cfg.IDTokenEncryptionKeyManagement,
		idTokenEncryptionContentEncryption:        cfg.IDTokenEncryptionContentEncryption,
		userInfoEncryptionKeyManagement:           cfg.UserInfoEncryptionKeyManagement,
		userInfoEncryptionContentEncryption:       cfg.UserInfoEncryptionContentEncryption,
		backchannelAuthenticationRequestAlgorithm: cfg.BackchannelAuthenticationRequestAlgorithm,
		backchannelTokenDeliveryMode:              cfg.BackchannelTokenDeliveryMode,
		backchannelClientNotificationEndpoint:     cfg.BackchannelClientNotificationEndpoint,
		allowsClientCredentialsGrant:              cfg.AllowsClientCredentialsGrant,
		automaticFederationRegistration:           cfg.AutomaticFederationRegistration,
		display:                                   cfg.Display,
	}, nil
}

// clientAuthMethods is every method cfg allows: ClientAuthMethods when
// set (which must include a non-default ClientAuthMethod), otherwise
// ClientAuthMethod alone. Duplicates are dropped.
func clientAuthMethods(cfg RegisteredClientConfig) ([]ClientAuthMethod, error) {
	if len(cfg.ClientAuthMethods) == 0 {
		return []ClientAuthMethod{cfg.ClientAuthMethod}, nil
	}
	if cfg.ClientAuthMethod != ClientAuthMethodPrivateKeyJWT && !slices.Contains(cfg.ClientAuthMethods, cfg.ClientAuthMethod) {
		return nil, fmt.Errorf("storage: client %q's ClientAuthMethod is not among its ClientAuthMethods", cfg.ID)
	}
	var methods []ClientAuthMethod
	for _, m := range cfg.ClientAuthMethods {
		if !slices.Contains(methods, m) {
			methods = append(methods, m)
		}
	}
	return methods, nil
}

// clientAssertionAlgorithms is every algorithm cfg allows for
// private_key_jwt: ClientAssertionAlgorithms when set (which must include
// a set ClientAssertionAlgorithm), otherwise ClientAssertionAlgorithm
// alone, if set. Duplicates are dropped.
func clientAssertionAlgorithms(cfg RegisteredClientConfig) ([]fapi.SignatureAlgorithm, error) {
	if len(cfg.ClientAssertionAlgorithms) == 0 {
		if cfg.ClientAssertionAlgorithm == 0 {
			return nil, nil
		}
		return []fapi.SignatureAlgorithm{cfg.ClientAssertionAlgorithm}, nil
	}
	if cfg.ClientAssertionAlgorithm != 0 && !slices.Contains(cfg.ClientAssertionAlgorithms, cfg.ClientAssertionAlgorithm) {
		return nil, fmt.Errorf("storage: client %q's ClientAssertionAlgorithm is not among its ClientAssertionAlgorithms", cfg.ID)
	}
	var algs []fapi.SignatureAlgorithm
	for _, a := range cfg.ClientAssertionAlgorithms {
		if !slices.Contains(algs, a) {
			algs = append(algs, a)
		}
	}
	return algs, nil
}

// validateClientAuthMethodFields checks the field(s) method requires of
// cfg — split out of NewRegisteredClient purely to keep that function's
// own cognitive complexity manageable. algs is cfg's resolved
// private_key_jwt algorithm list.
func validateClientAuthMethodFields(cfg RegisteredClientConfig, method ClientAuthMethod, algs []fapi.SignatureAlgorithm) error {
	switch method {
	case ClientAuthMethodPrivateKeyJWT:
		return validatePrivateKeyJWTAlgorithms(cfg.ID, algs)
	case ClientAuthMethodSelfSignedTLSClientAuth:
		return requireField(cfg.ID, cfg.ExpectedCertificateThumbprint, "ExpectedCertificateThumbprint", method)
	case ClientAuthMethodTLSClientAuth:
		return requireField(cfg.ID, cfg.ExpectedSubjectDN, "ExpectedSubjectDN", method)
	case ClientAuthMethodTLSClientAuthSANDNS:
		return requireField(cfg.ID, cfg.ExpectedSANDNS, "ExpectedSANDNS", method)
	case ClientAuthMethodTLSClientAuthSANURI:
		return requireField(cfg.ID, cfg.ExpectedSANURI, "ExpectedSANURI", method)
	case ClientAuthMethodTLSClientAuthSANIP:
		return validateSANIPField(cfg)
	case ClientAuthMethodTLSClientAuthSANEmail:
		return requireField(cfg.ID, cfg.ExpectedSANEmail, "ExpectedSANEmail", method)
	case ClientAuthMethodAttestation:
		return validateAttestationFields(cfg)
	default:
		return fmt.Errorf("storage: client %q has an invalid client auth method", cfg.ID)
	}
}

// validatePrivateKeyJWTAlgorithms checks that a private_key_jwt client
// has at least one client assertion algorithm, and only valid ones.
func validatePrivateKeyJWTAlgorithms(id fapi.ClientID, algs []fapi.SignatureAlgorithm) error {
	if len(algs) == 0 {
		return fmt.Errorf("storage: client %q has no valid client assertion algorithm", id)
	}
	for _, a := range algs {
		if !a.IsValid() {
			return fmt.Errorf("storage: client %q has no valid client assertion algorithm", id)
		}
	}
	return nil
}

// requireField checks that value, the field named field, is set, as
// method requires.
func requireField(id fapi.ClientID, value, field string, method ClientAuthMethod) error {
	if value == "" {
		return fmt.Errorf("storage: client %q must set %s for %s", id, field, method)
	}
	return nil
}

// validateSANIPField checks ExpectedSANIP — split out of
// validateClientAuthMethodFields's own ClientAuthMethodTLSClientAuthSANIP
// case purely to keep that function's own cognitive complexity
// manageable (this case alone has two checks, unlike its siblings).
func validateSANIPField(cfg RegisteredClientConfig) error {
	if cfg.ExpectedSANIP == "" {
		return fmt.Errorf("storage: client %q must set ExpectedSANIP for tls_client_auth_san_ip", cfg.ID)
	}
	if net.ParseIP(cfg.ExpectedSANIP) == nil {
		return fmt.Errorf("storage: client %q has an invalid ExpectedSANIP %q", cfg.ID, cfg.ExpectedSANIP)
	}
	return nil
}

// validateAttestationFields checks ExpectedAttesterIssuer and
// ClientAttestationAlgorithm — split out of
// validateClientAuthMethodFields's own ClientAuthMethodAttestation case
// for the same reason validateSANIPField is.
func validateAttestationFields(cfg RegisteredClientConfig) error {
	if cfg.ExpectedAttesterIssuer == "" {
		return fmt.Errorf("storage: client %q must set ExpectedAttesterIssuer for attest_jwt_client_auth", cfg.ID)
	}
	if !cfg.ClientAttestationAlgorithm.IsValid() {
		return fmt.Errorf("storage: client %q has no valid client attestation algorithm", cfg.ID)
	}
	return nil
}

// validateBackchannelTokenDeliveryMode checks the field(s) each
// BackchannelTokenDeliveryMode requires of cfg — split out of
// NewRegisteredClient for the same reason
// validateClientAuthMethodFields is.
func validateBackchannelTokenDeliveryMode(cfg RegisteredClientConfig) error {
	switch cfg.BackchannelTokenDeliveryMode {
	case BackchannelTokenDeliveryModePoll:
		if !cfg.BackchannelClientNotificationEndpoint.IsZero() {
			return fmt.Errorf("storage: client %q must not set BackchannelClientNotificationEndpoint for poll delivery", cfg.ID)
		}
	case BackchannelTokenDeliveryModePing:
		if cfg.BackchannelAuthenticationRequestAlgorithm == 0 {
			return fmt.Errorf("storage: client %q must be permitted to use CIBA (set BackchannelAuthenticationRequestAlgorithm) to use ping delivery", cfg.ID)
		}
		if cfg.BackchannelClientNotificationEndpoint.IsZero() {
			return fmt.Errorf("storage: client %q must set BackchannelClientNotificationEndpoint for ping delivery", cfg.ID)
		}
	default:
		return fmt.Errorf("storage: client %q has an invalid backchannel token delivery mode", cfg.ID)
	}
	return nil
}

// validateIDTokenEncryptionFields checks that
// IDTokenEncryptionKeyManagement/IDTokenEncryptionContentEncryption are
// both set or both empty, and valid when set — split out of
// NewRegisteredClient for the same reason
// validateClientAuthMethodFields is.
func validateIDTokenEncryptionFields(cfg RegisteredClientConfig) error {
	keyMgmtSet := cfg.IDTokenEncryptionKeyManagement != 0
	contentEncSet := cfg.IDTokenEncryptionContentEncryption != 0
	if keyMgmtSet != contentEncSet {
		return fmt.Errorf("storage: client %q must set both IDTokenEncryptionKeyManagement and IDTokenEncryptionContentEncryption, or neither", cfg.ID)
	}
	if !keyMgmtSet {
		return nil
	}
	if !cfg.IDTokenEncryptionKeyManagement.IsValid() {
		return fmt.Errorf("storage: client %q has an invalid ID token encryption key management algorithm", cfg.ID)
	}
	if !cfg.IDTokenEncryptionContentEncryption.IsValid() {
		return fmt.Errorf("storage: client %q has an invalid ID token encryption content encryption algorithm", cfg.ID)
	}
	return nil
}

// validateUserInfoEncryptionFields mirrors
// validateIDTokenEncryptionFields for the UserInfo encryption pair.
func validateUserInfoEncryptionFields(cfg RegisteredClientConfig) error {
	keyMgmtSet := cfg.UserInfoEncryptionKeyManagement != 0
	contentEncSet := cfg.UserInfoEncryptionContentEncryption != 0
	if keyMgmtSet != contentEncSet {
		return fmt.Errorf("storage: client %q must set both UserInfoEncryptionKeyManagement and UserInfoEncryptionContentEncryption, or neither", cfg.ID)
	}
	if !keyMgmtSet {
		return nil
	}
	if !cfg.UserInfoEncryptionKeyManagement.IsValid() {
		return fmt.Errorf("storage: client %q has an invalid UserInfo encryption key management algorithm", cfg.ID)
	}
	if !cfg.UserInfoEncryptionContentEncryption.IsValid() {
		return fmt.Errorf("storage: client %q has an invalid UserInfo encryption content encryption algorithm", cfg.ID)
	}
	return nil
}

// ID returns the client's ID.
func (c RegisteredClient) ID() fapi.ClientID { return c.id }

// AllowsAuthorizationCodeGrant reports whether the client may use the
// authorization code grant: whether it has any registered redirect URI.
// A client registered only for CIBA or client credentials has none.
func (c RegisteredClient) AllowsAuthorizationCodeGrant() bool { return len(c.redirectURIs) > 0 }

// HasRedirectURI reports whether candidate is exactly one of this
// client's registered redirect URIs (RegisteredRedirectURI.Equal
// semantics — exact match, no normalization), but for a native client's
// loopback redirect URI, which matches on any port (RFC 8252 §7.3).
func (c RegisteredClient) HasRedirectURI(candidate string) bool {
	for _, u := range c.redirectURIs {
		if u.Equal(candidate) {
			return true
		}
		// RFC 8252 §7.3, §8.4: a native app's loopback redirect URI
		// matches exactly except for the port, which the app picks when
		// it starts listening.
		if c.applicationType == ApplicationTypeNative && loopbackMatchesAnyPort(string(u), candidate) {
			return true
		}
	}
	return false
}

// ApplicationType returns whether this client is a web application or a
// native app — see RegisteredClientConfig.ApplicationType.
func (c RegisteredClient) ApplicationType() ApplicationType { return c.applicationType }

// checkApplicationType refuses an unknown application type, and a native
// client's redirect URI that isn't one of the forms ApplicationTypeNative
// lists.
func checkApplicationType(cfg RegisteredClientConfig) error {
	switch cfg.ApplicationType {
	case ApplicationTypeWeb:
		return nil
	case ApplicationTypeNative:
	default:
		return fmt.Errorf("storage: client %q has an unknown application type %d", cfg.ID, cfg.ApplicationType)
	}
	for _, uri := range cfg.RedirectURIs {
		parsed, err := fapi.ParseRedirectURL(string(uri), fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme())
		if err != nil {
			return fmt.Errorf("storage: client %q: native redirect URI %q: %w", cfg.ID, uri, err)
		}
		if u := parsed.URL(); u.Scheme == "http" {
			if !isLoopbackLiteral(u.Hostname()) {
				return fmt.Errorf("storage: client %q: native redirect URI %q: loopback redirects use the IP literal 127.0.0.1 or [::1], not a name (RFC 8252 §8.3)", cfg.ID, uri)
			}
			// Matched on any port, but the port written has to be one:
			// an empty, 0 or out-of-range port would never match.
			if !validRegisteredPort(u.Host, u.Port()) {
				return fmt.Errorf("storage: client %q: native redirect URI %q: give a port from 1 to 65535, or none", cfg.ID, uri)
			}
		}
	}
	return nil
}

// validRegisteredPort reports whether a loopback redirect URI's host,
// with port as url.URL.Port gives it, names no port or one from 1 to
// 65535: "127.0.0.1:" names an empty one.
func validRegisteredPort(host, port string) bool {
	if port == "" {
		return !strings.HasSuffix(host, ":")
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// isLoopbackLiteral reports whether host is the IP literal 127.0.0.1 or
// ::1, the loopback addresses RFC 8252 §7.3 names.
func isLoopbackLiteral(host string) bool {
	// Spelled exactly: net.IP.Equal would also take the IPv4-mapped
	// ::ffff:127.0.0.1.
	return host == "127.0.0.1" || host == "::1"
}

// loopbackMatchesAnyPort reports whether candidate is the loopback http
// redirect URI registered, but for its port: the same string once the
// port is taken out of each, and a candidate port, if any, between 1 and
// 65535.
func loopbackMatchesAnyPort(registered, candidate string) bool {
	r, ok := withoutLoopbackPort(registered)
	if !ok {
		return false
	}
	c, ok := withoutLoopbackPort(candidate)
	return ok && r == c
}

// withoutLoopbackPort returns uri without its port, if uri is an http
// URI to a loopback IP literal, spelled exactly "http://".
func withoutLoopbackPort(uri string) (string, bool) {
	const prefix = "http://"
	if !strings.HasPrefix(uri, prefix) {
		return "", false
	}
	u, err := url.Parse(uri)
	if err != nil || u.User != nil || u.Fragment != "" || !strings.HasPrefix(uri[len(prefix):], u.Host) {
		return "", false
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return "", false
	}
	host := u.Host
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		host = strings.TrimSuffix(host, ":"+port)
	}
	return prefix + host + uri[len(prefix)+len(u.Host):], true
}

// ClientAssertionAlgorithm returns the first of the algorithms this
// client's client assertions may be signed with — the only one, unless
// it was registered with ClientAssertionAlgorithms. See
// AllowsClientAssertionAlgorithm.
func (c RegisteredClient) ClientAssertionAlgorithm() fapi.SignatureAlgorithm {
	return c.clientAssertionAlgorithm
}

// ClientAssertionAlgorithms returns every algorithm this client's
// private_key_jwt client assertions may be signed with.
func (c RegisteredClient) ClientAssertionAlgorithms() []fapi.SignatureAlgorithm {
	return slices.Clone(c.clientAssertionAlgorithms)
}

// AllowsClientAssertionAlgorithm reports whether this client's client
// assertions may be signed with alg.
func (c RegisteredClient) AllowsClientAssertionAlgorithm(alg fapi.SignatureAlgorithm) bool {
	return slices.Contains(c.clientAssertionAlgorithms, alg)
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

// ClientAuthMethod returns how this client authenticates itself — the
// first of its methods, and the only one unless it was registered with
// ClientAuthMethods. See AllowsClientAuthMethod.
func (c RegisteredClient) ClientAuthMethod() ClientAuthMethod {
	return c.clientAuthMethod
}

// ClientAuthMethods returns every method this client may authenticate
// with.
func (c RegisteredClient) ClientAuthMethods() []ClientAuthMethod {
	return slices.Clone(c.clientAuthMethods)
}

// AllowsClientAuthMethod reports whether this client may authenticate
// with method.
func (c RegisteredClient) AllowsClientAuthMethod(method ClientAuthMethod) bool {
	return slices.Contains(c.clientAuthMethods, method)
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

// ExpectedAttesterIssuer returns the trusted Attester "iss" value this
// client's Client Attestation JWTs must carry under
// ClientAuthMethodAttestation.
func (c RegisteredClient) ExpectedAttesterIssuer() string {
	return c.expectedAttesterIssuer
}

// ClientAttestationAlgorithm returns the algorithm this client's Client
// Attestation JWTs must be signed with under ClientAuthMethodAttestation.
func (c RegisteredClient) ClientAttestationAlgorithm() fapi.SignatureAlgorithm {
	return c.clientAttestationAlgorithm
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

// AutomaticFederationRegistration reports whether this client was
// resolved via OpenID Federation 1.0 §12.1 Automatic Registration —
// see RegisteredClientConfig.AutomaticFederationRegistration's own doc
// comment.
func (c RegisteredClient) AutomaticFederationRegistration() bool {
	return c.automaticFederationRegistration
}

// Display is how a consent screen can present this client — see
// ClientDisplay.
func (c RegisteredClient) Display() ClientDisplay { return c.display }

// AllowsScope reports whether scope is in this client's registered set
// of allowed scopes.
func (c RegisteredClient) AllowsScope(scope string) bool {
	_, ok := c.allowedScopes[scope]
	return ok
}

// AllowsAuthorizationDetailsType reports whether typ is one of the Rich
// Authorization Request types this client is registered for — see
// RegisteredClientConfig.AuthorizationDetailsTypes.
func (c RegisteredClient) AllowsAuthorizationDetailsType(typ string) bool {
	_, ok := c.authorizationDetailsTypes[typ]
	return ok
}

// AuthorizationDetailsTypes returns the Rich Authorization Request types
// this client is registered for, sorted — see
// RegisteredClientConfig.AuthorizationDetailsTypes.
func (c RegisteredClient) AuthorizationDetailsTypes() []string {
	types := make([]string, 0, len(c.authorizationDetailsTypes))
	for typ := range c.authorizationDetailsTypes {
		types = append(types, typ)
	}
	slices.Sort(types)
	return types
}

// stringSet builds the set values lists for client id, refusing an
// empty entry, which what describes.
func stringSet(id fapi.ClientID, what string, values []string) (map[string]struct{}, error) {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "" {
			return nil, fmt.Errorf("storage: client %q has an empty %s", id, what)
		}
		set[v] = struct{}{}
	}
	return set, nil
}

// ClientRepository resolves a registered client by ID.
type ClientRepository interface {
	ResolveClient(ctx context.Context, id fapi.ClientID) (RegisteredClient, error)
}
