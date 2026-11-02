package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// ClientConfigVersion is the version of the client configuration
// document MarshalClientConfig writes and ParseClientConfig reads: its
// "version" member. A field storage.RegisteredClientConfig gains later
// becomes a new optional member of this version; a change an older
// reader would misread gets a new version. The jwks_uri and jwks
// members (ClientKeyRegistration) are such members, added in sqlstore
// v0.4: a v0.3 reader refuses a document that has them, as it refuses
// any member it doesn't know.
const ClientConfigVersion = 1

// ErrClientConfig is what ParseClientConfig returns, wrapped, for a
// document it can't read, and ClientRepository.ResolveClient for a row
// whose configuration doesn't make a valid client.
var ErrClientConfig = errors.New("sqlstore: invalid client configuration")

// clientConfigV1 is version 1 of the clients table's configuration
// document: storage.RegisteredClientConfig, less its ID (the row's
// client_id column) and AutomaticFederationRegistration (set only by
// federation.AutomaticClientRepository), with each enumeration as its
// wire value (the String of its type, which the type's Parse function
// reads back) and each URL as a string. An omitted member is that
// field's zero value.
type clientConfigV1 struct {
	Version int `json:"version"`

	RedirectURIs    []string `json:"redirect_uris,omitempty"`
	ApplicationType string   `json:"application_type,omitempty"`

	ClientAuthMethod                 string   `json:"client_auth_method,omitempty"`
	ClientAuthMethods                []string `json:"client_auth_methods,omitempty"`
	ClientAssertionAlgorithm         string   `json:"client_assertion_algorithm,omitempty"`
	ClientAssertionAlgorithms        []string `json:"client_assertion_algorithms,omitempty"`
	ExpectedCertificateThumbprint    string   `json:"expected_certificate_thumbprint,omitempty"`
	AdditionalCertificateThumbprints []string `json:"additional_certificate_thumbprints,omitempty"`
	CertificateKeyThumbprints        []string `json:"certificate_key_thumbprints,omitempty"`
	ExpectedSubjectDN                string   `json:"expected_subject_dn,omitempty"`
	ExpectedSANDNS                   string   `json:"expected_san_dns,omitempty"`
	ExpectedSANURI                   string   `json:"expected_san_uri,omitempty"`
	ExpectedSANIP                    string   `json:"expected_san_ip,omitempty"`
	ExpectedSANEmail                 string   `json:"expected_san_email,omitempty"`
	ExpectedAttesterIssuer           string   `json:"expected_attester_issuer,omitempty"`
	ClientAttestationAlgorithm       string   `json:"client_attestation_algorithm,omitempty"`

	RequestObjectAlgorithm string `json:"request_object_algorithm,omitempty"`
	SenderConstrain        string `json:"sender_constrain,omitempty"`

	IDTokenEncryptionKeyManagement      string `json:"id_token_encryption_key_management,omitempty"`
	IDTokenEncryptionContentEncryption  string `json:"id_token_encryption_content_encryption,omitempty"`
	UserInfoEncryptionKeyManagement     string `json:"userinfo_encryption_key_management,omitempty"`
	UserInfoEncryptionContentEncryption string `json:"userinfo_encryption_content_encryption,omitempty"`

	BackchannelAuthenticationRequestAlgorithm string `json:"backchannel_authentication_request_algorithm,omitempty"`
	BackchannelTokenDeliveryMode              string `json:"backchannel_token_delivery_mode,omitempty"`
	BackchannelClientNotificationEndpoint     string `json:"backchannel_client_notification_endpoint,omitempty"`

	AllowedScopes                []string `json:"allowed_scopes,omitempty"`
	AuthorizationDetailsTypes    []string `json:"authorization_details_types,omitempty"`
	AllowedResources             []string `json:"allowed_resources,omitempty"`
	AllowsClientCredentialsGrant bool     `json:"allows_client_credentials_grant,omitempty"`

	Display     *clientDisplayV1 `json:"display,omitempty"`
	SubjectType string           `json:"subject_type,omitempty"`
	Sector      string           `json:"sector,omitempty"`

	// The client's keys (ClientKeyRegistration), which DB.ClientKeys
	// serves: not part of storage.RegisteredClientConfig.
	JWKSURI string          `json:"jwks_uri,omitempty"`
	JWKS    json.RawMessage `json:"jwks,omitempty"`
}

// ClientKeyRegistration is where a client's keys are registered, in
// the clients table's configuration document beside its
// storage.RegisteredClientConfig: its jwks_uri, or its inline JWK Set
// (jwks), as in OAuth 2.0 Dynamic Client Registration (RFC 7591 §2),
// which forbids registering both. DB.ClientKeys serves them to the
// server. A client registered with neither has no keys: one that
// authenticates with a TLS client certificate, say, and signs nothing.
type ClientKeyRegistration struct {
	// JWKSURI is the https URL the client publishes its JWK Set at,
	// fetched (and cached) by DB.ClientKeys' fapihttp.Client.
	JWKSURI fapi.URL

	// JWKS is the client's JWK Set document, a JSON object with a
	// "keys" array of public keys.
	JWKS json.RawMessage
}

// IsZero reports whether reg registers no keys.
func (reg ClientKeyRegistration) IsZero() bool {
	return reg.JWKSURI.IsZero() && len(reg.JWKS) == 0
}

// check refuses reg unless it registers at most one of its members, an
// https JWKSURI or a JWKS that's a JSON object. It doesn't parse the
// keys: checkJWKS does.
func (reg ClientKeyRegistration) check() error {
	if !reg.JWKSURI.IsZero() && len(reg.JWKS) > 0 {
		return errors.New("jwks_uri and jwks are both registered (RFC 7591 §2 allows one)")
	}
	if !reg.JWKSURI.IsZero() {
		if _, err := fapi.ParseEndpointURL(reg.JWKSURI.String()); err != nil {
			return fmt.Errorf("jwks_uri: %w", err)
		}
	}
	if len(reg.JWKS) > 0 {
		if trimmed := bytes.TrimLeft(reg.JWKS, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(reg.JWKS) {
			return errors.New("jwks: not a JSON object")
		}
		// As the document holding it is read: a member twice, or text
		// that doesn't decode losslessly, is refused there.
		if err := checkStrictJSON(reg.JWKS, map[string]any(nil)); err != nil {
			return fmt.Errorf("jwks: %w", err)
		}
	}
	return nil
}

// clientDisplayV1 is storage.ClientDisplay in clientConfigV1.
type clientDisplayV1 struct {
	Name              string `json:"name,omitempty"`
	LogoURI           string `json:"logo_uri,omitempty"`
	PolicyURI         string `json:"policy_uri,omitempty"`
	TermsOfServiceURI string `json:"tos_uri,omitempty"`
}

// enum is a storage or fapi enumeration: its wire value is its String.
type enum interface {
	comparable
	String() string
}

// wire is v's wire value, or "" for its zero value.
func wire[T enum](v T) string {
	var zero T
	if v == zero {
		return ""
	}
	return v.String()
}

// wireAll is the wire value of each of vs, zero values included (a
// list's zero ClientAuthMethod is private_key_jwt, not an omission).
func wireAll[T enum](vs []T) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.String())
	}
	return out
}

// urlString is u's string form, or "" when unset.
func urlString(u fapi.URL) string {
	if u.IsZero() {
		return ""
	}
	return u.String()
}

// MarshalClientConfig encodes cfg, less its ID, as the clients table's
// configuration document (version ClientConfigVersion), registering no
// keys. It refuses a configuration with AutomaticFederationRegistration
// set: that's federation.AutomaticClientRepository's to set, never a
// stored client's.
func MarshalClientConfig(cfg storage.RegisteredClientConfig) ([]byte, error) {
	return MarshalClientConfigWithKeys(cfg, ClientKeyRegistration{})
}

// MarshalClientConfigWithKeys is MarshalClientConfig for a client whose
// keys the document registers too, as its jwks_uri or jwks member,
// for DB.ClientKeys. It refuses a registration with both, a jwks_uri
// that isn't an https URL, and a jwks that isn't a JWK Set with a key
// the server can use. The document keeps jwks compacted.
func MarshalClientConfigWithKeys(cfg storage.RegisteredClientConfig, reg ClientKeyRegistration) ([]byte, error) {
	if cfg.AutomaticFederationRegistration {
		return nil, fmt.Errorf("%w: AutomaticFederationRegistration is set only by federation.AutomaticClientRepository", ErrClientConfig)
	}
	if err := reg.check(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientConfig, err)
	}
	if err := checkJWKS(cfg.ID, reg.JWKS); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientConfig, err)
	}
	doc := clientConfigV1{
		JWKSURI:                                   urlString(reg.JWKSURI),
		JWKS:                                      reg.JWKS,
		Version:                                   ClientConfigVersion,
		ApplicationType:                           wire(cfg.ApplicationType),
		ClientAuthMethod:                          wire(cfg.ClientAuthMethod),
		ClientAuthMethods:                         wireAll(cfg.ClientAuthMethods),
		ClientAssertionAlgorithm:                  wire(cfg.ClientAssertionAlgorithm),
		ClientAssertionAlgorithms:                 wireAll(cfg.ClientAssertionAlgorithms),
		ExpectedCertificateThumbprint:             cfg.ExpectedCertificateThumbprint,
		AdditionalCertificateThumbprints:          cfg.AdditionalCertificateThumbprints,
		CertificateKeyThumbprints:                 cfg.CertificateKeyThumbprints,
		ExpectedSubjectDN:                         cfg.ExpectedSubjectDN,
		ExpectedSANDNS:                            cfg.ExpectedSANDNS,
		ExpectedSANURI:                            cfg.ExpectedSANURI,
		ExpectedSANIP:                             cfg.ExpectedSANIP,
		ExpectedSANEmail:                          cfg.ExpectedSANEmail,
		ExpectedAttesterIssuer:                    cfg.ExpectedAttesterIssuer,
		ClientAttestationAlgorithm:                wire(cfg.ClientAttestationAlgorithm),
		RequestObjectAlgorithm:                    wire(cfg.RequestObjectAlgorithm),
		SenderConstrain:                           wire(cfg.SenderConstrain),
		IDTokenEncryptionKeyManagement:            wire(cfg.IDTokenEncryptionKeyManagement),
		IDTokenEncryptionContentEncryption:        wire(cfg.IDTokenEncryptionContentEncryption),
		UserInfoEncryptionKeyManagement:           wire(cfg.UserInfoEncryptionKeyManagement),
		UserInfoEncryptionContentEncryption:       wire(cfg.UserInfoEncryptionContentEncryption),
		BackchannelAuthenticationRequestAlgorithm: wire(cfg.BackchannelAuthenticationRequestAlgorithm),
		BackchannelTokenDeliveryMode:              wire(cfg.BackchannelTokenDeliveryMode),
		BackchannelClientNotificationEndpoint:     urlString(cfg.BackchannelClientNotificationEndpoint),
		AllowedScopes:                             cfg.AllowedScopes,
		AuthorizationDetailsTypes:                 cfg.AuthorizationDetailsTypes,
		AllowedResources:                          cfg.AllowedResources,
		AllowsClientCredentialsGrant:              cfg.AllowsClientCredentialsGrant,
		SubjectType:                               wire(cfg.SubjectType),
		Sector:                                    cfg.Sector,
	}
	for _, uri := range cfg.RedirectURIs {
		doc.RedirectURIs = append(doc.RedirectURIs, string(uri))
	}
	if !cfg.Display.IsZero() {
		doc.Display = &clientDisplayV1{
			Name:              cfg.Display.Name,
			LogoURI:           urlString(cfg.Display.LogoURI),
			PolicyURI:         urlString(cfg.Display.PolicyURI),
			TermsOfServiceURI: urlString(cfg.Display.TermsOfServiceURI),
		}
	}
	return json.Marshal(doc)
}

// configParser parses a document's members, keeping the first error.
type configParser struct{ err error }

// one parses member name's wire value s with parse: the zero value
// when s is empty.
func one[T any](p *configParser, name, s string, parse func(string) (T, error)) T {
	var zero T
	if s == "" || p.err != nil {
		return zero
	}
	v, err := parse(s)
	if err != nil {
		p.err = fmt.Errorf("%s: %w", name, err)
		return zero
	}
	return v
}

// all is one for each of member name's values.
func all[T any](p *configParser, name string, ss []string, parse func(string) (T, error)) []T {
	var out []T
	for _, s := range ss {
		if s == "" && p.err == nil {
			p.err = fmt.Errorf("%s: empty value", name)
		}
		out = append(out, one(p, name, s, parse))
	}
	return out
}

// endpointURL parses an https URL member.
func endpointURL(s string) (fapi.URL, error) { return fapi.ParseEndpointURL(s) }

// ParseClientConfig decodes data, a clients table configuration
// document, as client id's storage.RegisteredClientConfig. It refuses
// any other version than ClientConfigVersion, a member it doesn't know
// (a misspelt one would otherwise be silently dropped), a member given
// twice in one object or spelt in another case (encoding/json would keep
// the last, or read it as the member it case-folds to, where a reviewer
// or another JSON parser may read the first), text that isn't valid
// UTF-8 or escapes an unpaired surrogate (which would read back as
// U+FFFD), and a wire value its field's type doesn't define, each with
// an error wrapping ErrClientConfig. It doesn't validate the configuration as a whole:
// storage.NewRegisteredClient does.
func ParseClientConfig(id fapi.ClientID, data []byte) (storage.RegisteredClientConfig, error) {
	doc, err := decodeClientConfig(data)
	if err != nil {
		return storage.RegisteredClientConfig{}, fmt.Errorf("%w: %w", ErrClientConfig, err)
	}
	p := &configParser{}
	cfg := storage.RegisteredClientConfig{
		ID:                                        id,
		ApplicationType:                           one(p, "application_type", doc.ApplicationType, storage.ParseApplicationType),
		ClientAuthMethod:                          one(p, "client_auth_method", doc.ClientAuthMethod, storage.ParseClientAuthMethod),
		ClientAuthMethods:                         all(p, "client_auth_methods", doc.ClientAuthMethods, storage.ParseClientAuthMethod),
		ClientAssertionAlgorithm:                  one(p, "client_assertion_algorithm", doc.ClientAssertionAlgorithm, fapi.ParseSignatureAlgorithm),
		ClientAssertionAlgorithms:                 all(p, "client_assertion_algorithms", doc.ClientAssertionAlgorithms, fapi.ParseSignatureAlgorithm),
		ExpectedCertificateThumbprint:             doc.ExpectedCertificateThumbprint,
		AdditionalCertificateThumbprints:          doc.AdditionalCertificateThumbprints,
		CertificateKeyThumbprints:                 doc.CertificateKeyThumbprints,
		ExpectedSubjectDN:                         doc.ExpectedSubjectDN,
		ExpectedSANDNS:                            doc.ExpectedSANDNS,
		ExpectedSANURI:                            doc.ExpectedSANURI,
		ExpectedSANIP:                             doc.ExpectedSANIP,
		ExpectedSANEmail:                          doc.ExpectedSANEmail,
		ExpectedAttesterIssuer:                    doc.ExpectedAttesterIssuer,
		ClientAttestationAlgorithm:                one(p, "client_attestation_algorithm", doc.ClientAttestationAlgorithm, fapi.ParseSignatureAlgorithm),
		RequestObjectAlgorithm:                    one(p, "request_object_algorithm", doc.RequestObjectAlgorithm, fapi.ParseSignatureAlgorithm),
		SenderConstrain:                           one(p, "sender_constrain", doc.SenderConstrain, storage.ParseSenderConstrain),
		IDTokenEncryptionKeyManagement:            one(p, "id_token_encryption_key_management", doc.IDTokenEncryptionKeyManagement, fapi.ParseKeyManagementAlgorithm),
		IDTokenEncryptionContentEncryption:        one(p, "id_token_encryption_content_encryption", doc.IDTokenEncryptionContentEncryption, fapi.ParseContentEncryptionAlgorithm),
		UserInfoEncryptionKeyManagement:           one(p, "userinfo_encryption_key_management", doc.UserInfoEncryptionKeyManagement, fapi.ParseKeyManagementAlgorithm),
		UserInfoEncryptionContentEncryption:       one(p, "userinfo_encryption_content_encryption", doc.UserInfoEncryptionContentEncryption, fapi.ParseContentEncryptionAlgorithm),
		BackchannelAuthenticationRequestAlgorithm: one(p, "backchannel_authentication_request_algorithm", doc.BackchannelAuthenticationRequestAlgorithm, fapi.ParseSignatureAlgorithm),
		BackchannelTokenDeliveryMode:              one(p, "backchannel_token_delivery_mode", doc.BackchannelTokenDeliveryMode, storage.ParseBackchannelTokenDeliveryMode),
		BackchannelClientNotificationEndpoint:     one(p, "backchannel_client_notification_endpoint", doc.BackchannelClientNotificationEndpoint, endpointURL),
		AllowedScopes:                             doc.AllowedScopes,
		AuthorizationDetailsTypes:                 doc.AuthorizationDetailsTypes,
		AllowedResources:                          doc.AllowedResources,
		AllowsClientCredentialsGrant:              doc.AllowsClientCredentialsGrant,
		SubjectType:                               one(p, "subject_type", doc.SubjectType, fapi.ParseSubjectType),
		Sector:                                    doc.Sector,
	}
	for _, uri := range doc.RedirectURIs {
		cfg.RedirectURIs = append(cfg.RedirectURIs, fapi.RegisteredRedirectURI(uri))
	}
	if doc.Display != nil {
		cfg.Display = storage.ClientDisplay{
			Name:              doc.Display.Name,
			LogoURI:           one(p, "display.logo_uri", doc.Display.LogoURI, endpointURL),
			PolicyURI:         one(p, "display.policy_uri", doc.Display.PolicyURI, endpointURL),
			TermsOfServiceURI: one(p, "display.tos_uri", doc.Display.TermsOfServiceURI, endpointURL),
		}
	}
	if p.err != nil {
		return storage.RegisteredClientConfig{}, fmt.Errorf("%w: %w", ErrClientConfig, p.err)
	}
	if _, err := docKeys(doc); err != nil {
		return storage.RegisteredClientConfig{}, fmt.Errorf("%w: %w", ErrClientConfig, err)
	}
	return cfg, nil
}

// ParseClientKeys decodes data, a clients table configuration document,
// as ParseClientConfig does, and returns the keys it registers: its
// jwks_uri or jwks member, or neither. It refuses what ParseClientConfig
// refuses, a document registering both, a jwks_uri that isn't an https
// URL, and a jwks that isn't a JSON object, each with an error wrapping
// ErrClientConfig. It doesn't parse the keys themselves:
// DB.ClientKeys does, as MarshalClientConfigWithKeys and
// ClientRepository.PutWithKeys do before writing them.
func ParseClientKeys(data []byte) (ClientKeyRegistration, error) {
	doc, err := decodeClientConfig(data)
	if err != nil {
		return ClientKeyRegistration{}, fmt.Errorf("%w: %w", ErrClientConfig, err)
	}
	reg, err := docKeys(doc)
	if err != nil {
		return ClientKeyRegistration{}, fmt.Errorf("%w: %w", ErrClientConfig, err)
	}
	return reg, nil
}

// docKeys is the ClientKeyRegistration in doc, checked.
func docKeys(doc clientConfigV1) (ClientKeyRegistration, error) {
	reg := ClientKeyRegistration{JWKS: doc.JWKS}
	if doc.JWKSURI != "" {
		u, err := fapi.ParseEndpointURL(doc.JWKSURI)
		if err != nil {
			return ClientKeyRegistration{}, fmt.Errorf("jwks_uri: %w", err)
		}
		reg.JWKSURI = u
	}
	if err := reg.check(); err != nil {
		return ClientKeyRegistration{}, err
	}
	return reg, nil
}

// checkJWKS refuses inline, client id's JWK Set, unless it parses as
// DB.ClientKeys parses it, with at least one key the server can use.
// Empty inline registers no JWK Set, which it accepts.
func checkJWKS(id fapi.ClientID, inline json.RawMessage) error {
	if len(inline) == 0 {
		return nil
	}
	lookup := func(context.Context, fapi.ClientID) (fapi.URL, []byte, error) { return fapi.URL{}, inline, nil }
	source, err := keys.NewClientJWKSSource(nil, lookup)
	if err != nil {
		return err
	}
	// Any algorithm: resolving parses the whole set, and an empty match
	// isn't an error.
	if _, err := source.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: id, Algorithm: fapi.ES256}); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	return nil
}

// decodeClientConfig strictly decodes data as a version 1 document: one
// JSON object, with no unknown, duplicate or case-variant member, that
// decodes losslessly (checkStrictJSON).
func decodeClientConfig(data []byte) (clientConfigV1, error) {
	var doc clientConfigV1
	if err := checkStrictJSON(data, doc); err != nil {
		return clientConfigV1{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return clientConfigV1{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return clientConfigV1{}, errors.New("data after the document")
	}
	if doc.Version != ClientConfigVersion {
		return clientConfigV1{}, fmt.Errorf("version %d, want %d", doc.Version, ClientConfigVersion)
	}
	return doc, nil
}
