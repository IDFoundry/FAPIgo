package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// ClientConfigVersion is the version of the client configuration
// document MarshalClientConfig writes and ParseClientConfig reads: its
// "version" member. A field storage.RegisteredClientConfig gains later
// becomes a new optional member of this version; a change an older
// reader would misread gets a new version.
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
// configuration document (version ClientConfigVersion). It refuses a
// configuration with AutomaticFederationRegistration set: that's
// federation.AutomaticClientRepository's to set, never a stored
// client's.
func MarshalClientConfig(cfg storage.RegisteredClientConfig) ([]byte, error) {
	if cfg.AutomaticFederationRegistration {
		return nil, fmt.Errorf("%w: AutomaticFederationRegistration is set only by federation.AutomaticClientRepository", ErrClientConfig)
	}
	doc := clientConfigV1{
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
// (a misspelt one would otherwise be silently dropped), and a wire value
// its field's type doesn't define, each with an error wrapping
// ErrClientConfig. It doesn't validate the configuration as a whole:
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
	return cfg, nil
}

// decodeClientConfig strictly decodes data as a version 1 document: one
// JSON object, with no unknown member.
func decodeClientConfig(data []byte) (clientConfigV1, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc clientConfigV1
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
