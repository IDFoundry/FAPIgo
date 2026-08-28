package metadata_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/metadata"
)

func validDocumentJSON(t *testing.T, issuer string) []byte {
	t.Helper()
	doc := metadata.Document{
		Issuer:                             issuer,
		AuthorizationEndpoint:              issuer + "/authorize",
		TokenEndpoint:                      issuer + "/token",
		PushedAuthorizationRequestEndpoint: issuer + "/par",
		JWKSURI:                            issuer + "/jwks",
		IDTokenSigningAlgValuesSupported:   []string{"ES256"},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

func TestParseAndValidateAcceptsValidDocument(t *testing.T) {
	body := validDocumentJSON(t, "https://as.example.com")
	doc, err := metadata.ParseAndValidate(body, "https://as.example.com")
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if doc.AuthorizationEndpoint != "https://as.example.com/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", doc.AuthorizationEndpoint)
	}
	if len(doc.IDTokenSigningAlgValuesSupported) != 1 || doc.IDTokenSigningAlgValuesSupported[0] != "ES256" {
		t.Errorf("IDTokenSigningAlgValuesSupported = %v", doc.IDTokenSigningAlgValuesSupported)
	}
}

func TestParseAndValidateAcceptsIDTokenEncryptionFields(t *testing.T) {
	issuer := "https://as.example.com"
	doc := metadata.Document{
		Issuer:                              issuer,
		AuthorizationEndpoint:               issuer + "/authorize",
		TokenEndpoint:                       issuer + "/token",
		PushedAuthorizationRequestEndpoint:  issuer + "/par",
		JWKSURI:                             issuer + "/jwks",
		IDTokenEncryptionAlgValuesSupported: []string{"RSA-OAEP-256"},
		IDTokenEncryptionEncValuesSupported: []string{"A256GCM"},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := metadata.ParseAndValidate(body, issuer)
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if len(parsed.IDTokenEncryptionAlgValuesSupported) != 1 || parsed.IDTokenEncryptionAlgValuesSupported[0] != "RSA-OAEP-256" {
		t.Errorf("IDTokenEncryptionAlgValuesSupported = %v", parsed.IDTokenEncryptionAlgValuesSupported)
	}
	if len(parsed.IDTokenEncryptionEncValuesSupported) != 1 || parsed.IDTokenEncryptionEncValuesSupported[0] != "A256GCM" {
		t.Errorf("IDTokenEncryptionEncValuesSupported = %v", parsed.IDTokenEncryptionEncValuesSupported)
	}
}

func TestParseAndValidateAcceptsUserinfoEndpoint(t *testing.T) {
	issuer := "https://as.example.com"
	doc := metadata.Document{
		Issuer:                             issuer,
		AuthorizationEndpoint:              issuer + "/authorize",
		TokenEndpoint:                      issuer + "/token",
		PushedAuthorizationRequestEndpoint: issuer + "/par",
		JWKSURI:                            issuer + "/jwks",
		UserinfoEndpoint:                   issuer + "/userinfo",
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := metadata.ParseAndValidate(body, issuer)
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if parsed.UserinfoEndpoint != issuer+"/userinfo" {
		t.Errorf("UserinfoEndpoint = %q", parsed.UserinfoEndpoint)
	}
}

// A document that never mentions userinfo_endpoint at all — a server
// with no UserInfo Endpoint, or one that just doesn't advertise it —
// must parse with the field empty, not fail; it's OPTIONAL per OpenID
// Connect Discovery 1.0 §3.
func TestParseAndValidateOmitsUserinfoEndpointWhenAbsent(t *testing.T) {
	body := validDocumentJSON(t, "https://as.example.com")
	doc, err := metadata.ParseAndValidate(body, "https://as.example.com")
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if doc.UserinfoEndpoint != "" {
		t.Errorf("UserinfoEndpoint = %q, want empty", doc.UserinfoEndpoint)
	}
}

// A document that never mentions encryption at all — the common case —
// must parse with both fields empty, not fail or default to something
// non-empty.
func TestParseAndValidateOmitsIDTokenEncryptionFieldsWhenAbsent(t *testing.T) {
	body := validDocumentJSON(t, "https://as.example.com")
	doc, err := metadata.ParseAndValidate(body, "https://as.example.com")
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if len(doc.IDTokenEncryptionAlgValuesSupported) != 0 {
		t.Errorf("IDTokenEncryptionAlgValuesSupported = %v, want empty", doc.IDTokenEncryptionAlgValuesSupported)
	}
	if len(doc.IDTokenEncryptionEncValuesSupported) != 0 {
		t.Errorf("IDTokenEncryptionEncValuesSupported = %v, want empty", doc.IDTokenEncryptionEncValuesSupported)
	}
}

func TestParseAndValidateRejectsIssuerMismatch(t *testing.T) {
	body := validDocumentJSON(t, "https://as.example.com")
	_, err := metadata.ParseAndValidate(body, "https://attacker.example.com")
	if !errors.Is(err, metadata.ErrIssuerMismatch) {
		t.Fatalf("error = %v, want ErrIssuerMismatch", err)
	}
}

func TestParseAndValidateRejectsMissingRequiredFields(t *testing.T) {
	base := func() metadata.Document {
		return metadata.Document{
			Issuer:                             "https://as.example.com",
			AuthorizationEndpoint:              "https://as.example.com/authorize",
			TokenEndpoint:                      "https://as.example.com/token",
			PushedAuthorizationRequestEndpoint: "https://as.example.com/par",
			JWKSURI:                            "https://as.example.com/jwks",
		}
	}
	cases := map[string]func(*metadata.Document){
		"missing issuer":         func(d *metadata.Document) { d.Issuer = "" },
		"missing token_endpoint": func(d *metadata.Document) { d.TokenEndpoint = "" },
		"missing jwks_uri":       func(d *metadata.Document) { d.JWKSURI = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := base()
			mutate(&doc)
			body, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := metadata.ParseAndValidate(body, "https://as.example.com"); !errors.Is(err, metadata.ErrMissingField) {
				t.Fatalf("ParseAndValidate(%s) error = %v, want ErrMissingField", name, err)
			}
		})
	}
}

// TestParseAndValidateAcceptsMissingAuthorizationAndPAREndpoints covers
// a CIBA-only authorization server's own discovery document — no
// browser flow at all, so neither authorization_endpoint nor
// pushed_authorization_request_endpoint is advertised. This must
// parse successfully with both fields empty, not fail — see
// ParseAndValidate's own doc comment for why these two are no longer
// unconditionally required.
func TestParseAndValidateAcceptsMissingAuthorizationAndPAREndpoints(t *testing.T) {
	doc := metadata.Document{
		Issuer:        "https://as.example.com",
		TokenEndpoint: "https://as.example.com/token",
		JWKSURI:       "https://as.example.com/jwks",
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := metadata.ParseAndValidate(body, "https://as.example.com")
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if parsed.AuthorizationEndpoint != "" {
		t.Errorf("AuthorizationEndpoint = %q, want empty", parsed.AuthorizationEndpoint)
	}
	if parsed.PushedAuthorizationRequestEndpoint != "" {
		t.Errorf("PushedAuthorizationRequestEndpoint = %q, want empty", parsed.PushedAuthorizationRequestEndpoint)
	}
}

func TestParseAndValidateAcceptsMTLSEndpointAliases(t *testing.T) {
	issuer := "https://as.example.com"
	doc := metadata.Document{
		Issuer:                             issuer,
		AuthorizationEndpoint:              issuer + "/authorize",
		TokenEndpoint:                      issuer + "/token",
		PushedAuthorizationRequestEndpoint: issuer + "/par",
		JWKSURI:                            issuer + "/jwks",
		MTLSEndpointAliases: &metadata.MTLSEndpointAliases{
			TokenEndpoint:                      "https://mtls.as.example.com/token",
			PushedAuthorizationRequestEndpoint: "https://mtls.as.example.com/par",
			BackchannelAuthenticationEndpoint:  "https://mtls.as.example.com/backchannel-authenticate",
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := metadata.ParseAndValidate(body, issuer)
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if parsed.MTLSEndpointAliases == nil {
		t.Fatalf("MTLSEndpointAliases = nil, want non-nil")
	}
	if parsed.MTLSEndpointAliases.TokenEndpoint != "https://mtls.as.example.com/token" {
		t.Errorf("MTLSEndpointAliases.TokenEndpoint = %q", parsed.MTLSEndpointAliases.TokenEndpoint)
	}
	if parsed.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint != "https://mtls.as.example.com/par" {
		t.Errorf("MTLSEndpointAliases.PushedAuthorizationRequestEndpoint = %q", parsed.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint)
	}
	if parsed.MTLSEndpointAliases.BackchannelAuthenticationEndpoint != "https://mtls.as.example.com/backchannel-authenticate" {
		t.Errorf("MTLSEndpointAliases.BackchannelAuthenticationEndpoint = %q", parsed.MTLSEndpointAliases.BackchannelAuthenticationEndpoint)
	}
}

// TestParseAndValidateOmitsMTLSEndpointAliasesWhenAbsent covers the
// common case — a server that never advertises
// mtls_endpoint_aliases at all — must parse with the field nil, not
// fail.
func TestParseAndValidateOmitsMTLSEndpointAliasesWhenAbsent(t *testing.T) {
	body := validDocumentJSON(t, "https://as.example.com")
	doc, err := metadata.ParseAndValidate(body, "https://as.example.com")
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if doc.MTLSEndpointAliases != nil {
		t.Errorf("MTLSEndpointAliases = %+v, want nil", doc.MTLSEndpointAliases)
	}
}

func TestParseAndValidateToleratesUnknownFields(t *testing.T) {
	raw := strings.Replace(string(validDocumentJSON(t, "https://as.example.com")), "{", `{"some_vendor_extension":"value",`, 1)
	if _, err := metadata.ParseAndValidate([]byte(raw), "https://as.example.com"); err != nil {
		t.Fatalf("ParseAndValidate(unknown field) = %v, want nil (documents are extensible)", err)
	}
}

func TestParseAndValidateRejectsMalformedJSON(t *testing.T) {
	if _, err := metadata.ParseAndValidate([]byte("not json"), "https://as.example.com"); !errors.Is(err, metadata.ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}

func TestParseAndValidateRejectsOversizedDocument(t *testing.T) {
	huge := make([]byte, 128*1024)
	for i := range huge {
		huge[i] = ' '
	}
	if _, err := metadata.ParseAndValidate(huge, "https://as.example.com"); !errors.Is(err, metadata.ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
}

func TestParseAndValidateRejectsEmptyExpectedIssuer(t *testing.T) {
	body := validDocumentJSON(t, "https://as.example.com")
	if _, err := metadata.ParseAndValidate(body, ""); err == nil {
		t.Fatalf("ParseAndValidate(empty expected issuer) = nil error, want error")
	}
}
