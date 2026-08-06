package metadata_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/osanderson/go-fapi/internal/metadata"
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
		"missing issuer":                 func(d *metadata.Document) { d.Issuer = "" },
		"missing authorization_endpoint": func(d *metadata.Document) { d.AuthorizationEndpoint = "" },
		"missing token_endpoint":         func(d *metadata.Document) { d.TokenEndpoint = "" },
		"missing par_endpoint":           func(d *metadata.Document) { d.PushedAuthorizationRequestEndpoint = "" },
		"missing jwks_uri":               func(d *metadata.Document) { d.JWKSURI = "" },
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
