package server

import "testing"

func TestValidateAdditionalGrantTypes(t *testing.T) {
	const preAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	if err := validateAdditionalGrantTypes([]string{preAuthorizedCode, "urn:example:other"}); err != nil {
		t.Errorf("validateAdditionalGrantTypes(valid) = %v", err)
	}
	for name, grantTypes := range map[string][]string{
		"served by the package": {"authorization_code"},
		"CIBA":                  {CIBAGrantType},
		"password":              {"password"},
		"implicit":              {"implicit"},
		"empty":                 {""},
		"with a space":          {"a b"},
		"with a control":        {"a\x7f"},
		"duplicate":             {preAuthorizedCode, preAuthorizedCode},
	} {
		if err := validateAdditionalGrantTypes(grantTypes); err == nil {
			t.Errorf("validateAdditionalGrantTypes(%s) = nil error, want refusal", name)
		}
	}
}
