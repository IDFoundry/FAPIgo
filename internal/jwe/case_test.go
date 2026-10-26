package jwe

import (
	"strings"
	"testing"
)

func TestParseHeaderRejectsCaseVariantMemberNames(t *testing.T) {
	_, err := parseHeader([]byte(`{"alg":"RSA-OAEP-256","ENC":"A256GCM"}`))
	if err == nil || !strings.Contains(err.Error(), "case-sensitive") {
		t.Fatalf("err = %v, want case-sensitivity rejection", err)
	}
}

func TestParseHeaderRejectsTrailingData(t *testing.T) {
	_, err := parseHeader([]byte(`{"alg":"RSA-OAEP-256","ENC":"A256GCM"} {}`))
	if err == nil || !strings.Contains(err.Error(), "after the top-level") {
		t.Fatalf("err = %v, want trailing-data rejection", err)
	}
}

// This package never decompresses, so a header naming a compression
// algorithm is refused rather than its member ignored.
func TestParseHeaderRejectsZip(t *testing.T) {
	for _, h := range []string{
		`{"alg":"RSA-OAEP-256","enc":"A256GCM","zip":"DEF"}`,
		`{"alg":"RSA-OAEP-256","enc":"A256GCM","zip":null}`,
		`{"alg":"RSA-OAEP-256","enc":"A256GCM","ZIP":"DEF"}`,
	} {
		if _, err := parseHeader([]byte(h)); err == nil {
			t.Errorf("parseHeader(%s) = nil error, want refusal", h)
		}
	}
	if _, err := parseHeader([]byte(`{"alg":"RSA-OAEP-256","enc":"A256GCM"}`)); err != nil {
		t.Fatalf("parseHeader(no zip): %v", err)
	}
}
