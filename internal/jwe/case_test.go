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
