package fapi

import "testing"

func TestSignatureAlgorithmStringRoundTrip(t *testing.T) {
	for _, alg := range []SignatureAlgorithm{ES256, PS256, EdDSA} {
		s := alg.String()
		if s == "" {
			t.Fatalf("%v.String() = %q, want non-empty", alg, s)
		}
		got, err := ParseSignatureAlgorithm(s)
		if err != nil {
			t.Fatalf("ParseSignatureAlgorithm(%q) error: %v", s, err)
		}
		if got != alg {
			t.Fatalf("ParseSignatureAlgorithm(%q) = %v, want %v", s, got, alg)
		}
		if !alg.IsValid() {
			t.Fatalf("%v.IsValid() = false, want true", alg)
		}
	}
}

func TestParseSignatureAlgorithmRejectsUnsupported(t *testing.T) {
	for _, s := range []string{"none", "HS256", "RS256", "", "es256"} {
		if _, err := ParseSignatureAlgorithm(s); err == nil {
			t.Fatalf("ParseSignatureAlgorithm(%q) = nil error, want error", s)
		}
	}
}

func TestSignatureAlgorithmZeroValueInvalid(t *testing.T) {
	var alg SignatureAlgorithm
	if alg.IsValid() {
		t.Fatalf("zero value SignatureAlgorithm.IsValid() = true, want false")
	}
	if alg.String() != "" {
		t.Fatalf("zero value SignatureAlgorithm.String() = %q, want empty", alg.String())
	}
}
