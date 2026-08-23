package fapi

import "testing"

func TestKeyManagementAlgorithmStringRoundTrip(t *testing.T) {
	for _, alg := range []KeyManagementAlgorithm{ECDHESA256KW} {
		s := alg.String()
		if s == "" {
			t.Fatalf("%v.String() = %q, want non-empty", alg, s)
		}
		got, err := ParseKeyManagementAlgorithm(s)
		if err != nil {
			t.Fatalf("ParseKeyManagementAlgorithm(%q) error: %v", s, err)
		}
		if got != alg {
			t.Fatalf("ParseKeyManagementAlgorithm(%q) = %v, want %v", s, got, alg)
		}
		if !alg.IsValid() {
			t.Fatalf("%v.IsValid() = false, want true", alg)
		}
	}
}

func TestParseKeyManagementAlgorithmRejectsUnsupported(t *testing.T) {
	for _, s := range []string{"RSA-OAEP", "RSA-OAEP-256", "dir", "ECDH-ES", "", "ecdh-es+a256kw"} {
		if _, err := ParseKeyManagementAlgorithm(s); err == nil {
			t.Fatalf("ParseKeyManagementAlgorithm(%q) = nil error, want error", s)
		}
	}
}

func TestKeyManagementAlgorithmZeroValueInvalid(t *testing.T) {
	var alg KeyManagementAlgorithm
	if alg.IsValid() {
		t.Fatalf("zero value KeyManagementAlgorithm.IsValid() = true, want false")
	}
	if alg.String() != "" {
		t.Fatalf("zero value KeyManagementAlgorithm.String() = %q, want empty", alg.String())
	}
}

func TestContentEncryptionAlgorithmStringRoundTrip(t *testing.T) {
	for _, alg := range []ContentEncryptionAlgorithm{A256GCM} {
		s := alg.String()
		if s == "" {
			t.Fatalf("%v.String() = %q, want non-empty", alg, s)
		}
		got, err := ParseContentEncryptionAlgorithm(s)
		if err != nil {
			t.Fatalf("ParseContentEncryptionAlgorithm(%q) error: %v", s, err)
		}
		if got != alg {
			t.Fatalf("ParseContentEncryptionAlgorithm(%q) = %v, want %v", s, got, alg)
		}
		if !alg.IsValid() {
			t.Fatalf("%v.IsValid() = false, want true", alg)
		}
	}
}

func TestParseContentEncryptionAlgorithmRejectsUnsupported(t *testing.T) {
	for _, s := range []string{"A128GCM", "A192GCM", "A128CBC-HS256", "A256CBC-HS256", "", "a256gcm"} {
		if _, err := ParseContentEncryptionAlgorithm(s); err == nil {
			t.Fatalf("ParseContentEncryptionAlgorithm(%q) = nil error, want error", s)
		}
	}
}

func TestContentEncryptionAlgorithmZeroValueInvalid(t *testing.T) {
	var alg ContentEncryptionAlgorithm
	if alg.IsValid() {
		t.Fatalf("zero value ContentEncryptionAlgorithm.IsValid() = true, want false")
	}
	if alg.String() != "" {
		t.Fatalf("zero value ContentEncryptionAlgorithm.String() = %q, want empty", alg.String())
	}
}
