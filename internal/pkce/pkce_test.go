package pkce

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestGenerateVerifierIsValidSyntax(t *testing.T) {
	for i := 0; i < 10; i++ {
		v, err := GenerateVerifier(nil)
		if err != nil {
			t.Fatalf("GenerateVerifier: %v", err)
		}
		if len(v) != 43 {
			t.Fatalf("len(verifier) = %d, want 43", len(v))
		}
		if err := validateVerifierSyntax(v); err != nil {
			t.Fatalf("validateVerifierSyntax(%q): %v", v, err)
		}
	}
}

func TestGenerateVerifierIsRandom(t *testing.T) {
	a, err := GenerateVerifier(nil)
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	b, err := GenerateVerifier(nil)
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	if a == b {
		t.Fatalf("two calls to GenerateVerifier produced the same value")
	}
}

func TestGenerateVerifierUsesSuppliedRandom(t *testing.T) {
	// A zero-filled source should still deterministically flow through
	// to a fixed, syntactically valid verifier.
	src := bytes.NewReader(make([]byte, verifierEntropyBytes))
	v, err := GenerateVerifier(src)
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	if err := validateVerifierSyntax(v); err != nil {
		t.Fatalf("validateVerifierSyntax(%q): %v", v, err)
	}
}

// TestChallengeKnownAnswer checks the S256 transform against the worked
// example from RFC 7636 Appendix B.
func TestChallengeKnownAnswer(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const wantChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	got, err := Challenge(verifier, S256)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if got != wantChallenge {
		t.Fatalf("Challenge(%q) = %q, want %q", verifier, got, wantChallenge)
	}
}

func TestVerifySuccess(t *testing.T) {
	verifier, err := GenerateVerifier(nil)
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	challenge, err := Challenge(verifier, S256)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if err := Verify(challenge, S256, verifier); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsWrongVerifier(t *testing.T) {
	verifier, err := GenerateVerifier(nil)
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	challenge, err := Challenge(verifier, S256)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	other, err := GenerateVerifier(nil)
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}

	err = Verify(challenge, S256, other)
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("Verify(wrong verifier) = %v, want ErrChallengeMismatch", err)
	}
}

func TestVerifyRejectsZeroValueMethod(t *testing.T) {
	// There is no exported way to obtain a Method representing "plain" —
	// ParseMethod refuses to produce one — so the only unsupported
	// Method a caller could pass through is the zero value.
	verifier, err := GenerateVerifier(nil)
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	err = Verify(verifier, 0, verifier)
	if !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("Verify with zero-value Method = %v, want ErrUnsupportedMethod", err)
	}
}

func TestParseMethodDistinguishesPlain(t *testing.T) {
	_, err := ParseMethod("plain")
	if !errors.Is(err, ErrPlainMethodNotPermitted) {
		t.Fatalf("ParseMethod(\"plain\") = %v, want ErrPlainMethodNotPermitted", err)
	}
}

func TestParseMethodRejectsEmptyRatherThanDefaultingToPlain(t *testing.T) {
	_, err := ParseMethod("")
	if err == nil {
		t.Fatalf("ParseMethod(\"\") = nil error, want error")
	}
	if errors.Is(err, ErrPlainMethodNotPermitted) {
		t.Fatalf("ParseMethod(\"\") = ErrPlainMethodNotPermitted, want ErrUnsupportedMethod (must not default to plain)")
	}
}

func TestParseMethodRoundTripsS256(t *testing.T) {
	m, err := ParseMethod("S256")
	if err != nil {
		t.Fatalf("ParseMethod(\"S256\"): %v", err)
	}
	if m != S256 {
		t.Fatalf("ParseMethod(\"S256\") = %v, want S256", m)
	}
	if m.String() != "S256" {
		t.Fatalf("S256.String() = %q, want \"S256\"", m.String())
	}
}

func TestParseMethodRejectsGarbage(t *testing.T) {
	for _, s := range []string{"sha256", "S256 ", "none", "S512"} {
		if _, err := ParseMethod(s); err == nil {
			t.Fatalf("ParseMethod(%q) = nil error, want error", s)
		}
	}
}

func TestValidateVerifierSyntaxRejectsBadLength(t *testing.T) {
	cases := []string{
		"",
		strings.Repeat("a", 42),
		strings.Repeat("a", 129),
	}
	for _, c := range cases {
		if err := validateVerifierSyntax(c); !errors.Is(err, ErrInvalidVerifierSyntax) {
			t.Fatalf("validateVerifierSyntax(len=%d) = %v, want ErrInvalidVerifierSyntax", len(c), err)
		}
	}
}

func TestValidateVerifierSyntaxRejectsBadCharset(t *testing.T) {
	// 43 chars, but with a space and a '+' which are outside the
	// unreserved character set RFC 7636 requires.
	bad := strings.Repeat("a", 41) + " +"
	if err := validateVerifierSyntax(bad); !errors.Is(err, ErrInvalidVerifierSyntax) {
		t.Fatalf("validateVerifierSyntax(%q) = %v, want ErrInvalidVerifierSyntax", bad, err)
	}
}

func TestChallengeRejectsInvalidVerifierSyntax(t *testing.T) {
	if _, err := Challenge("too-short", S256); !errors.Is(err, ErrInvalidVerifierSyntax) {
		t.Fatalf("Challenge(short verifier) = %v, want ErrInvalidVerifierSyntax", err)
	}
}
