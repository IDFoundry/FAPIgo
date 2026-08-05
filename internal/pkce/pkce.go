package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
)

// verifierEntropyBytes is the number of random octets used to build a
// code_verifier. Base64url-encoded (no padding), 32 octets produce
// exactly 43 characters — RFC 7636 Appendix B's own example, and the
// minimum length RFC 7636 §4.1 permits, at 256 bits of entropy.
const verifierEntropyBytes = 32

const (
	minVerifierLength = 43
	maxVerifierLength = 128
)

// GenerateVerifier produces a new, random code_verifier. If random is
// nil, crypto/rand.Reader is used.
func GenerateVerifier(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, verifierEntropyBytes)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", fmt.Errorf("pkce: generate verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Challenge derives the code_challenge for verifier under method.
func Challenge(verifier string, method Method) (string, error) {
	if err := validateVerifierSyntax(verifier); err != nil {
		return "", err
	}
	switch method {
	case S256:
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", ErrUnsupportedMethod
	}
}

// Verify checks that verifier, transformed under method, reproduces
// challenge — the code_challenge recorded when the authorization request
// was created. Callers must supply the method recorded alongside the
// challenge, not one read from the verifier's own request; Verify does
// not infer a method.
func Verify(challenge string, method Method, verifier string) error {
	computed, err := Challenge(verifier, method)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrChallengeMismatch
	}
	return nil
}

// validateVerifierSyntax checks verifier against RFC 7636 §4.1: 43-128
// characters, drawn only from the unreserved character set
// ALPHA / DIGIT / "-" / "." / "_" / "~".
func validateVerifierSyntax(verifier string) error {
	if len(verifier) < minVerifierLength || len(verifier) > maxVerifierLength {
		return ErrInvalidVerifierSyntax
	}
	for i := 0; i < len(verifier); i++ {
		if !isUnreservedChar(verifier[i]) {
			return ErrInvalidVerifierSyntax
		}
	}
	return nil
}

func isUnreservedChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	default:
		return false
	}
}
