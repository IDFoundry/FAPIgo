package fapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestSecretReveal(t *testing.T) {
	s := NewSecret("super-secret-value")
	if s.Reveal() != "super-secret-value" {
		t.Fatalf("Reveal() = %q, want %q", s.Reveal(), "super-secret-value")
	}
}

func TestSecretStringRedacts(t *testing.T) {
	s := NewSecret("super-secret-value")
	if s.String() != "[REDACTED]" {
		t.Fatalf("String() = %q, want [REDACTED]", s.String())
	}
	if got := fmt.Sprintf("%v", s); got != "[REDACTED]" {
		t.Fatalf("fmt %%v = %q, want [REDACTED]", got)
	}
	if got := fmt.Sprintf("%#v", s); got != "fapi.Secret([REDACTED])" {
		t.Fatalf("fmt %%#v = %q, want fapi.Secret([REDACTED])", got)
	}
}

func TestSecretMarshalTextFails(t *testing.T) {
	s := NewSecret("super-secret-value")
	if _, err := s.MarshalText(); !errors.Is(err, ErrSecretSerialization) {
		t.Fatalf("MarshalText() error = %v, want ErrSecretSerialization", err)
	}

	type wrapper struct {
		Token Secret
	}
	_, err := json.Marshal(wrapper{Token: s})
	if err == nil {
		t.Fatalf("json.Marshal(struct containing Secret) = nil error, want error")
	}
}
