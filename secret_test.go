package fapi

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/rendertest"
)

// secretTestValue is a raw value no rendering of its Secret may carry.
const secretTestValue = "S3CRET-RAW-VALUE-7f3a"

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

// TestSecretPrintsNoValue renders a Secret every way a log line can
// reach it — every verb and flag, in every operand position, through
// fmt, log, slog, the templates and the encoders — and finds the value
// in none, raw or encoded.
func TestSecretPrintsNoValue(t *testing.T) {
	s := NewSecret(secretTestValue)
	type embedding struct{ Secret }
	type unexportedEmbedding struct{ e embedding }
	rendertest.Check(t, s, []string{secretTestValue},
		rendertest.Extra("embedded", embedding{s}, rendertest.Logging),
		rendertest.Extra("embedded, in an unexported field", unexportedEmbedding{embedding{s}}, rendertest.Fallback),
	)
}

// stringerFor prints as a Secret's String does, for comparing Format's
// output with what fmt makes of a Stringer.
type stringerFor struct{}

func (stringerFor) String() string { return "[REDACTED]" }

// TestSecretFormatMatchesString pins Format to what fmt printed for a
// Secret before it had one: String's placeholder under v, s, q, x and X,
// GoString's under %#v, with every flag, width and precision applied as
// fmt applies them to a string.
func TestSecretFormatMatchesString(t *testing.T) {
	s := NewSecret(secretTestValue)
	for _, flags := range []string{"", "+", "-", " ", "0", "#", "-12", "12", ".3", "#14.5", "+#"} {
		for _, verb := range "vsqxX" {
			format := "%" + flags + string(verb)
			want := fmt.Sprintf(format, stringerFor{})
			if strings.Contains(flags, "#") && verb == 'v' {
				want = fmt.Sprintf("%"+flags+"s", s.GoString())
			}
			if got := fmt.Sprintf(format, s); got != want {
				t.Errorf("Sprintf(%q) = %q, want %q", format, got, want)
			}
		}
	}
}

func TestSecretFormatOtherVerbs(t *testing.T) {
	s := NewSecret(secretTestValue)
	for verb, want := range map[string]string{
		"d": "%!d(fapi.Secret=[REDACTED])",
		"e": "%!e(fapi.Secret=[REDACTED])",
		"c": "%!c(fapi.Secret=[REDACTED])",
		"t": "%!t(fapi.Secret=[REDACTED])",
	} {
		if got := fmt.Sprintf("%"+verb, s); got != want {
			t.Errorf("Sprintf(%%%s) = %q, want %q", verb, got, want)
		}
	}
}

// TestSecretReflectionPrintsAnAddress pins what fmt prints where it
// calls no method of a Secret: the address of its value, never the
// value.
func TestSecretReflectionPrintsAnAddress(t *testing.T) {
	type holder struct{ tok Secret }
	addr := regexp.MustCompile(`^\{tok:\{_:\[\] v:0x[0-9a-f]+\}\}$`)
	a := holder{NewSecret(secretTestValue)}
	if got := fmt.Sprintf("%+v", a); !addr.MatchString(got) {
		t.Errorf("Sprintf(%%+v) of a Secret in an unexported field = %q, want only its value's address", got)
	}
	wrapFormat := "%w"
	if got := fmt.Errorf(wrapFormat, a.tok).Error(); !strings.HasPrefix(got, "%!w(fapi.Secret={[] 0x") {
		t.Errorf("Errorf(%%w) of a Secret = %q, want fmt's wrong-verb shape with an address", got)
	}
}

func TestSecretLogValue(t *testing.T) {
	s := NewSecret(secretTestValue)
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "token", s)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "token", s)
	if !strings.Contains(text.String(), "token=[REDACTED]") {
		t.Errorf("slog text = %q, want token=[REDACTED]", text.String())
	}
	if !strings.Contains(js.String(), `"token":"[REDACTED]"`) {
		t.Errorf("slog JSON = %q, want \"token\":\"[REDACTED]\"", js.String())
	}
}

// TestSecretEqual pins how Secrets compare: by value through Equal and
// reflect.DeepEqual, never through ==, which doesn't compile.
func TestSecretEqual(t *testing.T) {
	a, b := NewSecret(secretTestValue), NewSecret(strings.Clone(secretTestValue))
	if !a.Equal(b) || !b.Equal(a) || !reflect.DeepEqual(a, b) {
		t.Error("two Secrets of one value compare unequal")
	}
	for _, other := range []Secret{NewSecret(secretTestValue + "x"), NewSecret(strings.ToUpper(secretTestValue)), {}} {
		if a.Equal(other) || other.Equal(a) {
			t.Errorf("Secrets of %q and %q compare equal", a.Reveal(), other.Reveal())
		}
	}
	if !NewSecret("").IsZero() || !(Secret{}).IsZero() || a.IsZero() {
		t.Error(`IsZero isn't true exactly for NewSecret("") and the zero Secret`)
	}
	if !NewSecret("").Equal(Secret{}) || (Secret{}).Reveal() != "" {
		t.Error(`NewSecret("") isn't equal to the zero Secret, or the zero Secret reveals a value`)
	}
	if reflect.TypeFor[Secret]().Comparable() {
		t.Error("Secret is comparable: == would compare pointers, and stop matching equal values")
	}
	if got := b.Reveal(); got != secretTestValue {
		t.Errorf("Reveal() = %q, want %q", got, secretTestValue)
	}
}

// TestSecretComparedThroughAnInterfacePanics pins the failure the
// documentation names for a comparison that compiles: one through an
// interface.
func TestSecretComparedThroughAnInterfacePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("comparing two Secrets through an interface didn't panic")
		}
	}()
	var x, y any = NewSecret(secretTestValue), NewSecret(secretTestValue)
	_ = x == y
}

func TestSecretEncodersFail(t *testing.T) {
	type carrier struct{ Token Secret }
	c := carrier{Token: NewSecret(secretTestValue)}
	if _, err := json.Marshal(c); err == nil {
		t.Error("json.Marshal of a struct holding a Secret succeeded")
	}
	if _, err := xml.Marshal(c); err == nil {
		t.Error("xml.Marshal of a struct holding a Secret succeeded")
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(c); err == nil || strings.Contains(buf.String(), secretTestValue) {
		t.Errorf("gob of a struct holding a Secret: err = %v, output carries the value: %t", err, strings.Contains(buf.String(), secretTestValue))
	}
	var decoded carrier
	if err := json.Unmarshal([]byte(`{"Token":"`+secretTestValue+`"}`), &decoded); err == nil || decoded.Token.Reveal() != "" {
		t.Errorf("json.Unmarshal into a struct holding a Secret: err = %v, value set: %t", err, decoded.Token.Reveal() != "")
	}
}
