package rendertest

import (
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const testSecret = "S3CRET-RAW-VALUE-7f3a"

// stringRedacting is a redacting type of the layout the matrix exists
// to catch: the raw value in a string field, redacted only by String
// and GoString.
type stringRedacting struct{ value string }

func (stringRedacting) String() string   { return "[REDACTED]" }
func (stringRedacting) GoString() string { return "x([REDACTED])" }

// TestLeaksFindsAStringFieldLayout checks the matrix finds what fmt's
// reflection fallback prints of a value redacted only by String: under
// a verb other than v, s, q, x and X, under %w, and in an unexported
// field, also through slog's text handler.
func TestLeaksFindsAStringFieldLayout(t *testing.T) {
	leaks := Leaks(stringRedacting{value: testSecret}, []string{testSecret})
	for _, want := range []struct{ shape, printer string }{
		{"value", "Sprintf %d"},
		{"value", "Errorf %w"},
		{"value", "Sprintf %p"},
		{"unexported field", "Sprintf %v"},
		{"unexported field", "slog text"},
		{"four-deep unexported chain", "Sprint"},
	} {
		if !slices.ContainsFunc(leaks, func(l Leak) bool { return l.Shape == want.shape && l.Printer == want.printer }) {
			t.Errorf("no leak found for %s via %s", want.shape, want.printer)
		}
	}
	for _, l := range leaks {
		if l.Shape == "value" && l.Printer == "Sprintf %v" {
			t.Errorf("String's own rendering counted as a leak: %v", l)
		}
		if l.Shape == "unexported field" && l.Class != Fallback {
			t.Errorf("a leak in an unexported field is classed %q, want %q", l.Class, Fallback)
		}
	}
}

// TestLeaksFindsEncodedForms checks the matrix finds a secret fmt or an
// encoder prints in an encoded form: a byte slice under %v (decimal),
// %x (hex), % X (spaced hex), %o (octal) and %c (characters), and
// encoding/json's base64.
func TestLeaksFindsEncodedForms(t *testing.T) {
	type rawBytes struct{ B []byte }
	leaks := Leaks(rawBytes{B: []byte(testSecret)}, []string{testSecret})
	forms := map[string]bool{}
	for _, l := range leaks {
		forms[l.Form] = true
	}
	for _, want := range []string{"raw", "hex", "HEX", "decimal bytes", "bytes as %X", "bytes as %o", "bytes as %c", "base64"} {
		if !forms[want] {
			t.Errorf("no leak found in form %q; found %v", want, forms)
		}
	}
}

// opaque holds its value behind a pointer and prints nothing of it.
type opaque struct{ p *string }

func (opaque) String() string                  { return "[REDACTED]" }
func (o opaque) Format(f fmt.State, verb rune) { fmt.Fprint(f, o.String()) }

func TestLeaksQuietForAnOpaqueType(t *testing.T) {
	v := testSecret
	if leaks := Leaks(opaque{p: &v}, []string{testSecret}, Quick()); len(leaks) != 0 {
		t.Errorf("an opaque type leaked: %v", leaks[0])
	}
	if leaks := Leaks(opaque{p: &v}, []string{testSecret}, Extra("extra", stringRedacting{value: testSecret}, Fallback)); len(leaks) == 0 {
		t.Error("an Extra operand's leak wasn't found")
	}
}

// jsonCarrier is a type whose JSON encoding, its storage encoding,
// carries its value, while every other rendering redacts it.
type jsonCarrier struct{ p *string }

func (jsonCarrier) String() string                  { return "[REDACTED]" }
func (c jsonCarrier) Format(f fmt.State, verb rune) { fmt.Fprint(f, c.String()) }
func (c jsonCarrier) LogValue() slog.Value          { return slog.StringValue(c.String()) }
func (c jsonCarrier) MarshalJSON() ([]byte, error)  { return []byte(`"` + *c.p + `"`), nil }

func TestAllowAcceptsAStorageEncoding(t *testing.T) {
	v := testSecret
	leaks := Leaks(jsonCarrier{p: &v}, []string{testSecret}, Quick())
	if len(leaks) == 0 {
		t.Fatal("a JSON encoding carrying the value wasn't found")
	}
	for _, l := range leaks {
		if l.Class != Encoding {
			t.Errorf("a JSON encoding's leak is classed %q: %v", l.Class, l)
		}
	}
	if leaks := Leaks(jsonCarrier{p: &v}, []string{testSecret}, Quick(), Allow(Encoding)); len(leaks) != 0 {
		t.Errorf("Allow(Encoding) still reports %v", leaks[0])
	}
}

// wireHandle is a handle as this module's are: its String is its wire
// value, and log/slog logs it, through LogValue, as a placeholder.
type wireHandle struct{ p *string }

func (h wireHandle) String() string     { return *h.p }
func (wireHandle) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// handleGroup and resolvedHandleGroup hold a wireHandle and log a group
// of it: handleGroup puts the handle in the group as it is, to be
// resolved later, resolvedHandleGroup its LogValue.
type (
	handleGroup         struct{ h wireHandle }
	resolvedHandleGroup struct{ h wireHandle }
)

func (handleGroup) Format(f fmt.State, _ rune)         { fmt.Fprint(f, "{h:[REDACTED]}") }
func (g handleGroup) LogValue() slog.Value             { return slog.GroupValue(slog.Any("h", g.h)) }
func (resolvedHandleGroup) Format(f fmt.State, _ rune) { fmt.Fprint(f, "{h:[REDACTED]}") }
func (g resolvedHandleGroup) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("h", g.h.LogValue()))
}

// TestLeaksFindsAnUnresolvedGroupAttribute checks the matrix finds a
// LogValue group holding a value that only log/slog's own handlers
// resolve: slog.Value's String, and a handler printing a resolved value
// with %v, print the handle's wire value. A group holding resolved
// values prints none.
func TestLeaksFindsAnUnresolvedGroupAttribute(t *testing.T) {
	v := testSecret
	leaks := Leaks(handleGroup{h: wireHandle{p: &v}}, []string{testSecret}, Quick())
	for _, printer := range []string{"slog AnyValue.Resolve.String", "slog resolving handler"} {
		if !slices.ContainsFunc(leaks, func(l Leak) bool { return l.Shape == "value" && l.Printer == printer }) {
			t.Errorf("no leak found for the value via %s", printer)
		}
	}
	for _, l := range leaks {
		if l.Printer == "slog text" || l.Printer == "slog JSON" {
			t.Errorf("a log/slog handler, which resolves a group's attributes, printed the handle: %v", l)
		}
	}
	if leaks := Leaks(resolvedHandleGroup{h: wireHandle{p: &v}}, []string{testSecret}, Quick()); len(leaks) != 0 {
		t.Errorf("a group of resolved values printed the handle: %v", leaks[0])
	}
}

// rawForm is a request type as this module's are: its exported field
// holds the raw value, which encoding/json encodes, while its Format and
// LogValue print a placeholder.
type rawForm struct{ Value string }

func (rawForm) Format(f fmt.State, _ rune) { fmt.Fprint(f, "{Value:[REDACTED]}") }
func (rawForm) LogValue() slog.Value {
	return slog.GroupValue(slog.String("Value", "[REDACTED]"))
}

// formGroup and resolvedFormGroup hold a rawForm and log a group of it:
// formGroup puts the form in the group as it is, to be resolved later,
// resolvedFormGroup its LogValue.
type (
	formGroup         struct{ f rawForm }
	resolvedFormGroup struct{ f rawForm }
)

func (formGroup) Format(f fmt.State, _ rune)         { fmt.Fprint(f, "{f:{Value:[REDACTED]}}") }
func (g formGroup) LogValue() slog.Value             { return slog.GroupValue(slog.Any("f", g.f)) }
func (resolvedFormGroup) Format(f fmt.State, _ rune) { fmt.Fprint(f, "{f:{Value:[REDACTED]}}") }
func (g resolvedFormGroup) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("f", g.f.LogValue()))
}

// TestLeaksFindsAGroupAttributeEncodedUnresolved checks the matrix finds
// a LogValue group holding a value whose renderings redact but whose
// encoding/json carries the secret: a handler that walks the group
// without resolving its attributes, and encodes each one's value, logs
// it. A group holding resolved values logs none. What fmt's reflection
// fallback prints of the form's field, from the unexported field
// holding the form, is left out.
func TestLeaksFindsAGroupAttributeEncodedUnresolved(t *testing.T) {
	const printer = "slog group attributes as JSON, unresolved"
	leaks := Leaks(formGroup{f: rawForm{Value: testSecret}}, []string{testSecret}, Quick(), Allow(Fallback))
	for _, shape := range []string{"value", "pointer"} {
		if !slices.ContainsFunc(leaks, func(l Leak) bool { return l.Shape == shape && l.Printer == printer }) {
			t.Errorf("no leak found for the %s via %s", shape, printer)
		}
	}
	for _, l := range leaks {
		if l.Printer != printer {
			t.Errorf("a printer that resolves the group, or formats it, printed the form: %v", l)
		}
	}
	if leaks := Leaks(resolvedFormGroup{f: rawForm{Value: testSecret}}, []string{testSecret}, Quick(), Allow(Fallback)); len(leaks) != 0 {
		t.Errorf("a group of resolved values printed the form: %v", leaks[0])
	}
}

// failingEncoding redacts in its renderings, but its encoding/json fails
// with an error that quotes its value, as an encoder's error may.
type failingEncoding struct{ p *string }

func (failingEncoding) Format(f fmt.State, _ rune) { fmt.Fprint(f, "[REDACTED]") }
func (e failingEncoding) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("can't encode %s", *e.p)
}

// failingEncodingGroup puts a failingEncoding in its group as it is.
type failingEncodingGroup struct{ e failingEncoding }

func (failingEncodingGroup) Format(f fmt.State, _ rune) { fmt.Fprint(f, "{e:[REDACTED]}") }
func (g failingEncodingGroup) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("e", g.e))
}

// TestLeaksFindsAnUnresolvedAttributesEncodingError checks the matrix
// reports the error an unresolved group attribute's encoding gives, as
// log/slog's JSON handler logs one: an error that quotes the value
// carries it.
func TestLeaksFindsAnUnresolvedAttributesEncodingError(t *testing.T) {
	v := testSecret
	leaks := Leaks(failingEncodingGroup{e: failingEncoding{p: &v}}, []string{testSecret}, Quick())
	if !slices.ContainsFunc(leaks, func(l Leak) bool {
		return l.Shape == "value" && l.Printer == "slog group attributes as JSON, unresolved"
	}) {
		t.Errorf("no leak found through the encoding's error: %v", leaks)
	}
}

// fakeReporter records what report says.
type fakeReporter struct{ errors []string }

func (f *fakeReporter) Helper() {}

func (f *fakeReporter) Errorf(format string, args ...any) {
	f.errors = append(f.errors, fmt.Sprintf(format, args...))
}

func TestReportListsTheFirstLeaks(t *testing.T) {
	var r fakeReporter
	leaks := make([]Leak, maxReported+3)
	for i := range leaks {
		leaks[i] = Leak{Secret: testSecret, Shape: "value", Printer: fmt.Sprint(i), Class: Logging, Form: "raw", Output: strings.Repeat("x", 400)}
	}
	report(&r, "T", leaks)
	if len(r.errors) != maxReported+1 || !strings.HasPrefix(r.errors[maxReported], "... and 3 more") {
		t.Fatalf("report said %d things, the last %q; want %d leaks and a count", len(r.errors), r.errors[len(r.errors)-1], maxReported)
	}
	if !strings.Contains(r.errors[0], "T printed a secret") {
		t.Errorf("report said %q", r.errors[0])
	}
	if got := cut(strings.Repeat("x", 400)); len(got) != 303 {
		t.Errorf("cut kept %d bytes, want 300 and an ellipsis", len(got))
	}
}

func TestCheckShadowComparesFieldNames(t *testing.T) {
	type real struct{ A, B string }
	type shadow struct{ A, B int }
	type drifted struct{ B, A string }
	CheckShadow(t, reflect.TypeFor[real](), reflect.TypeFor[shadow]())
	var r fakeReporter
	CheckShadow(&r, reflect.TypeFor[real](), reflect.TypeFor[drifted]())
	if len(r.errors) != 1 {
		t.Errorf("a shadow with its fields in another order passed: %v", r.errors)
	}
}

func TestShortSecretPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a secret too short to search for reliably was accepted")
		}
	}()
	newDetector([]string{"short"})
}

func TestLeaksOfFindsAStringFieldLayout(t *testing.T) {
	leaks := LeaksOf(reflect.ValueOf(stringRedacting{value: testSecret}), []string{testSecret})
	for _, want := range []struct{ shape, printer string }{
		{"value", "Sprintf %d"},
		{"pointer", "Sprintf %d"},
		{"exported field", "Sprintf %d"},
		{"unexported field", "Sprintf %v"},
	} {
		if !slices.ContainsFunc(leaks, func(l Leak) bool { return l.Shape == want.shape && l.Printer == want.printer }) {
			t.Errorf("no leak found for %s via %s", want.shape, want.printer)
		}
	}
}

// TestPrefixCheckFindsEverySecret checks the detector's shortcut, which
// skips a rendering carrying none of its secrets' common prefix, still
// finds secrets sharing one, base64-encoded at each of the three
// alignments.
func TestPrefixCheckFindsEverySecret(t *testing.T) {
	type encoded struct{ A, B, C []byte }
	secrets := []string{"SHAREDPREFIX-1-SECRET-END", "SHAREDPREFIX-2-SECRET-END", "SHAREDPREFIX-3-SECRET-END"}
	v := encoded{A: []byte(secrets[0]), B: []byte("x" + secrets[1]), C: []byte("xy" + secrets[2])}
	found := map[string]bool{}
	for _, l := range Leaks(v, secrets, Quick()) {
		if l.Printer == "encoding/json" && l.Form == "base64" {
			found[l.Secret] = true
		}
	}
	for _, s := range secrets {
		if !found[s] {
			t.Errorf("%s, base64-encoded in JSON, wasn't found", s)
		}
	}
	if d := newDetector(secrets); d.prefix == nil || d.mayCarry("nothing to see", nil) {
		t.Error("the detector has no prefix shortcut, or it doesn't skip a rendering without the prefix")
	}
}

func TestLeaksOfTakesOptions(t *testing.T) {
	v := reflect.ValueOf(stringRedacting{value: testSecret})
	if leaks := LeaksOf(v, []string{testSecret}, Allow(Fallback)); len(leaks) != 0 {
		t.Errorf("Allow(Fallback) still reports %v", leaks[0])
	}
	if commonPrefix(nil) != "" || commonPrefix([]string{"abc", "abd"}) != "ab" {
		t.Error("commonPrefix is wrong")
	}
}
