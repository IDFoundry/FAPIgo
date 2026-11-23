// Package rendertest renders a value every way a log line, an error
// message or a debug dump can reach it, and reports each rendering that
// carries one of the value's secrets, raw or encoded: the matrix the
// tests of this module's redacting types share.
//
// A value is rendered in every operand position fmt treats differently
// (the value itself, a pointer to it, an exported or unexported field,
// a slice, array, map value or map key, an interface field, a pointer
// field, a four-deep unexported chain, an error type that formats it,
// and whatever the caller adds, such as the value embedded in a struct
// of its own), through fmt's verbs and flags (every ASCII letter and
// "@ ~ ! %" under thirteen flag sets, and indexed, star, extra and
// missing arguments), Sprint, Sprintln, Errorf with %w and %v, the log
// package, log/slog's text and JSON handlers (attributes, groups,
// nested groups, With, WithGroup and an error attribute), a slog.Value
// resolved and then printed with %v, as a handler of a deployment's own
// may print one, a LogValue group's attributes encoded with
// encoding/json unresolved, as a handler that walks a group without
// resolving it may log them, text/template and html/template, and
// encoding/json, encoding/xml and encoding/gob when they succeed. Every
// format is built at run time, so vet can't refuse it.
//
// A secret counts as printed when a rendering carries it raw, in
// lower- or upper-case hex (contiguous, spaced, or 0x-prefixed per
// byte), as the decimal, octal, binary, character or U+ forms fmt
// prints a byte slice in, or in base64 (standard or URL alphabet, at
// any alignment).
package rendertest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	htmltemplate "html/template"
	"io"
	"log"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"
	"text/template"
)

// Class says how a rendering reached a value.
type Class string

const (
	// Logging is a rendering through a value's own methods: fmt's v, s,
	// q, x and X verbs on the value or an exported field holding it,
	// Sprint, Sprintln, the log package, log/slog and the templates.
	Logging Class = "log"

	// Fallback is a rendering through fmt's reflection fallback, which
	// calls no method of the value: any other verb, %p, %w on a value
	// that isn't an error, or the value in an unexported field.
	Fallback Class = "fallback"

	// Encoding is encoding/json, encoding/xml or encoding/gob, which
	// carry a value's exported fields by design, and log/slog's JSON
	// handler for a value inside another (a struct, slice or map), which
	// it encodes with encoding/json: it resolves a LogValuer only at the
	// top of an attribute.
	Encoding Class = "encoding"
)

// Leak is one rendering that carried a secret.
type Leak struct {
	Secret  string // the secret found
	Shape   string // where the value sat: "value", "unexported field", ...
	Printer string // how it was rendered: "Sprintf %+v", "slog text", ...
	Class   Class
	Form    string // how the secret appeared: "raw", "hex", "decimal", ...
	Output  string // the rendering, cut to a readable length
}

// String describes l for a test failure.
func (l Leak) String() string {
	return fmt.Sprintf("%s in %s via %s (%s, %s): %s", l.Form, l.Shape, l.Printer, l.Class, l.Secret, l.Output)
}

// Option changes what a matrix renders.
type Option func(*config)

type config struct {
	quick   bool
	allowed map[Class]bool
	extra   []operand
}

// Quick renders under fewer verbs and flags (v s q x X d, %p and %w,
// with no flag, "+" and "#"), for a type whose fields are themselves
// tested in full, or for a sweep over many types.
func Quick() Option { return func(c *config) { c.quick = true } }

// Allow accepts renderings of the given classes that carry a secret: the
// Encoding class for a type whose JSON encoding is its storage encoding
// and carries every value by design, and the Fallback class too for an
// input type whose exported fields hold the raw values, which fmt's
// reflection fallback prints as it prints any exported field.
func Allow(classes ...Class) Option {
	return func(c *config) {
		if c.allowed == nil {
			c.allowed = map[Class]bool{}
		}
		for _, class := range classes {
			c.allowed[class] = true
		}
	}
}

// Extra adds an operand shape, such as the value embedded in a struct,
// which a generic type can't express.
func Extra(shape string, value any, class Class) Option {
	return func(c *config) { c.extra = append(c.extra, operand{shape: shape, value: value, class: class}) }
}

// Check fails t for every rendering of v that carries one of secrets,
// listing the first few.
func Check[T any](t testing.TB, v T, secrets []string, opts ...Option) {
	t.Helper()
	report(t, fmt.Sprintf("%T", v), Leaks(v, secrets, opts...))
}

// CheckShadow fails t unless shadow, the struct a redacting type prints
// in its place, has typ's field names in typ's order: a field added to
// a type and not to its shadow would never print, and a shadow that
// drifted would print fields under the wrong names.
func CheckShadow(t Reporter, typ, shadow reflect.Type) {
	t.Helper()
	if got, want := fieldNames(shadow), fieldNames(typ); !slices.Equal(got, want) {
		t.Errorf("%v shadows %v with fields %v, want %v", shadow, typ, got, want)
	}
}

func fieldNames(t reflect.Type) []string {
	names := make([]string, t.NumField())
	for i := range t.NumField() {
		names[i] = t.Field(i).Name
	}
	return names
}

// Reporter is the part of testing.TB this package fails a test through.
type Reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// report fails t for each of leaks, a rendering of a value of type
// typeName, listing the first few.
func report(t Reporter, typeName string, leaks []Leak) {
	t.Helper()
	for i, l := range leaks {
		if i == maxReported {
			t.Errorf("... and %d more", len(leaks)-maxReported)
			return
		}
		t.Errorf("%s printed a secret: %v", typeName, l)
	}
}

// maxReported bounds how many leaks Check lists.
const maxReported = 8

// Leaks renders v in every operand shape through every printer and
// returns each rendering that carries one of secrets. Each secret must
// be at least 12 bytes, so no rendering carries it by chance, and
// secrets must differ from one another more than two bytes from either
// end: a base64 form of a secret can lose up to two bytes at each end
// to the bytes around it.
func Leaks[T any](v T, secrets []string, opts ...Option) []Leak {
	var c config
	for _, opt := range opts {
		opt(&c)
	}
	m := matrix{detect: newDetector(secrets), formats: formats(c.quick), allowed: c.allowed}
	for _, op := range append(operands(v), c.extra...) {
		m.render(op)
	}
	return m.leaks
}

// LeaksOf is Leaks for a value whose type is known only at run time, in
// the positions a sweep over many types needs: the value itself, a
// pointer to it, an exported field and an unexported one, under Quick's
// verbs and flags.
func LeaksOf(v reflect.Value, secrets []string, opts ...Option) []Leak {
	c := config{quick: true}
	for _, opt := range opts {
		opt(&c)
	}
	m := matrix{detect: newDetector(secrets), formats: formats(true), allowed: c.allowed}
	for _, op := range append(operandsOf(v), c.extra...) {
		m.render(op)
	}
	return m.leaks
}

// operandsOf is v in the positions LeaksOf renders it in.
func operandsOf(v reflect.Value) []operand {
	p := reflect.New(v.Type())
	p.Elem().Set(v)
	holder := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "V", Type: v.Type()}})).Elem()
	holder.Field(0).Set(v)
	return []operand{
		{shape: "value", value: v.Interface(), slogResolves: true},
		{shape: "pointer", value: p.Interface(), slogResolves: true},
		{shape: "exported field", value: holder.Interface()},
		{shape: "unexported field", value: unexportedInterfaceField{v: v.Interface()}, class: Fallback},
	}
}

// matrix renders operands and collects what they leak.
type matrix struct {
	detect  detector
	formats []format
	allowed map[Class]bool
	leaks   []Leak
}

// format is one Sprintf format, whether fmt calls the operand's
// methods under it, and whether it is %#v, under which fmt calls a
// GoString or Format method but not String or Error.
type format struct {
	text    string
	methods bool
	sharpV  bool
}

// verbs is every verb rune the full matrix tries.
const verbs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@~!%"

// flagSets are the flags, widths and precisions tried with each verb.
var flagSets = []string{"", "+", "-", "#", " ", "0", "+#", "#0", "- ", "8", "-8", ".2", "#8.3"}

func formats(quick bool) []format {
	vs, fs := verbs, flagSets
	if quick {
		vs, fs = "vsqxXdpw", []string{"", "+", "#"}
	}
	out := make([]format, 0, len(vs)*len(fs))
	for _, flags := range fs {
		for _, verb := range vs {
			// %% takes no operand, so fmt prints it as an extra argument,
			// under %v: through its methods.
			out = append(out, format{
				text:    "%" + flags + string(verb),
				methods: strings.ContainsRune("vsqxX%", verb),
				sharpV:  verb == 'v' && strings.ContainsRune(flags, '#'),
			})
		}
	}
	return out
}

func (m *matrix) render(op operand) {
	for _, f := range m.formats {
		m.check(op, "Sprintf "+f.text, op.classUnder(f.methods && (!f.sharpV || !op.viaError)), fmt.Sprintf(f.text, op.value))
	}
	_, isError := op.value.(error)
	for _, p := range printers {
		m.check(op, p.name, op.classUnder(p.methods || p.wrapsErrors && isError), p.render(op.value))
	}
	logged := slogRenderings(op.value)
	m.check(op, "slog text", op.classUnder(true), logged.text)
	// log/slog's JSON handler encodes a value with encoding/json unless
	// it resolves the value itself: a LogValuer at the top of an
	// attribute, or an error, which it logs by its text.
	_, isLogValuer := op.value.(slog.LogValuer)
	jsonClass := op.classUnder(true)
	if (!op.slogResolves || !isLogValuer) && !isError {
		jsonClass = Encoding
	}
	m.check(op, "slog JSON", jsonClass, logged.json)
	m.check(op, "slog error attribute", op.classUnder(true), logged.errorAttrs)
	m.check(op, "slog resolving handler", op.classUnder(true), logged.resolving)
	for _, e := range encoders {
		if out, err := e.encode(op.value); err == nil {
			m.check(op, e.name, Encoding, string(out))
		}
	}
}

func (m *matrix) check(op operand, printer string, class Class, out string) {
	if m.allowed[class] {
		return
	}
	for _, found := range m.detect.find(out) {
		m.leaks = append(m.leaks, Leak{
			Secret: found.secret, Shape: op.shape, Printer: printer, Class: class,
			Form: found.form, Output: cut(out),
		})
	}
}

// cut shortens out to a readable length for a failure message.
func cut(out string) string {
	const limit = 300
	if len(out) <= limit {
		return out
	}
	return out[:limit] + "..."
}

// printer renders an operand some way other than a Sprintf format:
// through the operand's methods (methods), or, for an error operand only,
// through its Error (wrapsErrors).
type printer struct {
	name        string
	methods     bool
	wrapsErrors bool
	render      func(v any) string
}

// The formats below are variables, not constants, so vet doesn't check
// them against an operand whose type it can't know.
var (
	indexedFormat = "%[1]v"
	starFormat    = "%*v"
	extraFormat   = "%d"
	missingFormat = "%v %v"
	wrapFormat    = "%w"
	valueFormat   = "%v"
	plusFormat    = "%+v"
)

var printers = []printer{
	{"Sprint", true, false, func(v any) string { return fmt.Sprint(v) }},
	{"Sprintln", true, false, func(v any) string { return fmt.Sprintln(v) }},
	{"Sprintf %[1]v", true, false, func(v any) string { return fmt.Sprintf(indexedFormat, v) }},
	{"Sprintf %*v", true, false, func(v any) string { return fmt.Sprintf(starFormat, 12, v) }},
	{"Sprintf EXTRA", true, false, func(v any) string { return fmt.Sprintf(extraFormat, 1, v) }},
	{"Sprintf MISSING", true, false, func(v any) string { return fmt.Sprintf(missingFormat, v) }},
	{"Errorf %w", false, true, func(v any) string { return fmt.Errorf(wrapFormat, v).Error() }},
	{"Errorf %v", true, false, func(v any) string { return fmt.Errorf(valueFormat, v).Error() }},
	{"log", true, false, logRendering},
	// A value slog resolves, printed by its String, as a handler of a
	// deployment's own may print one: the attributes of a LogValue's
	// group print as they are, unresolved, which only log/slog's own
	// handlers resolve.
	{"slog AnyValue.Resolve.String", true, false, func(v any) string { return slog.AnyValue(v).Resolve().String() }},
	// A LogValue's group as a handler of a deployment's own may log it
	// when it walks the group without resolving its attributes: a value
	// left in the group for the handler to resolve prints as
	// encoding/json encodes it, which for a request type is its raw
	// fields.
	{"slog group attributes as JSON, unresolved", true, false, unresolvedGroupRendering},
	{"text/template", true, false, textTemplateRendering},
	{"text/template printf %d", false, false, textTemplateBadVerbRendering},
	{"html/template", true, false, htmlTemplateRendering},
}

func logRendering(v any) string {
	var buf bytes.Buffer
	l := log.New(&buf, "", 0)
	l.Printf(valueFormat, v)
	l.Printf(plusFormat, v)
	l.Println(v)
	return buf.String()
}

// unresolvedGroupRendering is v's LogValue, when it is a group, as a
// handler that walks a group without resolving its attributes may log
// it: each attribute's value, in the groups it holds too, encoded with
// encoding/json as it stands, or the error encoding it gave. It is ""
// for a v that doesn't log as a group.
func unresolvedGroupRendering(v any) string {
	var b strings.Builder
	writeUnresolvedGroup(&b, slog.AnyValue(v).Resolve())
	return b.String()
}

func writeUnresolvedGroup(b *strings.Builder, v slog.Value) {
	if v.Kind() != slog.KindGroup {
		return
	}
	for _, a := range v.Group() {
		if a.Value.Kind() == slog.KindGroup {
			writeUnresolvedGroup(b, a.Value)
			continue
		}
		out, err := json.Marshal(a.Value.Any())
		if err != nil {
			out = []byte(err.Error())
		}
		_, _ = fmt.Fprintf(b, " %s=%s", a.Key, out)
	}
}

var (
	textTemplate        = template.Must(template.New("t").Parse(`{{.}} {{printf "%v" .}} {{printf "%+v" .}} {{printf "%x" .}}`))
	textTemplateBadVerb = template.Must(template.New("d").Parse(`{{printf "%d" .}}`))
	htmlTemplate        = htmltemplate.Must(htmltemplate.New("h").Parse(`<p>{{.}}</p><input value="{{.}}">`))
)

func textTemplateRendering(v any) string { return execute(textTemplate, v) }

func textTemplateBadVerbRendering(v any) string { return execute(textTemplateBadVerb, v) }

func execute(t *template.Template, v any) string {
	var buf bytes.Buffer
	_ = t.Execute(&buf, v)
	return buf.String()
}

func htmlTemplateRendering(v any) string {
	var buf bytes.Buffer
	_ = htmlTemplate.Execute(&buf, v)
	return buf.String()
}

// The message, key and group slogRenderings logs v with.
const (
	logMessage = "m"
	logKey     = "k"
	logGroup   = "g"
)

// slogOutput is what slogRenderings logged, by handler.
type slogOutput struct {
	text, json, errorAttrs, resolving string
}

// slogRenderings logs v through a text and a JSON handler, as an
// attribute, in a group, in a nested group, and through With and
// WithGroup; separately, inside an error attribute, which both handlers
// print with the error's text; and as an attribute, and through With
// and WithGroup, to a resolvingHandler.
func slogRenderings(v any) slogOutput {
	var textBuf, jsonBuf, errBuf, resolvingBuf bytes.Buffer
	for _, l := range []*slog.Logger{
		slog.New(slog.NewTextHandler(&textBuf, nil)),
		slog.New(slog.NewJSONHandler(&jsonBuf, nil)),
	} {
		l.Info(logMessage, logKey, v)
		l.Info(logMessage, slog.Group(logGroup, slog.Any(logKey, v)))
		l.Info(logMessage, slog.Group(logGroup, slog.Group("h", slog.Any(logKey, v))))
		l.With(logKey, v).Info(logMessage)
		l.WithGroup(logGroup).Info(logMessage, logKey, v)
	}
	for _, l := range []*slog.Logger{
		slog.New(slog.NewTextHandler(&errBuf, nil)),
		slog.New(slog.NewJSONHandler(&errBuf, nil)),
	} {
		l.Info(logMessage, slog.Any("err", formattingError{v: v}))
	}
	resolving := slog.New(resolvingHandler{w: &resolvingBuf})
	resolving.Info(logMessage, logKey, v)
	resolving.With(logKey, v).Info(logMessage)
	resolving.WithGroup(logGroup).Info(logMessage, logKey, v)
	return slogOutput{text: textBuf.String(), json: jsonBuf.String(), errorAttrs: errBuf.String(), resolving: resolvingBuf.String()}
}

// resolvingHandler is a slog.Handler of the kind a deployment may write
// for itself: it resolves each attribute's value and prints it with %v,
// which is the value's String, rather than walking a group's attributes
// and resolving each as log/slog's own handlers do. A LogValue that
// returns a group must hold resolved values in it, or this handler
// prints each as fmt does. It logs no group of its own.
type resolvingHandler struct {
	w     io.Writer
	attrs []slog.Attr
}

func (resolvingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h resolvingHandler) Handle(_ context.Context, r slog.Record) error {
	write := func(a slog.Attr) bool {
		_, _ = fmt.Fprintf(h.w, " %s=%v", a.Key, a.Value.Resolve())
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)
	_, err := io.WriteString(h.w, "\n")
	return err
}

func (h resolvingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.attrs = append(slices.Clip(h.attrs), attrs...)
	return h
}

func (h resolvingHandler) WithGroup(string) slog.Handler { return h }

// encoder is a standard encoder, whose output must not carry a secret
// when it succeeds.
type encoder struct {
	name   string
	encode func(v any) ([]byte, error)
}

var encoders = []encoder{
	{"encoding/json", json.Marshal},
	{"encoding/xml", xml.Marshal},
	{"encoding/gob", func(v any) ([]byte, error) {
		var buf bytes.Buffer
		err := gob.NewEncoder(&buf).Encode(v)
		return buf.Bytes(), err
	}},
}

// formattingError is an error whose text formats the value it holds.
type formattingError struct{ v any }

func (e formattingError) Error() string { return fmt.Sprintf(valueFormat, e.v) }

// operand is a value in one position.
type operand struct {
	shape string
	value any
	// class is Fallback when fmt can reach the value only through its
	// reflection fallback, whatever the verb: in an unexported position,
	// or behind a pointer below the top that has no methods, which fmt
	// prints as an address, or under a verb it rejects for a pointer
	// (s, q and most others) by reflection, calling no method of
	// anything beneath it.
	class Class
	// slogResolves is whether the operand is the value itself or a
	// pointer to it, which log/slog resolves as a LogValuer, rather than
	// a value inside another, which its JSON handler encodes.
	slogResolves bool
	// viaError is whether the operand reaches the value only through its
	// own Error, which formats it: fmt calls Error under v, s, q, x and
	// X, but under %#v prints the operand, and its unexported field, by
	// reflection.
	viaError bool
}

// classUnder is the class of a rendering of op through a printer that
// calls a value's methods (methods) or doesn't.
func (op operand) classUnder(methods bool) Class {
	if op.class == Fallback || !methods {
		return Fallback
	}
	return Logging
}

type (
	exportedField[T any]          struct{ V T }
	unexportedField[T any]        struct{ v T }
	exportedPointerField[T any]   struct{ P *T }
	unexportedPointerField[T any] struct{ p *T }
	exportedInterfaceField        struct{ V any }
	unexportedInterfaceField      struct{ v any }
	pointerToExported[T any]      struct{ H *exportedField[T] }
	pointerToUnexported[T any]    struct{ h *unexportedField[T] }
	unexportedChain[T any]        struct {
		a struct{ b struct{ c struct{ d T } } }
	}
	errorHolding[T any]        struct{ v T }
	pointerErrorHolding[T any] struct{ v T }
)

func (e errorHolding[T]) Error() string { return fmt.Sprintf(valueFormat, e.v) }

func (e *pointerErrorHolding[T]) Error() string { return "failed" }

// operands is v in every position fmt treats differently.
func operands[T any](v T) []operand {
	p := v
	var chain unexportedChain[T]
	chain.a.b.c.d = v
	ops := []operand{
		{shape: "value", value: v, slogResolves: true},
		{shape: "pointer", value: &p, slogResolves: true},
		{shape: "exported field", value: exportedField[T]{V: v}},
		{shape: "pointer to an exported field", value: &exportedField[T]{V: v}},
		{shape: "exported pointer field", value: exportedPointerField[T]{P: &p}},
		{shape: "slice", value: []T{v}},
		{shape: "array", value: [1]T{v}},
		{shape: "map value", value: map[string]T{"key": v}},
		{shape: "[]any", value: []any{v}},
		{shape: "exported interface field", value: exportedInterfaceField{V: v}},
		{shape: "pointer field to an exported holder", value: pointerToExported[T]{H: &exportedField[T]{V: v}}, class: Fallback},
		{shape: "slice of maps of pointers", value: []map[string]*exportedField[T]{{"key": {V: v}}}, class: Fallback},
		{shape: "error formatting it", value: errorHolding[T]{v: v}, viaError: true},
		{shape: "unexported field", value: unexportedField[T]{v: v}, class: Fallback},
		{shape: "pointer to an unexported field", value: &unexportedField[T]{v: v}, class: Fallback},
		{shape: "unexported pointer field", value: unexportedPointerField[T]{p: &p}, class: Fallback},
		{shape: "unexported interface field", value: unexportedInterfaceField{v: v}, class: Fallback},
		{shape: "unexported interface field holding a pointer", value: unexportedInterfaceField{v: &p}, class: Fallback},
		{shape: "pointer field to an unexported holder", value: pointerToUnexported[T]{h: &unexportedField[T]{v: v}}, class: Fallback},
		{shape: "four-deep unexported chain", value: chain, class: Fallback},
		{shape: "pointer error holding it", value: &pointerErrorHolding[T]{v: v}, class: Fallback},
	}
	if key, ok := mapKey(v); ok {
		ops = append(ops, operand{shape: "map key", value: key})
	}
	return ops
}

// mapKey is a map keyed by v, when v is comparable: its type, and the
// values its interface fields hold.
func mapKey[T any](v T) (any, bool) {
	key := reflect.ValueOf(&v).Elem()
	if !key.Comparable() {
		return nil, false
	}
	m := reflect.MakeMap(reflect.MapOf(key.Type(), reflect.TypeFor[int]()))
	m.SetMapIndex(key, reflect.ValueOf(1))
	return m.Interface(), true
}

// minSecret is the shortest secret a detector searches for.
const minSecret = 12

// detector finds secrets in renderings.
type detector struct {
	secrets []secretForms
	// prefix is the forms of the secrets' longest common prefix, when it
	// is long enough to search for: a rendering carrying none of them
	// carries no secret, in any form.
	prefix []form
}

// secretForms is one secret and the substrings that betray it.
type secretForms struct {
	secret string
	forms  []form
}

type form struct{ name, text string }

type found struct{ secret, form string }

func newDetector(secrets []string) detector {
	var d detector
	for _, s := range secrets {
		if len(s) < minSecret {
			panic(fmt.Sprintf("rendertest: secret %q is shorter than %d bytes", s, minSecret))
		}
		d.secrets = append(d.secrets, secretForms{secret: s, forms: encodedForms(s)})
	}
	if p := commonPrefix(secrets); len(secrets) > 1 && len(p) >= minSecret/2+3 {
		d.prefix = encodedForms(p)
	}
	return d
}

// commonPrefix is the longest prefix every one of secrets starts with.
func commonPrefix(secrets []string) string {
	if len(secrets) == 0 {
		return ""
	}
	p := secrets[0]
	for _, s := range secrets[1:] {
		for !strings.HasPrefix(s, p) {
			p = p[:len(p)-1]
		}
	}
	return p
}

// mayCarry reports whether out can carry any of d's secrets: false only
// when it carries none of their common prefix's forms either.
func (d detector) mayCarry(out string, numbers []int) bool {
	if d.prefix == nil {
		return true
	}
	for _, f := range d.prefix {
		if strings.Contains(out, f.text) {
			return true
		}
	}
	return decimalRun(numbers, d.prefix[0].text)
}

// encodedForms is every substring a rendering carrying s contains.
func encodedForms(s string) []form {
	b := []byte(s)
	forms := []form{
		{"raw", s},
		{"hex", hex.EncodeToString(b)},
		{"HEX", strings.ToUpper(hex.EncodeToString(b))},
	}
	for _, verb := range []string{"%x", "%X", "%#x", "%#X", "%o", "%O", "%b", "%c", "%U", "%#U"} {
		forms = append(forms, form{"bytes as " + verb, perByte(b, verb)})
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for _, text := range base64Forms(enc, b) {
			forms = append(forms, form{"base64", text})
		}
	}
	return forms
}

// perByte is b's bytes, each formatted with verb, separated by spaces:
// how fmt prints a byte slice under most verbs, and under x and X with
// the space flag.
func perByte(b []byte, verb string) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf(verb, c)
	}
	return strings.Join(parts, " ")
}

// base64Forms is what enc's encoding of any byte string holding b
// contains, at each of the three alignments b can start at: the
// complete four-character groups made only of b's bits.
func base64Forms(enc *base64.Encoding, b []byte) []string {
	var out []string
	for lead := range 3 {
		encoded := enc.EncodeToString(append(make([]byte, lead), b...))
		start := 0
		if lead > 0 {
			start = 4
		}
		end := (lead + len(b)) / 3 * 4
		if end-start >= 8 {
			out = append(out, encoded[start:end])
		}
	}
	return out
}

// find reports each secret out carries, with the first form found.
func (d detector) find(out string) []found {
	var hits []found
	numbers := decimalNumbers(out)
	if !d.mayCarry(out, numbers) {
		return nil
	}
	for _, s := range d.secrets {
		if name, ok := s.in(out, numbers); ok {
			hits = append(hits, found{secret: s.secret, form: name})
		}
	}
	return hits
}

// in reports whether out, whose decimal numbers are numbers, carries s,
// and in which form.
func (s secretForms) in(out string, numbers []int) (string, bool) {
	for _, f := range s.forms {
		if strings.Contains(out, f.text) {
			return f.name, true
		}
	}
	if decimalRun(numbers, s.secret) {
		return "decimal bytes", true
	}
	return "", false
}

// decimalRun reports whether numbers, a rendering's decimal numbers in
// order, include secret's bytes as a run: a byte slice printed under %v
// or %d, or under a verb that is wrong for its bytes ("%!e(uint8=83)").
func decimalRun(numbers []int, secret string) bool {
	for i := 0; i+len(secret) <= len(numbers); i++ {
		if matchesAt(numbers[i:], secret) {
			return true
		}
	}
	return false
}

func matchesAt(numbers []int, secret string) bool {
	for j := range len(secret) {
		if numbers[j] != int(secret[j]) {
			return false
		}
	}
	return true
}

// decimalNumbers is every run of decimal digits in out, as numbers, in
// order; a run too long for a byte counts as -1.
func decimalNumbers(out string) []int {
	var numbers []int
	n, digits := 0, 0
	flush := func() {
		if digits > 0 {
			if digits > 3 {
				n = -1
			}
			numbers = append(numbers, n)
		}
		n, digits = 0, 0
	}
	for i := range len(out) {
		c := out[i]
		if c < '0' || c > '9' {
			flush()
			continue
		}
		n = n*10 + int(c-'0')
		digits++
	}
	flush()
	return numbers
}
