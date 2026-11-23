package extension_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

const (
	testOTP     = "SENSITIVE-OTP-424242"
	testPurpose = "PURPOSE-VISIBLE-9001"
)

var (
	otpDef = extension.Definition[string]{
		Sensitivity: extension.Sensitive, Name: "x_otp", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	purposeDef = extension.Definition[accountHint]{
		Sensitivity: extension.NotSensitive, Name: "x_purpose", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 128,
	}
)

// sensitiveValues is a Values holding a Sensitive and a NotSensitive
// value.
func sensitiveValues(t *testing.T) extension.Values {
	t.Helper()
	var values extension.Values
	if err := extension.Set(&values, otpDef, testOTP); err != nil {
		t.Fatal(err)
	}
	if err := extension.Set(&values, purposeDef, accountHint{AccountID: testPurpose}); err != nil {
		t.Fatal(err)
	}
	return values
}

// TestValuesPrintNoValue renders a Values every way a log line can
// reach it and finds neither value, the Sensitive one or the other, in
// any encoding. Its JSON encoding, for storage, carries both by design,
// and so does log/slog's JSON handler, which encodes a Values sitting
// inside another value with it.
func TestValuesPrintNoValue(t *testing.T) {
	rendertest.Check(t, sensitiveValues(t), []string{testOTP, testPurpose}, rendertest.Allow(rendertest.Encoding))
}

func TestValuesRenderNames(t *testing.T) {
	values := sensitiveValues(t)
	var zero extension.Values
	for _, tc := range []struct{ got, want string }{
		{fmt.Sprintf("%v", values), "map[x_otp:[REDACTED] x_purpose:[REDACTED]]"},
		{fmt.Sprintf("%+v", values), "map[x_otp:[REDACTED] x_purpose:[REDACTED]]"},
		{fmt.Sprintf("%#v", values), `extension.Values{"x_otp":[REDACTED], "x_purpose":[REDACTED]}`},
		{fmt.Sprintf("%q", values), `map["x_otp":"[REDACTED]" "x_purpose":"[REDACTED]"]`},
		{values.String(), "map[x_otp:[REDACTED] x_purpose:[REDACTED]]"},
		{fmt.Sprintf("%v", zero), "map[]"},
		{fmt.Sprintf("%#v", zero), "extension.Values{}"},
	} {
		if tc.got != tc.want {
			t.Errorf("rendering = %s, want %s", tc.got, tc.want)
		}
	}

	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "ext", values)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "ext", values)
	if !strings.Contains(text.String(), "ext.x_otp=[REDACTED] ext.x_purpose=[REDACTED]") {
		t.Errorf("slog text = %s", text.String())
	}
	if !strings.Contains(js.String(), `"ext":{"x_otp":"[REDACTED]","x_purpose":"[REDACTED]"}`) {
		t.Errorf("slog JSON = %s", js.String())
	}
}

// TestValuesStorageEncodingsKeepValues pins that the encodings meant
// for storage and tokens still carry every value, the Sensitive one
// included, byte for byte.
func TestValuesStorageEncodingsKeepValues(t *testing.T) {
	values := sensitiveValues(t)
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"x_otp":"` + testOTP + `","x_purpose":{"account_id":"` + testPurpose + `"}}`; string(raw) != want {
		t.Errorf("MarshalJSON = %s, want %s", raw, want)
	}
	var restored extension.Values
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if got, ok := extension.Get(restored, otpDef); !ok || got != testOTP {
		t.Errorf("Get(restored, x_otp) = %q, %v", got, ok)
	}
	if got := extension.Snapshot(restored)["x_otp"]; string(got) != `"`+testOTP+`"` {
		t.Errorf("Snapshot(restored)[x_otp] = %s", got)
	}
	if !reflect.DeepEqual(restored, values) {
		t.Error("a restored Values isn't deeply equal to the one encoded")
	}
}

// TestValuesCopiesShareStorage pins Values' aliasing: copies of a
// Values holding values share them, as copies of the map it once was
// did, while Set on a copy of the zero Values gives that copy its own.
func TestValuesCopiesShareStorage(t *testing.T) {
	var held extension.Values
	if err := extension.Set(&held, otpDef, testOTP); err != nil {
		t.Fatal(err)
	}
	copied := held
	if err := extension.Set(&copied, purposeDef, accountHint{AccountID: testPurpose}); err != nil {
		t.Fatal(err)
	}
	if _, ok := extension.Get(held, purposeDef); !ok {
		t.Error("Set on a copy of a non-zero Values isn't visible in the original")
	}

	var zero extension.Values
	zeroCopy := zero
	if err := extension.Set(&zeroCopy, otpDef, testOTP); err != nil {
		t.Fatal(err)
	}
	if _, ok := extension.Get(zero, otpDef); ok {
		t.Error("Set on a copy of the zero Values changed the original")
	}
}

type pinAccount struct {
	Number string `json:"number"`
}

// refusal is one value a Definition of T refuses, whose decoder or
// check quotes it in its error: param's value raw, quoting literal.
type refusal struct {
	name, param, raw, literal, typ string
	def                            func(param string, s extension.Sensitivity) extension.Registered
}

func defOf[T any]() func(string, extension.Sensitivity) extension.Registered {
	return func(param string, s extension.Sensitivity) extension.Registered {
		return extension.Definition[T]{
			Sensitivity: s, Name: param, Cardinality: extension.Single,
			AllowedSources: extension.SourcePlainParameter, MaxBytes: 256,
		}
	}
}

var refusals = []refusal{
	{"int32 overflow", "x_pin", `98765432109876`, "98765432109876", "int32", defOf[int32]()},
	{"int32 fraction", "x_pin", `1234567.890123`, "1234567.890123", "int32", defOf[int32]()},
	{"float32 overflow", "x_amount", `9.87654321098765e+39`, "9.87654321098765e+39", "float32", defOf[float32]()},
	{"time.Time", "x_dob", `"19900102-PRIVATE"`, "19900102-PRIVATE", "time.Time", defOf[time.Time]()},
	{"netip.Addr", "x_ip", `"10.20.30.400.secret"`, "10.20.30.400.secret", "netip.Addr", defOf[netip.Addr]()},
	{"*big.Int", "x_big", `"12345678901234567890x"`, "12345678901234567890x", "*big.Int", defOf[*big.Int]()},
	{"map member repeated in another case", "x_map", `{"MEMBERSECRET1":1,"membersecret1":2}`, "MEMBERSECRET1", "map[string]int", defOf[map[string]int]()},
	{"struct member of the wrong type", "x_acct", `{"number":4111111111111111}`, "number", "extension_test.pinAccount", defOf[pinAccount]()},
}

// TestSensitiveRefusalWithholdsTheValue checks that a Sensitive
// Definition's refusal names the parameter and its type and quotes
// nothing of the value, in its text, in any rendering of it, or through
// Unwrap and errors.As, while a NotSensitive one keeps its cause.
func TestSensitiveRefusalWithholdsTheValue(t *testing.T) {
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			sensitive := parseRefusal(t, tc, extension.Sensitive)
			want := fmt.Sprintf("extension: %q: malformed value: not a valid %s (detail withheld: the definition is Sensitive)", tc.param, tc.typ)
			if sensitive.Error() != want {
				t.Errorf("Sensitive refusal = %q, want %q", sensitive.Error(), want)
			}
			if errors.Unwrap(sensitive) != nil || errors.As(sensitive, new(*json.UnmarshalTypeError)) {
				t.Error("a Sensitive refusal hands out its cause")
			}
			// fmt's reflection fallback (%#v, %w outside Errorf, a verb
			// an error doesn't take) prints the refusal's fields. The
			// struct case's literal, a member name, is too short to
			// search renderings for.
			if len(tc.literal) >= 12 {
				rendertest.Check(t, sensitive, []string{tc.literal})
			}
			notSensitive := parseRefusal(t, tc, extension.NotSensitive)
			if errors.Unwrap(notSensitive) == nil || !strings.Contains(notSensitive.Error(), tc.literal) {
				t.Errorf("NotSensitive refusal = %q, want its cause's text", notSensitive.Error())
			}
		})
	}
}

// parseRefusal parses tc's value against its Definition at sensitivity
// s, and returns the refusal.
func parseRefusal(t *testing.T, tc refusal, s extension.Sensitivity) error {
	t.Helper()
	reg, err := extension.NewRegistry(tc.def(tc.param, s))
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Parse(map[string]json.RawMessage{tc.param: json.RawMessage(tc.raw)}, nil, extension.SourcePlainParameter)
	if err == nil {
		t.Fatalf("Parse(%s) accepted it", tc.raw)
	}
	return err
}

var errPINTooShort = errors.New("pin too short")

// pinRefusal is Validate's error in the test below: an error held by
// value that quotes the value, as an embedder's own error type can.
type pinRefusal struct{ pin string }

func (e pinRefusal) Error() string { return errPINTooShort.Error() + ": " + e.pin }

func (pinRefusal) Unwrap() error { return errPINTooShort }

// TestSensitiveValidateRefusalMatchesItsSentinel checks a Sensitive
// Validate refusal, at Parse and at Set, withholds Validate's text, in
// any rendering of it, while errors.Is still finds the sentinel it
// wraps, as it does for the duplicate-member check's.
func TestSensitiveValidateRefusalMatchesItsSentinel(t *testing.T) {
	def := extension.Definition[string]{
		Sensitivity: extension.Sensitive, Name: "x_pin", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
		Validate: func(v string) error { return pinRefusal{v} },
	}
	reg, err := extension.NewRegistry(def)
	if err != nil {
		t.Fatal(err)
	}
	_, parseErr := reg.Parse(map[string]json.RawMessage{"x_pin": json.RawMessage(`"` + testOTP + `"`)}, nil, extension.SourcePlainParameter)
	var values extension.Values
	setErr := extension.Set(&values, def, testOTP)
	for _, err := range []error{parseErr, setErr} {
		if want := `extension: "x_pin": value rejected by its Validate (detail withheld: the definition is Sensitive)`; err == nil || err.Error() != want {
			t.Errorf("refusal = %v, want %q", err, want)
		}
		if !errors.Is(err, errPINTooShort) {
			t.Error("errors.Is doesn't find Validate's sentinel in a Sensitive refusal")
		}
		rendertest.Check(t, err, []string{testOTP})
	}
	dup := parseRefusal(t, refusals[6], extension.Sensitive)
	if !errors.Is(dup, extension.ErrDuplicateMember) {
		t.Error("errors.Is doesn't find ErrDuplicateMember in a Sensitive refusal")
	}
}

// failingMarshaler can't be encoded.
type failingMarshaler struct{}

func (failingMarshaler) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cannot encode " + testOTP)
}

func TestSensitiveSetRefusalWithholdsTheValue(t *testing.T) {
	def := extension.Definition[failingMarshaler]{
		Sensitivity: extension.Sensitive, Name: "x_blob", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	var values extension.Values
	err := extension.Set(&values, def, failingMarshaler{})
	if want := `extension: "x_blob": malformed value: not a valid extension_test.failingMarshaler (detail withheld: the definition is Sensitive)`; err == nil || err.Error() != want {
		t.Errorf("Set = %v, want %q", err, want)
	}
	def.Sensitivity = extension.NotSensitive
	if err := extension.Set(&values, def, failingMarshaler{}); err == nil || !strings.HasPrefix(err.Error(), `extension: "x_blob": marshal: `) {
		t.Errorf("NotSensitive Set = %v, want today's text", err)
	}
}

// TestNewRegistryRefusesSensitiveTokenClaims checks NewRegistry refuses
// a Sensitive Definition that sets ReturnInTokenClaims, whose value
// would sit in tokens anyone holding one can read, and accepts either
// on its own.
func TestNewRegistryRefusesSensitiveTokenClaims(t *testing.T) {
	both := otpDef
	both.ReturnInTokenClaims = true
	if _, err := extension.NewRegistry(both); !errors.Is(err, extension.ErrSensitiveTokenClaim) || !strings.Contains(err.Error(), `"x_otp"`) {
		t.Errorf("NewRegistry(Sensitive, ReturnInTokenClaims) = %v, want ErrSensitiveTokenClaim naming x_otp", err)
	}
	claimed := both
	claimed.Sensitivity = extension.NotSensitive
	for _, def := range []extension.Definition[string]{otpDef, claimed} {
		if _, err := extension.NewRegistry(def); err != nil {
			t.Errorf("NewRegistry(%v, ReturnInTokenClaims %t) = %v, want it accepted", def.Sensitivity, def.ReturnInTokenClaims, err)
		}
	}
}

// TestAsParametersLeavesOutSensitiveValues checks AsParameters returns
// no Sensitive value, even for a Definition passed to it without being
// registered, while a NotSensitive one marked ReturnInTokenClaims still
// goes into the token's claims.
func TestAsParametersLeavesOutSensitiveValues(t *testing.T) {
	both := otpDef
	both.ReturnInTokenClaims = true
	claimed := purposeDef
	claimed.ReturnInTokenClaims = true
	got := extension.AsParameters(sensitiveValues(t), both, claimed)
	if _, ok := got["x_otp"]; ok {
		t.Error("AsParameters returned a Sensitive value")
	}
	if want := `{"account_id":"` + testPurpose + `"}`; string(got["x_purpose"]) != want {
		t.Errorf("AsParameters()[x_purpose] = %s, want %s", got["x_purpose"], want)
	}
}

func TestRegistrySensitive(t *testing.T) {
	reg, err := extension.NewRegistry(otpDef, purposeDef)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                  string
		sensitive, registered bool
	}{
		{"x_otp", true, true},
		{"x_purpose", false, true},
		{"x_unknown", false, false},
	} {
		if sensitive, registered := reg.Sensitive(tc.name); sensitive != tc.sensitive || registered != tc.registered {
			t.Errorf("Sensitive(%q) = %t, %t; want %t, %t", tc.name, sensitive, registered, tc.sensitive, tc.registered)
		}
	}
}

// TestValueRefusalsMatchTheirSentinels checks errors.Is tells a
// malformed value from one Validate rejected, for a Sensitive and a
// NotSensitive Definition alike, and matches neither for a refusal of
// another kind.
func TestValueRefusalsMatchTheirSentinels(t *testing.T) {
	for _, s := range []extension.Sensitivity{extension.Sensitive, extension.NotSensitive} {
		malformed := parseRefusal(t, refusals[0], s)
		def := extension.Definition[string]{
			Sensitivity: s, Name: "x_pin", Cardinality: extension.Single,
			AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
			Validate: func(string) error { return errPINTooShort },
		}
		var values extension.Values
		rejected := extension.Set(&values, def, testOTP)
		if !errors.Is(malformed, extension.ErrMalformedValue) || errors.Is(malformed, extension.ErrValueRejected) {
			t.Errorf("%v malformed value: errors.Is matches the wrong sentinel: %v", s, malformed)
		}
		if !errors.Is(rejected, extension.ErrValueRejected) || errors.Is(rejected, extension.ErrMalformedValue) {
			t.Errorf("%v rejected value: errors.Is matches the wrong sentinel: %v", s, rejected)
		}
	}
	def := otpDef
	def.AllowedSources = extension.SourceRequestObject
	reg, err := extension.NewRegistry(def)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Parse(map[string]json.RawMessage{"x_otp": json.RawMessage(`"` + testOTP + `"`)}, nil, extension.SourcePlainParameter)
	if !errors.Is(err, extension.ErrSourceNotAllowed) || errors.Is(err, extension.ErrMalformedValue) || errors.Is(err, extension.ErrValueRejected) {
		t.Errorf("a refusal by source matches a value sentinel: %v", err)
	}
}
