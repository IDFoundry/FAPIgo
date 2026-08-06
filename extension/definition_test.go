package extension_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/osanderson/go-fapi/extension"
)

type accountHint struct {
	AccountID string `json:"account_id"`
}

var accountHintDef = extension.Definition[accountHint]{
	Name:           "x_account_hint",
	Cardinality:    extension.Single,
	AllowedSources: extension.SourcePlainParameter | extension.SourceRequestObject,
	MaxBytes:       256,
}

var tagsDef = extension.Definition[[]string]{
	Name:           "x_tags",
	Cardinality:    extension.Multiple,
	AllowedSources: extension.SourcePlainParameter,
	MaxBytes:       256,
}

func TestSetGetRoundTrip(t *testing.T) {
	var values extension.Values
	if err := extension.Set(&values, accountHintDef, accountHint{AccountID: "acc-1"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok := extension.Get(values, accountHintDef)
	if !ok {
		t.Fatalf("Get: ok = false, want true")
	}
	if got.AccountID != "acc-1" {
		t.Errorf("AccountID = %q, want acc-1", got.AccountID)
	}
}

func TestGetMissingValueReturnsFalse(t *testing.T) {
	var values extension.Values
	_, ok := extension.Get(values, accountHintDef)
	if ok {
		t.Fatalf("Get(unset) ok = true, want false")
	}
}

func TestSetRejectsOversizedValue(t *testing.T) {
	var values extension.Values
	huge := accountHint{AccountID: string(make([]byte, 1024))}
	if err := extension.Set(&values, accountHintDef, huge); err == nil {
		t.Fatalf("Set(oversized) = nil error, want error")
	}
}

func TestSetRejectsValidatorFailure(t *testing.T) {
	def := accountHintDef
	def.Validate = func(v accountHint) error {
		if v.AccountID == "" {
			return errors.New("account_id is required")
		}
		return nil
	}
	var values extension.Values
	if err := extension.Set(&values, def, accountHint{}); err == nil {
		t.Fatalf("Set(invalid) = nil error, want error")
	}
}

func TestNewRegistryRejectsDuplicateName(t *testing.T) {
	dup := extension.Definition[string]{
		Name: "x_account_hint", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	_, err := extension.NewRegistry(accountHintDef, dup)
	if err == nil {
		t.Fatalf("NewRegistry(duplicate name) = nil error, want error")
	}
}

func TestNewRegistryRejectsCardinalityMismatch(t *testing.T) {
	bad := extension.Definition[accountHint]{
		Name: "x_bad", Cardinality: extension.Multiple, // accountHint is not a slice
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	_, err := extension.NewRegistry(bad)
	if err == nil {
		t.Fatalf("NewRegistry(cardinality mismatch) = nil error, want error")
	}

	badSlice := extension.Definition[[]string]{
		Name: "x_bad_slice", Cardinality: extension.Single, // []string is a slice
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	if _, err := extension.NewRegistry(badSlice); err == nil {
		t.Fatalf("NewRegistry(cardinality mismatch, slice) = nil error, want error")
	}
}

func rawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestRegistryParseAcceptsRegisteredParameter(t *testing.T) {
	reg, err := extension.NewRegistry(accountHintDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	params := map[string]json.RawMessage{
		"x_account_hint": rawJSON(t, accountHint{AccountID: "acc-2"}),
	}
	values, err := reg.Parse(params, nil, extension.SourcePlainParameter)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, ok := extension.Get(values, accountHintDef)
	if !ok || got.AccountID != "acc-2" {
		t.Errorf("Get after Parse = %+v, %v; want acc-2, true", got, ok)
	}
}

func TestRegistryParseRejectsUnregisteredParameter(t *testing.T) {
	reg, err := extension.NewRegistry(accountHintDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	params := map[string]json.RawMessage{"x_unknown": rawJSON(t, "value")}
	if _, err := reg.Parse(params, nil, extension.SourcePlainParameter); !errors.Is(err, extension.ErrUnregisteredParameter) {
		t.Fatalf("Parse(unregistered) error = %v, want ErrUnregisteredParameter", err)
	}
}

func TestRegistryParseSkipsCoreParameters(t *testing.T) {
	reg, err := extension.NewRegistry(accountHintDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	params := map[string]json.RawMessage{
		"response_type":  rawJSON(t, "code"),
		"x_account_hint": rawJSON(t, accountHint{AccountID: "acc-3"}),
	}
	core := map[string]struct{}{"response_type": {}}
	values, err := reg.Parse(params, core, extension.SourcePlainParameter)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := extension.Get(values, accountHintDef); !ok {
		t.Errorf("Get(x_account_hint) ok = false, want true")
	}
}

func TestRegistryParseRejectsDisallowedSource(t *testing.T) {
	requestObjectOnly := extension.Definition[accountHint]{
		Name: "x_sensitive", Cardinality: extension.Single,
		AllowedSources: extension.SourceRequestObject, MaxBytes: 256,
	}
	reg, err := extension.NewRegistry(requestObjectOnly)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	params := map[string]json.RawMessage{"x_sensitive": rawJSON(t, accountHint{AccountID: "acc-4"})}
	if _, err := reg.Parse(params, nil, extension.SourcePlainParameter); !errors.Is(err, extension.ErrSourceNotAllowed) {
		t.Fatalf("Parse(disallowed source) error = %v, want ErrSourceNotAllowed", err)
	}
	if _, err := reg.Parse(params, nil, extension.SourceRequestObject); err != nil {
		t.Fatalf("Parse(allowed source): %v", err)
	}
}

func TestRegistryParseRejectsUnknownFields(t *testing.T) {
	reg, err := extension.NewRegistry(accountHintDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	params := map[string]json.RawMessage{
		"x_account_hint": json.RawMessage(`{"account_id":"acc-5","extra":"field"}`),
	}
	if _, err := reg.Parse(params, nil, extension.SourcePlainParameter); err == nil {
		t.Fatalf("Parse(unknown field) = nil error, want error")
	}
}

func TestAsParametersFiltersByReturnInTokenClaims(t *testing.T) {
	inClaims := extension.Definition[string]{
		Name: "x_in_claims", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
		ReturnInTokenClaims: true,
	}
	notInClaims := extension.Definition[string]{
		Name: "x_not_in_claims", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	var values extension.Values
	if err := extension.Set(&values, inClaims, "a"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := extension.Set(&values, notInClaims, "b"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	params := extension.AsParameters(values, inClaims, notInClaims)
	if _, ok := params["x_in_claims"]; !ok {
		t.Errorf("params missing x_in_claims")
	}
	if _, ok := params["x_not_in_claims"]; ok {
		t.Errorf("params unexpectedly contains x_not_in_claims")
	}
}
