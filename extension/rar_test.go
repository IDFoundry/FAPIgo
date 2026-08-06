package extension_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/osanderson/go-fapi/extension"
)

type paymentDetail struct {
	Type          string `json:"type"`
	InstructedAmt string `json:"instructed_amount"`
}

var paymentDef = extension.RARDefinition[paymentDetail]{
	Type: "payment_initiation", MaxObjects: 2, MaxBytesPerObject: 512,
}

func TestRARRegistryParseAcceptsValidDetails(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`)
	values, err := reg.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	details, err := extension.RARGet(values, paymentDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 1 || details[0].Fields.InstructedAmt != "100.00" {
		t.Errorf("details = %+v", details)
	}
}

func TestRARRegistryParseRejectsUnregisteredType(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[{"type":"unknown_type"}]`)
	if _, err := reg.Parse(raw); !errors.Is(err, extension.ErrRARUnregisteredType) {
		t.Fatalf("Parse(unregistered type) error = %v, want ErrRARUnregisteredType", err)
	}
}

func TestRARRegistryParseRejectsTooManyObjects(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[
		{"type":"payment_initiation","instructed_amount":"1"},
		{"type":"payment_initiation","instructed_amount":"2"},
		{"type":"payment_initiation","instructed_amount":"3"}
	]`)
	if _, err := reg.Parse(raw); !errors.Is(err, extension.ErrRARTooManyObjects) {
		t.Fatalf("Parse(too many objects) error = %v, want ErrRARTooManyObjects", err)
	}
}

func TestRARRegistryParseRejectsOversizedObject(t *testing.T) {
	tiny := extension.RARDefinition[paymentDetail]{Type: "payment_initiation", MaxObjects: 5, MaxBytesPerObject: 32}
	reg, err := extension.NewRARRegistry(4096, 4, tiny)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"a very long amount string that exceeds the tiny per-object byte limit"}]`)
	if _, err := reg.Parse(raw); !errors.Is(err, extension.ErrRARObjectTooLarge) {
		t.Fatalf("Parse(oversized object) error = %v, want ErrRARObjectTooLarge", err)
	}
}

func TestRARRegistryParseRejectsTotalSizeOverLimit(t *testing.T) {
	reg, err := extension.NewRARRegistry(16, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`)
	if _, err := reg.Parse(raw); !errors.Is(err, extension.ErrRARTooLarge) {
		t.Fatalf("Parse(total too large) error = %v, want ErrRARTooLarge", err)
	}
}

func TestRARRegistryParseRejectsExcessiveDepth(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 2, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	// Depth 3: the array (1), the object (2), a nested object value (3).
	raw := json.RawMessage(`[{"type":"payment_initiation","instructed_amount":{"nested":"oops"}}]`)
	if _, err := reg.Parse(raw); !errors.Is(err, extension.ErrRARTooDeep) {
		t.Fatalf("Parse(too deep) error = %v, want ErrRARTooDeep", err)
	}
}

func TestRARRegistryParseRejectsDuplicateTopLevelMember(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"1","instructed_amount":"2"}]`)
	_, err = reg.Parse(raw)
	if !errors.Is(err, extension.ErrDuplicateMember) {
		t.Fatalf("Parse(duplicate member) error = %v, want ErrDuplicateMember", err)
	}
}

func TestRARRegistryParseRejectsUnknownFieldWithinObject(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"1","unexpected_field":"x"}]`)
	if _, err := reg.Parse(raw); err == nil {
		t.Fatalf("Parse(unknown field) = nil error, want error")
	}
}

func TestNewRARRegistryRejectsDuplicateType(t *testing.T) {
	dup := extension.RARDefinition[paymentDetail]{Type: "payment_initiation", MaxObjects: 1, MaxBytesPerObject: 64}
	if _, err := extension.NewRARRegistry(4096, 4, paymentDef, dup); err == nil {
		t.Fatalf("NewRARRegistry(duplicate type) = nil error, want error")
	}
}

func TestNewRARRegistryRejectsInvalidBounds(t *testing.T) {
	if _, err := extension.NewRARRegistry(0, 4, paymentDef); err == nil {
		t.Fatalf("NewRARRegistry(zero max total bytes) = nil error, want error")
	}
	if _, err := extension.NewRARRegistry(4096, 0, paymentDef); err == nil {
		t.Fatalf("NewRARRegistry(zero max depth) = nil error, want error")
	}
	zeroObjects := extension.RARDefinition[paymentDetail]{Type: "x", MaxObjects: 0, MaxBytesPerObject: 64}
	if _, err := extension.NewRARRegistry(4096, 4, zeroObjects); err == nil {
		t.Fatalf("NewRARRegistry(zero max objects) = nil error, want error")
	}
}

func TestRARRegistryParseRejectsNonArrayTopLevel(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`{"type":"payment_initiation"}`)
	if _, err := reg.Parse(raw); err == nil {
		t.Fatalf("Parse(non-array) = nil error, want error")
	}
}

func TestRARRegistryParseRejectsMultipleTypesIndependently(t *testing.T) {
	accountDef := extension.RARDefinition[struct {
		Type string `json:"type"`
	}]{Type: "account_information", MaxObjects: 1, MaxBytesPerObject: 128}
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef, accountDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[
		{"type":"payment_initiation","instructed_amount":"1"},
		{"type":"account_information"}
	]`)
	values, err := reg.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	payments, err := extension.RARGet(values, paymentDef)
	if err != nil || len(payments) != 1 {
		t.Fatalf("RARGet(payment): %v, %d results", err, len(payments))
	}
	accounts, err := extension.RARGet(values, accountDef)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("RARGet(account): %v, %d results", err, len(accounts))
	}
}

func TestRARRegistryParseRejectsValidatorFailure(t *testing.T) {
	strict := extension.RARDefinition[paymentDetail]{
		Type: "payment_initiation", MaxObjects: 5, MaxBytesPerObject: 512,
		Validate: func(p paymentDetail) error {
			if !strings.HasPrefix(p.InstructedAmt, "$") {
				return errors.New("instructed_amount must start with $")
			}
			return nil
		},
	}
	reg, err := extension.NewRARRegistry(4096, 4, strict)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw := json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`)
	if _, err := reg.Parse(raw); err == nil {
		t.Fatalf("Parse(validator failure) = nil error, want error")
	}
}
