package extension_test

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/extension"
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

// --- RARRegistry.ValidateGrant -------------------------------------------

func TestRARRegistryValidateGrantAcceptsExactMatchByDefault(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	requested, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`))
	if err != nil {
		t.Fatalf("Parse(requested): %v", err)
	}
	granted, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`))
	if err != nil {
		t.Fatalf("Parse(granted): %v", err)
	}
	if err := reg.ValidateGrant(requested, granted); err != nil {
		t.Fatalf("ValidateGrant(identical objects) = %v, want nil", err)
	}
}

func TestRARRegistryValidateGrantAcceptsSubsetByDroppingObjects(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	requested, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"},{"type":"payment_initiation","instructed_amount":"10.00"}]`))
	if err != nil {
		t.Fatalf("Parse(requested): %v", err)
	}
	granted, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"10.00"}]`))
	if err != nil {
		t.Fatalf("Parse(granted): %v", err)
	}
	if err := reg.ValidateGrant(requested, granted); err != nil {
		t.Fatalf("ValidateGrant(dropped one object) = %v, want nil", err)
	}
}

func TestRARRegistryValidateGrantRejectsUnrequestedObjectByDefault(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	requested, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`))
	if err != nil {
		t.Fatalf("Parse(requested): %v", err)
	}
	// A different amount than what was requested — not a subset, and
	// with no ValidateGrant hook this type has no narrowing allowance at
	// all, so this must be rejected.
	granted, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"999999.00"}]`))
	if err != nil {
		t.Fatalf("Parse(granted): %v", err)
	}
	if err := reg.ValidateGrant(requested, granted); !errors.Is(err, extension.ErrRARGrantExceedsRequest) {
		t.Fatalf("ValidateGrant(unrequested amount) = %v, want errors.Is ErrRARGrantExceedsRequest", err)
	}
}

func TestRARRegistryValidateGrantRejectsMoreObjectsThanRequested(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	requested, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`))
	if err != nil {
		t.Fatalf("Parse(requested): %v", err)
	}
	// Two identical objects granted, but only one was ever requested.
	granted, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"},{"type":"payment_initiation","instructed_amount":"100.00"}]`))
	if err != nil {
		t.Fatalf("Parse(granted): %v", err)
	}
	if err := reg.ValidateGrant(requested, granted); !errors.Is(err, extension.ErrRARGrantExceedsRequest) {
		t.Fatalf("ValidateGrant(more objects than requested) = %v, want errors.Is ErrRARGrantExceedsRequest", err)
	}
}

func TestRARRegistryValidateGrantHonorsPerTypeNarrowingHook(t *testing.T) {
	// narrowable permits a granted InstructedAmt that is numerically no
	// greater than what was requested — real field-level narrowing,
	// beyond exact match.
	narrowable := extension.RARDefinition[paymentDetail]{
		Type: "payment_initiation", MaxObjects: 5, MaxBytesPerObject: 512,
		ValidateGrant: func(requested, granted paymentDetail) error {
			if granted.InstructedAmt > requested.InstructedAmt {
				return errors.New("granted amount exceeds requested amount")
			}
			return nil
		},
	}
	reg, err := extension.NewRARRegistry(4096, 4, narrowable)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	requested, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"500.00"}]`))
	if err != nil {
		t.Fatalf("Parse(requested): %v", err)
	}

	granted, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`))
	if err != nil {
		t.Fatalf("Parse(granted): %v", err)
	}
	if err := reg.ValidateGrant(requested, granted); err != nil {
		t.Fatalf("ValidateGrant(narrowed amount) = %v, want nil", err)
	}

	tooMuch, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"900.00"}]`))
	if err != nil {
		t.Fatalf("Parse(tooMuch): %v", err)
	}
	if err := reg.ValidateGrant(requested, tooMuch); !errors.Is(err, extension.ErrRARGrantExceedsRequest) {
		t.Fatalf("ValidateGrant(amount exceeding request) = %v, want errors.Is ErrRARGrantExceedsRequest", err)
	}
}

func TestRARRegistryValidateGrantRejectsTypeNeverRequested(t *testing.T) {
	accountDef := extension.RARDefinition[struct {
		Type string `json:"type"`
	}]{Type: "account_information", MaxObjects: 1, MaxBytesPerObject: 128}
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef, accountDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	requested, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`))
	if err != nil {
		t.Fatalf("Parse(requested): %v", err)
	}
	granted, err := reg.Parse(json.RawMessage(`[{"type":"account_information"}]`))
	if err != nil {
		t.Fatalf("Parse(granted): %v", err)
	}
	if err := reg.ValidateGrant(requested, granted); err == nil {
		t.Fatalf("ValidateGrant(type never requested) = nil error, want error")
	}
}

// --- RARSet ---------------------------------------------------------------

// bareInstructedAmount deliberately has no "type" field at all, to prove
// RARSet adds the discriminator itself rather than requiring the
// caller's struct to declare and keep it in sync.
type bareInstructedAmount struct {
	InstructedAmt string `json:"instructed_amount"`
}

func TestRARSetStampsTypeOnStructWithoutOwnTypeField(t *testing.T) {
	def := extension.RARDefinition[bareInstructedAmount]{
		Type: "payment_initiation", MaxObjects: 5, MaxBytesPerObject: 512,
	}
	raw, err := extension.RARSet(def, bareInstructedAmount{InstructedAmt: "100.00"})
	if err != nil {
		t.Fatalf("RARSet: %v", err)
	}
	var got struct {
		Type          string `json:"type"`
		InstructedAmt string `json:"instructed_amount"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal RARSet output: %v", err)
	}
	if got.Type != "payment_initiation" || got.InstructedAmt != "100.00" {
		t.Fatalf("RARSet output = %+v, want type=payment_initiation instructed_amount=100.00", got)
	}
}

func TestRARSetOverridesMismatchedTypeField(t *testing.T) {
	// paymentDef.Type is "payment_initiation" — construct a value that
	// disagrees with it and confirm RARSet's own def.Type wins.
	raw, err := extension.RARSet(paymentDef, paymentDetail{Type: "wrong_type", InstructedAmt: "50.00"})
	if err != nil {
		t.Fatalf("RARSet: %v", err)
	}
	var got paymentDetail
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal RARSet output: %v", err)
	}
	if got.Type != "payment_initiation" {
		t.Fatalf("Type = %q, want %q (RARSet must override the value's own mismatched type)", got.Type, "payment_initiation")
	}
}

func TestRARSetRoundTripsThroughRegistryParseAndRARGet(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	raw, err := extension.RARSet(paymentDef, paymentDetail{InstructedAmt: "250.00"})
	if err != nil {
		t.Fatalf("RARSet: %v", err)
	}
	array, err := json.Marshal([]json.RawMessage{raw})
	if err != nil {
		t.Fatalf("marshal array: %v", err)
	}
	values, err := reg.Parse(array)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	details, err := extension.RARGet(values, paymentDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 1 || details[0].Fields.InstructedAmt != "250.00" {
		t.Fatalf("RARGet = %+v, want one object with instructed_amount=250.00", details)
	}
}

func TestRARSetRejectsNonObjectValue(t *testing.T) {
	def := extension.RARDefinition[string]{Type: "payment_initiation", MaxObjects: 1, MaxBytesPerObject: 128}
	if _, err := extension.RARSet(def, "not an object"); err == nil {
		t.Fatalf("RARSet(string) = nil error, want error (a bare string is not a JSON object)")
	}
}

func TestRARSetRejectsValueThatCannotMarshal(t *testing.T) {
	type withNaN struct {
		Amount float64 `json:"amount"`
	}
	def := extension.RARDefinition[withNaN]{Type: "payment_initiation", MaxObjects: 1, MaxBytesPerObject: 128}
	// encoding/json cannot represent NaN/Inf float values at all — the
	// most realistic way a caller's own value fails to marshal.
	if _, err := extension.RARSet(def, withNaN{Amount: math.NaN()}); err == nil {
		t.Fatalf("RARSet(NaN) = nil error, want error")
	}
}

func TestRARSetRejectsNilPointerValue(t *testing.T) {
	def := extension.RARDefinition[*paymentDetail]{Type: "payment_initiation", MaxObjects: 1, MaxBytesPerObject: 128}
	if _, err := extension.RARSet(def, nil); err == nil {
		t.Fatalf("RARSet(nil *paymentDetail) = nil error, want error (encodes as JSON null, not an object)")
	}
}
