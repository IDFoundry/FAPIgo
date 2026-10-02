package extension_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

type nestedAmount struct {
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

type nestedPayment struct {
	InstructedAmount nestedAmount   `json:"instructedAmount"`
	Actions          []string       `json:"actions,omitempty"`
	Creditors        []nestedAmount `json:"creditors,omitempty"`
	Reference        untaggedNested `json:"reference,omitempty"`
}

// untaggedNested has no json tags: encoding/json matches its members to
// the Go names in any case, as it always has.
type untaggedNested struct {
	Text string
}

var nestedPaymentType = extension.RARDefinition[nestedPayment]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 512}

// TestRARParseRejectsNestedCaseVariants covers members below the top
// level that encoding/json reads differently from a case-sensitive
// reader of the issued token: a second "value" spelled "VALUE" makes the
// consent page show 1.00 where that reader sees 1000.00, and a lone
// "ACTIONS" is actions to one and no actions at all to the other.
func TestRARParseRejectsNestedCaseVariants(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 5, nestedPaymentType)
	if err != nil {
		t.Fatal(err)
	}
	for name, detail := range map[string]string{
		"value and VALUE":          `{"type":"payment","instructedAmount":{"value":"1000.00","currency":"EUR","VALUE":"1.00"}}`,
		"value twice":              `{"type":"payment","instructedAmount":{"value":"1000.00","currency":"EUR","value":"1.00"}}`,
		"in an array":              `{"type":"payment","instructedAmount":{"value":"1.00","currency":"EUR"},"creditors":[{"value":"1.00","Value":"9.00","currency":"EUR"}]}`,
		"a lone ACTIONS":           `{"type":"payment","instructedAmount":{"value":"1.00","currency":"EUR"},"ACTIONS":["read"]}`,
		"a lone nested VALUE":      `{"type":"payment","instructedAmount":{"VALUE":"1.00","currency":"EUR"}}`,
		"long s for s in currency": "{\"type\":\"payment\",\"instructedAmount\":{\"value\":\"1.00\",\"currenſy\":\"EUR\"}}",
	} {
		if _, err := reg.Parse(json.RawMessage(`[` + detail + `]`)); err == nil {
			t.Errorf("%s: Parse = nil error, want refusal", name)
		}
	}
	for name, detail := range map[string]string{
		"exact names":                  `{"type":"payment","instructedAmount":{"value":"1.00","currency":"EUR"},"actions":["read"]}`,
		"an untagged field, as before": `{"type":"payment","instructedAmount":{"value":"1.00","currency":"EUR"},"reference":{"text":"inv-1"}}`,
	} {
		if _, err := reg.Parse(json.RawMessage(`[` + detail + `]`)); err != nil {
			t.Errorf("%s: Parse = %v, want nil", name, err)
		}
	}
}

// TestGrantedRARRejectsNestedCaseVariants covers the resource side: a
// claim with a nested repeat is refused by ParseGrantedRAR, and a lone
// variant by RARGet, which knows the detail type.
func TestGrantedRARRejectsNestedCaseVariants(t *testing.T) {
	_, err := extension.ParseGrantedRAR(json.RawMessage(`[{"type":"payment","instructedAmount":{"value":"1000.00","VALUE":"1.00","currency":"EUR"}}]`))
	if !errors.Is(err, extension.ErrDuplicateMember) {
		t.Errorf("ParseGrantedRAR(nested repeat) = %v, want ErrDuplicateMember", err)
	}
	granted, err := extension.ParseGrantedRAR(json.RawMessage(`[{"type":"payment","instructedAmount":{"value":"1.00","currency":"EUR"},"ACTIONS":["read"]}]`))
	if err != nil {
		t.Fatalf("ParseGrantedRAR: %v", err)
	}
	if _, err := extension.RARGet(granted, nestedPaymentType); err == nil {
		t.Error("RARGet(a lone ACTIONS) = nil error, want refusal")
	}
}
