package extension_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

type typedDetail struct {
	Type   string `json:"type"`
	Amount string `json:"amount"`
	Kind   string `json:"kind,omitempty"`
}

// TestRARParseRejectsCaseVariantMembers covers member names encoding/json
// matches case-insensitively, where a case-sensitive reader of the issued
// token would read the object differently: a second "type", a "type"
// spelled otherwise, or a second "amount".
func TestRARParseRejectsCaseVariantMembers(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4,
		extension.RARDefinition[typedDetail]{Type: "a", MaxObjects: 1, MaxBytesPerObject: 256},
		extension.RARDefinition[typedDetail]{Type: "b", MaxObjects: 1, MaxBytesPerObject: 256},
		extension.RARDefinition[untaggedTypeDetail]{Type: "c", MaxObjects: 1, MaxBytesPerObject: 256},
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, detail := range map[string]string{
		"type and TYPE":             `{"type":"a","TYPE":"b","amount":"1"}`,
		"Type alone":                `{"Type":"b","amount":"1"}`,
		"kind and Kelvin-sign kind": "{\"type\":\"a\",\"amount\":\"1\",\"kind\":\"x\",\"\u212aind\":\"y\"}", // encoding/json folds the Kelvin sign to k
		"amount and AMOUNT":         `{"type":"a","amount":"1","AMOUNT":"1000"}`,
		"amount and amounT":         `{"type":"b","amounT":"1000","amount":"1"}`,
		"untagged, TYPE too":        `{"type":"c","TYPE":"c","amount":"1"}`,
	} {
		_, err := reg.Parse(json.RawMessage(`[` + detail + `]`))
		if err == nil {
			t.Errorf("%s: Parse(%s) = nil error, want refusal", name, detail)
		}
	}
	for _, detail := range []string{
		`{"type":"a","amount":"1"}`,
		`{"type":"c","amount":"1"}`, // untagged Type field: "type" still matches it
	} {
		if _, err := reg.Parse(json.RawMessage(`[` + detail + `]`)); err != nil {
			t.Errorf("Parse(%s) = %v, want nil", detail, err)
		}
	}

	_, err = reg.Parse(json.RawMessage(`[{"type":"a","TYPE":"b","amount":"1"}]`))
	if !errors.Is(err, extension.ErrDuplicateMember) {
		t.Errorf("Parse(type and TYPE) = %v, want ErrDuplicateMember", err)
	}
}
