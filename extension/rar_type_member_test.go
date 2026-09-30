package extension_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

// untypedDetail declares no "type" field, as RARSet's own doc comment
// says a detail type need not.
type untypedDetail struct {
	Amount string `json:"amount"`
}

type typeHolder struct {
	Type string `json:"type"`
}

// embeddedTypeDetail declares "type" through an embedded struct.
type embeddedTypeDetail struct {
	typeHolder
	Amount string `json:"amount"`
}

// untaggedTypeDetail's Type field matches "type" by name, as
// encoding/json matches it.
type untaggedTypeDetail struct {
	Type   string
	Amount string `json:"amount"`
}

func parseOne[T any](t *testing.T, def extension.RARDefinition[T], detail json.RawMessage) error {
	t.Helper()
	reg, err := extension.NewRARRegistry(4096, 4, def)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	arr, err := json.Marshal([]json.RawMessage{detail})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Parse(arr)
	return err
}

// TestRARSetOutputParses covers a detail type without a "type" field:
// RARSet adds the member, and Parse must accept its own output.
func TestRARSetOutputParses(t *testing.T) {
	def := extension.RARDefinition[untypedDetail]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 256}
	raw, err := extension.RARSet(def, untypedDetail{Amount: "1.00"})
	if err != nil {
		t.Fatalf("RARSet: %v", err)
	}
	if err := parseOne(t, def, raw); err != nil {
		t.Fatalf("Parse(RARSet output %s) = %v, want nil", raw, err)
	}
}

func TestRARParseStillRejectsUnknownMembers(t *testing.T) {
	def := extension.RARDefinition[untypedDetail]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 256}
	for name, raw := range map[string]string{
		"another member":           `{"type":"payment","amount":"1.00","payee":"x"}`,
		"type in a different case": `{"type":"payment","TYPE":"payment","amount":"1.00"}`,
	} {
		if err := parseOne(t, def, json.RawMessage(raw)); err == nil {
			t.Errorf("Parse(%s) = nil, want an unknown-member error", name)
		}
	}
}

func TestRARParseDeclaredTypeMember(t *testing.T) {
	const raw = `{"type":"payment","amount":"1.00"}`
	embedded := extension.RARDefinition[embeddedTypeDetail]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 256}
	if err := parseOne(t, embedded, json.RawMessage(raw)); err != nil {
		t.Errorf("Parse(embedded type field) = %v, want nil", err)
	}
	untagged := extension.RARDefinition[untaggedTypeDetail]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 256}
	if err := parseOne(t, untagged, json.RawMessage(raw)); err != nil {
		t.Errorf("Parse(untagged Type field) = %v, want nil", err)
	}
	// A type that declares "type" sees it, so Validate can check it.
	var seen string
	checked := extension.RARDefinition[embeddedTypeDetail]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 256,
		Validate: func(d embeddedTypeDetail) error { seen = d.Type; return nil }}
	if err := parseOne(t, checked, json.RawMessage(raw)); err != nil || seen != "payment" {
		t.Errorf("Validate saw type %q (err %v), want payment", seen, err)
	}
}
