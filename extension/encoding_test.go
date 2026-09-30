package extension_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

func TestRARValuesJSONRoundTrip(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef)
	if err != nil {
		t.Fatal(err)
	}
	values, err := reg.Parse(json.RawMessage(`[{"type":"payment_initiation","instructed_amount":"1.00"},{"type":"payment_initiation","instructed_amount":"2.00"}]`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var restored extension.RARValues
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(restored, values) {
		t.Errorf("restored %+v, want %+v", restored, values)
	}
	details, err := extension.RARGet(restored, paymentDef)
	if err != nil || len(details) != 2 || details[1].Fields.InstructedAmt != "2.00" {
		t.Errorf("RARGet(restored) = %+v, %v", details, err)
	}

	var zero extension.RARValues
	if raw, _ := json.Marshal(zero); string(raw) != "[]" {
		t.Errorf("Marshal(zero) = %s, want []", raw)
	}
	if err := json.Unmarshal([]byte(`[]`), &restored); err != nil || !reflect.DeepEqual(restored, zero) {
		t.Errorf("Unmarshal([]) = %+v, %v; want the zero value", restored, err)
	}
	for _, bad := range []string{`{}`, `[{"amount":"1"}]`, `[1]`} {
		if err := json.Unmarshal([]byte(bad), &restored); err == nil {
			t.Errorf("Unmarshal(%s) = nil error, want error", bad)
		}
	}
}

func TestValuesJSONRoundTrip(t *testing.T) {
	var values extension.Values
	if err := extension.Set(&values, accountHintDef, accountHint{AccountID: "acct-1"}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var restored extension.Values
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(restored, values) {
		t.Errorf("restored %+v, want %+v", restored, values)
	}

	var zero extension.Values
	if raw, _ := json.Marshal(zero); string(raw) != "{}" {
		t.Errorf("Marshal(zero) = %s, want {}", raw)
	}
	if err := json.Unmarshal([]byte(`{}`), &restored); err != nil || !reflect.DeepEqual(restored, zero) {
		t.Errorf("Unmarshal({}) = %+v, %v; want the zero value", restored, err)
	}
	if err := json.Unmarshal([]byte(`[]`), &restored); err == nil {
		t.Error("Unmarshal([]) = nil error, want error")
	}
}
