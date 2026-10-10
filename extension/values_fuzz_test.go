package extension_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

// firstExactAmount reads "amount" from a top-level JSON object by its
// exact name, keeping the first occurrence — what a first-wins,
// case-sensitive token reader would see.
func firstExactAmount(raw []byte) (json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, false
		}
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return nil, false
		}
		if k == "amount" {
			return v, true
		}
	}
	return nil, false
}

// FuzzExtensionValueReadersAgree: whenever Registry.Parse accepts an
// extension value (whose raw JSON is what goes into tokens verbatim),
// a first-wins and a last-wins case-sensitive reader of that raw value
// see the same amount Validate approved.
func FuzzExtensionValueReadersAgree(f *testing.F) {
	for _, s := range []string{`{"amount":10}`, `{"amount":1000000,"amount":10}`, `{"AMOUNT":1000000,"amount":10}`,
		`{"amount":10,"amount":1000}`, `{"amount":1e1}`, `{"amount":10.0}`, `{"amount":"10"}`, `{"amount":10,"payees":[{"name":"a"}]}`,
		`{"Amount":5}`, `{"amount":10 , "amount" : 10}`} {
		f.Add(s)
	}
	reg, err := extension.NewRegistry(cappedLimitDef)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		values, err := reg.Parse(map[string]json.RawMessage{"x_payment_limit": json.RawMessage(raw)}, nil, extension.SourcePlainParameter)
		if err != nil {
			return
		}
		got, ok := extension.Get(values, cappedLimitDef)
		if !ok {
			return
		}
		var last map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &last) != nil {
			t.Fatalf("accepted %q, which isn't a JSON object", raw)
		}
		first, _ := firstExactAmount([]byte(raw))
		for name, v := range map[string]json.RawMessage{"last": last["amount"], "first": first} {
			if v == nil {
				if got.Amount != 0 {
					t.Fatalf("accepted %q: Validate saw amount %d, a %s-wins exact reader sees none", raw, got.Amount, name)
				}
				continue
			}
			var n float64
			if json.Unmarshal(v, &n) != nil || n != float64(got.Amount) {
				t.Fatalf("accepted %q: Validate saw amount %d, a %s-wins exact reader sees %s", raw, got.Amount, name, v)
			}
		}
	})
}
