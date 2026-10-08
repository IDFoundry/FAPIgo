package extension_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

type paymentLimit struct {
	Amount int `json:"amount"`
	Payees []struct {
		Name string `json:"name"`
	} `json:"payees,omitempty"`
}

// cappedLimitDef caps amount at 100 in Validate: the value a token
// reader sees must be the value Validate approved.
var cappedLimitDef = extension.Definition[paymentLimit]{
	Sensitivity:    extension.NotSensitive,
	Name:           "x_payment_limit",
	Cardinality:    extension.Single,
	AllowedSources: extension.SourcePlainParameter,
	MaxBytes:       256,
	Validate: func(v paymentLimit) error {
		if v.Amount > 100 {
			return errors.New("amount over the cap")
		}
		return nil
	},
}

// TestRegistryParseRefusesRepeatedMembers: encoding/json keeps the last
// of a repeated member, matching names case-insensitively, while the raw
// value is what's stored and copied into tokens — so Validate could
// approve one amount and a token reader see another.
func TestRegistryParseRefusesRepeatedMembers(t *testing.T) {
	reg, err := extension.NewRegistry(cappedLimitDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	for name, raw := range map[string]string{
		"case variant":  `{"AMOUNT":1000000,"amount":10}`,
		"exact repeat":  `{"amount":1000000,"amount":10}`,
		"nested repeat": `{"amount":10,"payees":[{"name":"a","NAME":"b"}]}`,
		"lone miscased": `{"AMOUNT":10}`,
	} {
		t.Run(name, func(t *testing.T) {
			params := map[string]json.RawMessage{"x_payment_limit": json.RawMessage(raw)}
			if _, err := reg.Parse(params, nil, extension.SourcePlainParameter); err == nil {
				t.Fatalf("Parse(%s) = nil error, want it refused", raw)
			}
		})
	}
	t.Run("repeat reports ErrDuplicateMember", func(t *testing.T) {
		params := map[string]json.RawMessage{"x_payment_limit": json.RawMessage(`{"amount":1,"Amount":2}`)}
		if _, err := reg.Parse(params, nil, extension.SourcePlainParameter); !errors.Is(err, extension.ErrDuplicateMember) {
			t.Fatalf("Parse = %v, want ErrDuplicateMember", err)
		}
	})
	t.Run("well-formed value accepted", func(t *testing.T) {
		params := map[string]json.RawMessage{"x_payment_limit": json.RawMessage(`{"amount":10,"payees":[{"name":"a"}]}`)}
		values, err := reg.Parse(params, nil, extension.SourcePlainParameter)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if got, ok := extension.Get(values, cappedLimitDef); !ok || got.Amount != 10 {
			t.Fatalf("Get = %+v, %v; want amount 10", got, ok)
		}
	})
}

// repeatingMarshaler emits a repeated member from its own MarshalJSON.
type repeatingMarshaler struct{}

func (repeatingMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(`{"a":1,"A":2}`), nil
}

func TestSetRefusesRepeatedMembersFromMarshalJSON(t *testing.T) {
	def := extension.Definition[repeatingMarshaler]{
		Sensitivity: extension.NotSensitive,
		Name:        "x_repeating", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	var values extension.Values
	if err := extension.Set(&values, def, repeatingMarshaler{}); !errors.Is(err, extension.ErrDuplicateMember) {
		t.Fatalf("Set = %v, want ErrDuplicateMember", err)
	}
}
