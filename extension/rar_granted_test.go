package extension_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

var (
	grantedPayment = extension.RARDefinition[typedDetail]{Type: "payment", MaxObjects: 2, MaxBytesPerObject: 256}
	grantedAccess  = extension.RARDefinition[untypedDetail]{Type: "access", MaxObjects: 2, MaxBytesPerObject: 256}
)

func TestParseGrantedRARReadsEachType(t *testing.T) {
	granted, err := extension.ParseGrantedRAR(json.RawMessage(`[
		{"type":"payment","amount":"1.00"},
		{"type":"access","amount":"2.00"},
		{"type":"payment","amount":"3.00"},
		{"type":"unknown_here","anything":{"at":"all"}}
	]`))
	if err != nil {
		t.Fatalf("ParseGrantedRAR: %v", err)
	}
	payments, err := extension.RARGet(granted, grantedPayment)
	if err != nil || len(payments) != 2 || payments[0].Fields.Amount != "1.00" || payments[1].Fields.Amount != "3.00" {
		t.Errorf("RARGet(payment) = %+v, %v; want 1.00 and 3.00", payments, err)
	}
	access, err := extension.RARGet(granted, grantedAccess)
	if err != nil || len(access) != 1 || access[0].Fields.Amount != "2.00" {
		t.Errorf("RARGet(access) = %+v, %v; want 2.00 alone", access, err)
	}
}

func TestParseGrantedRARWithoutAClaimGrantsNothing(t *testing.T) {
	for _, claim := range []string{"", "null", " ", "[]"} {
		granted, err := extension.ParseGrantedRAR(json.RawMessage(claim))
		if err != nil {
			t.Errorf("ParseGrantedRAR(%q) = %v, want nil", claim, err)
			continue
		}
		if payments, err := extension.RARGet(granted, grantedPayment); err != nil || len(payments) != 0 {
			t.Errorf("ParseGrantedRAR(%q) granted %+v, %v; want nothing", claim, payments, err)
		}
	}
}

func TestParseGrantedRARRefusesAMalformedClaim(t *testing.T) {
	for name, claim := range map[string]string{
		"an object, not an array": `{"type":"payment"}`,
		"not JSON":                `[{"type":`,
		"a string in the array":   `["payment"]`,
		"no type":                 `[{"amount":"1.00"}]`,
		"an empty type":           `[{"type":"","amount":"1.00"}]`,
		"a type that isn't text":  `[{"type":7}]`,
		"type and TYPE":           `[{"type":"access","TYPE":"payment","amount":"1.00"}]`,
		"Type alone":              `[{"Type":"payment","amount":"1.00"}]`,
		"amount and AMOUNT":       `[{"type":"payment","amount":"1.00","AMOUNT":"1000.00"}]`,
	} {
		if _, err := extension.ParseGrantedRAR(json.RawMessage(claim)); err == nil {
			t.Errorf("%s: ParseGrantedRAR(%s) = nil error, want refusal", name, claim)
		}
	}
}

// FuzzParseGrantedRAR covers ParseGrantedRAR on any claim: it never
// panics, and what it accepts RARGet can read without panicking.
func FuzzParseGrantedRAR(f *testing.F) {
	f.Add([]byte(`[{"type":"payment","amount":"1.00"},{"type":"access"}]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[{"type":"payment","TYPE":"x"}]`))
	f.Fuzz(func(t *testing.T, claim []byte) {
		granted, err := extension.ParseGrantedRAR(claim)
		if err != nil {
			return
		}
		_, _ = extension.RARGet(granted, grantedPayment)
	})
}
