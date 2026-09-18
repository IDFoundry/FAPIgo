package extension_test

import (
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

type fuzzAccountDetail struct {
	Type    string   `json:"type"`
	Actions []string `json:"actions"`
}

var fuzzAccountDef = extension.RARDefinition[fuzzAccountDetail]{
	Type: "account_information", MaxObjects: 3, MaxBytesPerObject: 512,
}

// FuzzRARRegistryParse exercises RARRegistry.Parse against arbitrary
// bytes — the authorization_details parameter (RFC 9396) is
// client-supplied, unsigned JSON, parsed before any authorization
// decision. Unlike every other fuzz target in this repo, this one
// involves no JWT/signature at all: Parse's own doc comment describes
// what it enforces beyond plain JSON decoding — total size and nesting
// depth bounds, no duplicate top-level members per object, a registered
// type with its own size/count bounds, and strict (DisallowUnknownFields)
// decoding against that type's own Go shape. Registered with two types
// so the fuzzer can exercise cross-type dispatch, not just a single
// type's own decodeCheck. Only checks for panics/hangs.
func FuzzRARRegistryParse(f *testing.F) {
	reg, err := extension.NewRARRegistry(4096, 4, paymentDef, fuzzAccountDef)
	if err != nil {
		f.Fatalf("NewRARRegistry: %v", err)
	}

	f.Add([]byte(`[{"type":"payment_initiation","instructed_amount":"100.00"}]`))
	f.Add([]byte(`[{"type":"account_information","actions":["list_accounts","read_balances"]}]`))
	f.Add([]byte(`[{"type":"payment_initiation","instructed_amount":"1.00"},{"type":"account_information","actions":["list_accounts"]}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"type":"unregistered_type"}]`))
	f.Add([]byte(`[{"type":"payment_initiation","instructed_amount":"1.00","unexpected_field":true}]`))
	f.Add([]byte(`[{"type":"payment_initiation"},{"type":"payment_initiation"}]`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = reg.Parse(raw)
	})
}
