package extension_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

// mintedDetail has a member, "minted", that only the authorization server
// may set: a client must not supply it, but a grant may carry it.
type mintedDetail struct {
	Type    string `json:"type"`
	Amount  string `json:"amount"`
	Minted  string `json:"minted,omitempty"`
	Invalid bool   `json:"invalid,omitempty"`
}

var (
	errMintedInvalid   = errors.New("invalid is set")
	errMintedByRequest = errors.New("minted is set by the authorization server")
)

// mintedDef records the order its hooks run in.
func mintedDef(calls *[]string) extension.RARDefinition[mintedDetail] {
	return extension.RARDefinition[mintedDetail]{
		Type: "minted", MaxObjects: 2, MaxBytesPerObject: 512,
		Validate: func(v mintedDetail) error {
			*calls = append(*calls, "Validate")
			if v.Invalid {
				return errMintedInvalid
			}
			return nil
		},
		ValidateRequest: func(v mintedDetail) error {
			*calls = append(*calls, "ValidateRequest")
			if v.Minted != "" {
				return errMintedByRequest
			}
			return nil
		},
	}
}

func TestRARRegistryParseRequestAppliesValidateRequest(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       string
		wantErr   error
		wantCalls []string
	}{
		{"accepted", `[{"type":"minted","amount":"1"}]`, nil, []string{"Validate", "ValidateRequest"}},
		{"server-only member", `[{"type":"minted","amount":"1","minted":"id-1"}]`, errMintedByRequest, []string{"Validate", "ValidateRequest"}},
		{"Validate first", `[{"type":"minted","amount":"1","minted":"id-1","invalid":true}]`, errMintedInvalid, []string{"Validate"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			reg, err := extension.NewRARRegistry(4096, 4, mintedDef(&calls))
			if err != nil {
				t.Fatalf("NewRARRegistry: %v", err)
			}
			_, err = reg.ParseRequest(json.RawMessage(tc.raw))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseRequest error = %v, want %v", err, tc.wantErr)
			}
			if !slices.Equal(calls, tc.wantCalls) {
				t.Fatalf("hooks ran %v, want %v", calls, tc.wantCalls)
			}
		})
	}
}

func TestRARRegistryParseIgnoresValidateRequest(t *testing.T) {
	var calls []string
	def := mintedDef(&calls)
	reg, err := extension.NewRARRegistry(4096, 4, def)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	values, err := reg.Parse(json.RawMessage(`[{"type":"minted","amount":"1","minted":"id-1"}]`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !slices.Equal(calls, []string{"Validate"}) {
		t.Fatalf("hooks ran %v, want only Validate", calls)
	}
	details, err := extension.RARGet(values, def)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 1 || details[0].Fields.Minted != "id-1" {
		t.Fatalf("details = %+v, want the minted member kept", details)
	}
}

// ParseRequest refuses authorization_details encoding/json would alter —
// invalid UTF-8, or an unpaired surrogate escape — while Parse, which
// reads details already stored or granted, still accepts them, so a
// grant or request stored before ParseRequest refused them is still
// read. Non-ASCII that decodes as written is accepted by both.
func TestRARRegistryParseRequestRefusesLossyJSON(t *testing.T) {
	var calls []string
	reg, err := extension.NewRARRegistry(4096, 4, mintedDef(&calls))
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	detail := func(amount string) json.RawMessage {
		return json.RawMessage(`[{"type":"minted","amount":` + amount + `}]`)
	}
	for _, amount := range []string{"\"SGD \xff\"", `"SGD \ud800"`, `"SGD \udc00"`, `"\ud83d"`} {
		if _, err := reg.ParseRequest(detail(amount)); err == nil {
			t.Errorf("ParseRequest(%q) accepted it, want an error", amount)
		}
		if _, err := reg.Parse(detail(amount)); err != nil {
			t.Errorf("Parse(%q) = %v, want it read as stored", amount, err)
		}
	}
	for _, amount := range []string{`"SGD €"`, `"é"`, `"😀"`, `"😀"`, `"é"`} {
		if _, err := reg.ParseRequest(detail(amount)); err != nil {
			t.Errorf("ParseRequest(%q) = %v, want it accepted", amount, err)
		}
	}
}
