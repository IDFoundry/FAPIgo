package extension_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/strictjson"
)

// fuzzCredentialDetail declares no "type" field, so its objects take
// decodeCheck's withoutTypeMember path; credential_identifier is a
// member only the authorization server may set.
type fuzzCredentialDetail struct {
	Actions              []string `json:"actions,omitempty"`
	CredentialIdentifier string   `json:"credential_identifier,omitempty"`
	Limit                *float64 `json:"limit,omitempty"`
}

var (
	errForbiddenAction   = errors.New("forbidden action")
	errServerOnlyMember  = errors.New("credential_identifier is the server's to set")
	errRequestOutOfOrder = errors.New("ValidateRequest ran on a value Validate refuses")
)

func validateFuzzCredential(v fuzzCredentialDetail) error {
	if slices.Contains(v.Actions, "forbidden") {
		return errForbiddenAction
	}
	return nil
}

var fuzzCredentialDef = extension.RARDefinition[fuzzCredentialDetail]{
	Type: "credential", MaxObjects: 3, MaxBytesPerObject: 256,
	Validate: validateFuzzCredential,
	ValidateRequest: func(v fuzzCredentialDetail) error {
		if validateFuzzCredential(v) != nil {
			return errRequestOutOfOrder
		}
		if v.CredentialIdentifier != "" {
			return errServerOnlyMember
		}
		return nil
	},
}

// FuzzRARRegistryParseRequest checks RARRegistry.ParseRequest against
// Parse on the same client-supplied authorization_details. Beyond never
// panicking:
//
//   - ValidateRequest runs only after Validate has accepted a value;
//   - ParseRequest accepts only what Parse accepts, with the same
//     values; of what Parse accepts, it refuses all that encoding/json
//     would alter (invalid UTF-8, an unpaired surrogate escape), and
//     otherwise only for ValidateRequest's own reason, exactly when an
//     object sets the server-only member;
//   - every object Parse accepts passes its type's Validate, and the
//     accepted values survive MarshalJSON and UnmarshalJSON (how a
//     server stores them with an interaction) unchanged for RARGet.
func FuzzRARRegistryParseRequest(f *testing.F) {
	reg, err := extension.NewRARRegistry(1024, 4, fuzzCredentialDef, fuzzAccountDef)
	if err != nil {
		f.Fatalf("NewRARRegistry: %v", err)
	}
	f.Add([]byte(`[{"type":"credential","actions":["issue"]}]`))
	f.Add([]byte(`[{"type":"credential","credential_identifier":"id-1"}]`))
	f.Add([]byte(`[{"type":"credential","actions":["forbidden"],"credential_identifier":"id-1"}]`))
	f.Add([]byte(`[{"type":"credential","CREDENTIAL_IDENTIFIER":"id-1"}]`))
	f.Add([]byte(`[{"type":"credential","limit":1e400}]`))
	f.Add([]byte(`[{"type":"account_information","actions":["list_accounts"]},{"type":"credential","limit":2}]`))
	f.Add([]byte(`[{"type":"credential","type":"account_information"}]`))
	f.Add([]byte(`[{"type":"credential","actions":["\ud800"]}]`))
	f.Add([]byte("[{\"type\":\"credential\",\"actions\":[\"\xff\"]}]"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		parsed, parseErr := reg.Parse(raw)
		requested, requestErr := reg.ParseRequest(raw)
		if errors.Is(requestErr, errRequestOutOfOrder) {
			t.Fatalf("ParseRequest(%q) ran ValidateRequest before Validate", raw)
		}
		if parseErr != nil {
			if requestErr == nil {
				t.Fatalf("ParseRequest accepted %q, which Parse refuses: %v", raw, parseErr)
			}
			return
		}
		if !strictjson.DecodesLosslessly(raw) {
			if requestErr == nil {
				t.Fatalf("ParseRequest accepted %q, which encoding/json would alter", raw)
			}
			return
		}
		credentials := checkParsedCredentials(t, parsed)
		setsServerMember := slices.ContainsFunc(credentials, func(d extension.RARDetail[fuzzCredentialDetail]) bool {
			return d.Fields.CredentialIdentifier != ""
		})
		if (requestErr != nil) != setsServerMember || (requestErr != nil && !errors.Is(requestErr, errServerOnlyMember)) {
			t.Fatalf("ParseRequest(%q) = %v, with the server-only member set: %v", raw, requestErr, setsServerMember)
		}
		if requestErr == nil {
			checkSameRARValues(t, parsed, requested)
		}
		checkRARValuesStoreRoundTrip(t, parsed)
	})
}

// checkParsedCredentials reads parsed's credential objects back, and
// checks each passes Validate.
func checkParsedCredentials(t *testing.T, parsed extension.RARValues) []extension.RARDetail[fuzzCredentialDetail] {
	t.Helper()
	credentials, err := extension.RARGet(parsed, fuzzCredentialDef)
	if err != nil {
		t.Fatalf("RARGet of values Parse accepted: %v", err)
	}
	for _, d := range credentials {
		if err := validateFuzzCredential(d.Fields); err != nil {
			t.Fatalf("Parse accepted %+v, which Validate refuses: %v", d.Fields, err)
		}
	}
	return credentials
}

func checkSameRARValues(t *testing.T, a, b extension.RARValues) {
	t.Helper()
	aj, aerr := a.MarshalJSON()
	bj, berr := b.MarshalJSON()
	if aerr != nil || berr != nil || !bytes.Equal(aj, bj) {
		t.Fatalf("values differ: %s (%v) and %s (%v)", aj, aerr, bj, berr)
	}
}

// checkRARValuesStoreRoundTrip checks values read the same through
// RARGet after MarshalJSON and UnmarshalJSON.
func checkRARValuesStoreRoundTrip(t *testing.T, values extension.RARValues) {
	t.Helper()
	stored, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var restored extension.RARValues
	if err := json.Unmarshal(stored, &restored); err != nil {
		t.Fatalf("UnmarshalJSON(%s): %v", stored, err)
	}
	for _, read := range []func(extension.RARValues) (any, error){
		func(v extension.RARValues) (any, error) { return extension.RARGet(v, fuzzCredentialDef) },
		func(v extension.RARValues) (any, error) { return extension.RARGet(v, fuzzAccountDef) },
	} {
		before, err1 := read(values)
		after, err2 := read(restored)
		bj, _ := json.Marshal(before)
		aj, _ := json.Marshal(after)
		if err1 != nil || err2 != nil || !bytes.Equal(bj, aj) {
			t.Fatalf("stored values read back as %s (%v), want %s (%v)", aj, err2, bj, err1)
		}
	}
}
