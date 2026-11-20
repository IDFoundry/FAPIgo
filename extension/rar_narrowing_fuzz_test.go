package extension_test

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

// plainCredentialDef is fuzzCredentialDef without any hook, so granting
// and narrowing are exact matches.
var plainCredentialDef = extension.RARDefinition[fuzzCredentialDetail]{Type: "credential", MaxObjects: 3, MaxBytesPerObject: 256}

// subsetCredentialDef lets a grant drop actions, and nothing else.
var subsetCredentialDef = extension.RARDefinition[fuzzCredentialDetail]{
	Type: "credential", MaxObjects: 3, MaxBytesPerObject: 256,
	ValidateGrant: func(requested, granted fuzzCredentialDetail) error {
		if granted.CredentialIdentifier != requested.CredentialIdentifier || !sameLimit(granted.Limit, requested.Limit) {
			return extension.ErrRARGrantExceedsRequest
		}
		for _, a := range granted.Actions {
			if !slices.Contains(requested.Actions, a) {
				return extension.ErrRARGrantExceedsRequest
			}
		}
		return nil
	},
}

func sameLimit(a, b *float64) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// refuseOmission is a ValidateOmission that lets no granted object be
// left out.
func refuseOmission[T any](T, []string) error {
	return errors.New("may not be left out")
}

// FuzzRARValidateNarrowing checks RARRegistry.ValidateNarrowing and
// ValidateGrant on two authorization_details arrays Parse accepts — a
// grant, and what a client asks for at the token endpoint. Beyond never
// panicking:
//
//   - with no hooks, the two agree, and accept exactly when, type by
//     type, every narrowed object's canonical encoding matches a
//     distinct granted object's: the narrowed objects are a sub-multiset
//     of the granted ones, so greedy matching never lets two narrowed
//     objects use one granted object;
//   - with or without hooks, a grant always narrows to itself, and
//     ValidateNarrowing falls back to ValidateGrant's hook;
//   - with every omission refused (ValidateOmission), it accepts exactly
//     when the narrowed objects are the granted ones, canonically, in
//     any order: whatever greedy matching leaves unmatched is left out.
func FuzzRARValidateNarrowing(f *testing.F) {
	plain, err := extension.NewRARRegistry(1024, 4, plainCredentialDef, fuzzAccountDef)
	if err != nil {
		f.Fatalf("NewRARRegistry: %v", err)
	}
	subset, err := extension.NewRARRegistry(1024, 4, subsetCredentialDef, fuzzAccountDef)
	if err != nil {
		f.Fatalf("NewRARRegistry: %v", err)
	}
	keepCredentials, keepAccounts := plainCredentialDef, fuzzAccountDef
	keepCredentials.ValidateOmission = refuseOmission[fuzzCredentialDetail]
	keepAccounts.ValidateOmission = refuseOmission[fuzzAccountDetail]
	keepAll, err := extension.NewRARRegistry(1024, 4, keepCredentials, keepAccounts)
	if err != nil {
		f.Fatalf("NewRARRegistry: %v", err)
	}
	f.Add([]byte(`[{"type":"credential","actions":["a","b"]},{"type":"credential","actions":["a"]}]`), []byte(`[{"type":"credential","actions":["a"]}]`))
	f.Add([]byte(`[{"type":"credential","actions":["a"]}]`), []byte(`[{"type":"credential","actions":["a"]},{"type":"credential","actions":["a"]}]`))
	f.Add([]byte(`[{"type":"credential","limit":1.0}]`), []byte(`[{"type":"credential","limit":1}]`))
	f.Add([]byte(`[{"type":"credential","actions":[]}]`), []byte(`[{"actions":null,"type":"credential"}]`))
	f.Add([]byte(`[{"type":"account_information","actions":["x"]}]`), []byte(`[{"type":"credential"}]`))
	f.Add([]byte(`[]`), []byte(`[]`))
	f.Add([]byte(`[{"type":"credential","actions":["a"]},{"type":"credential","actions":["b"]}]`), []byte(`[{"type":"credential","actions":["b"]},{"type":"credential","actions":["a"]}]`))
	f.Add([]byte(`[{"type":"credential","actions":["a"]},{"type":"account_information","actions":["x"]}]`), []byte(`[]`))
	f.Fuzz(func(t *testing.T, grantedRaw, narrowedRaw []byte) {
		checkExactNarrowing(t, plain, grantedRaw, narrowedRaw)
		checkHookedNarrowing(t, subset, grantedRaw, narrowedRaw)
		checkOmissionsRefused(t, keepAll, grantedRaw, narrowedRaw)
	})
}

// checkOmissionsRefused checks that, with every omission refused,
// ValidateNarrowing accepts exactly when narrowed keeps every granted
// object, and refuses a narrowing that leaves one out as an omission.
func checkOmissionsRefused(t *testing.T, reg *extension.RARRegistry, grantedRaw, narrowedRaw []byte) {
	t.Helper()
	granted, err1 := reg.Parse(grantedRaw)
	narrowed, err2 := reg.Parse(narrowedRaw)
	if err1 != nil || err2 != nil {
		return
	}
	err := reg.ValidateNarrowing(granted, narrowed, nil)
	want := maps.Equal(canonicalCounts(t, granted), canonicalCounts(t, narrowed))
	if (err == nil) != want {
		t.Fatalf("with every omission refused, ValidateNarrowing(%s, %s) = %v, want acceptance %v", grantedRaw, narrowedRaw, err, want)
	}
	if err != nil && canonicalSubMultiset(t, granted, narrowed) && !errors.Is(err, extension.ErrRAROmissionRefused) {
		t.Fatalf("ValidateNarrowing(%s, %s) leaving out an object = %v, want ErrRAROmissionRefused", grantedRaw, narrowedRaw, err)
	}
}

func checkExactNarrowing(t *testing.T, reg *extension.RARRegistry, grantedRaw, narrowedRaw []byte) {
	t.Helper()
	granted, err1 := reg.Parse(grantedRaw)
	narrowed, err2 := reg.Parse(narrowedRaw)
	if err1 != nil || err2 != nil {
		return
	}
	narrowErr := reg.ValidateNarrowing(granted, narrowed, nil)
	grantErr := reg.ValidateGrant(granted, narrowed)
	if (narrowErr == nil) != (grantErr == nil) {
		t.Fatalf("with no hooks, ValidateNarrowing = %v but ValidateGrant = %v for %s narrowed to %s", narrowErr, grantErr, grantedRaw, narrowedRaw)
	}
	want := canonicalSubMultiset(t, granted, narrowed)
	if (narrowErr == nil) != want {
		t.Fatalf("ValidateNarrowing(%s, %s) = %v, want acceptance %v", grantedRaw, narrowedRaw, narrowErr, want)
	}
	if err := reg.ValidateNarrowing(granted, granted, nil); err != nil {
		t.Fatalf("grant %s doesn't narrow to itself: %v", grantedRaw, err)
	}
}

func checkHookedNarrowing(t *testing.T, reg *extension.RARRegistry, grantedRaw, narrowedRaw []byte) {
	t.Helper()
	granted, err1 := reg.Parse(grantedRaw)
	narrowed, err2 := reg.Parse(narrowedRaw)
	if err1 != nil || err2 != nil {
		return
	}
	if err := reg.ValidateNarrowing(granted, granted, nil); err != nil {
		t.Fatalf("grant %s doesn't narrow to itself under a hook: %v", grantedRaw, err)
	}
	narrowErr := reg.ValidateNarrowing(granted, narrowed, nil)
	grantErr := reg.ValidateGrant(granted, narrowed)
	if (narrowErr == nil) != (grantErr == nil) {
		t.Fatalf("with no ValidateNarrowing hook, ValidateNarrowing = %v but ValidateGrant = %v", narrowErr, grantErr)
	}
}

// canonicalSubMultiset reports whether, per registered type, the
// canonical encodings of narrowed's objects are a sub-multiset of
// granted's.
func canonicalSubMultiset(t *testing.T, granted, narrowed extension.RARValues) bool {
	t.Helper()
	available := canonicalCounts(t, granted)
	for key, n := range canonicalCounts(t, narrowed) {
		if available[key] < n {
			return false
		}
	}
	return true
}

// canonicalCounts counts values' objects by type and canonical
// encoding: the object decoded into its type's Go value and encoded
// again.
func canonicalCounts(t *testing.T, values extension.RARValues) map[string]int {
	t.Helper()
	counts := map[string]int{}
	credentials, err1 := extension.RARGet(values, plainCredentialDef)
	accounts, err2 := extension.RARGet(values, fuzzAccountDef)
	if err1 != nil || err2 != nil {
		t.Fatalf("RARGet of parsed values: %v, %v", err1, err2)
	}
	for _, d := range credentials {
		enc, _ := json.Marshal(d.Fields)
		counts["credential "+string(enc)]++
	}
	for _, d := range accounts {
		enc, _ := json.Marshal(d.Fields)
		counts["account "+string(enc)]++
	}
	return counts
}
