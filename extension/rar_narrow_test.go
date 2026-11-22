package extension_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

// The detail types below each hold a member encoding/json reads the same
// way when it's left out, null or the zero value: what a grant holds
// explicitly, the strictest value there is, is lost when the object is
// decoded into the type.
type (
	narrowLimit struct {
		Account string `json:"account"`
		Limit   int    `json:"limit"`
	}
	narrowFlag struct {
		Account       string `json:"account"`
		International bool   `json:"international"`
	}
	narrowNested struct {
		Account     string `json:"account"`
		Constraints struct {
			MaxPayments int `json:"maxPayments"`
		} `json:"constraints"`
	}
	narrowFloat struct {
		Account float64 `json:"account"`
	}
	narrowActions struct {
		Account string   `json:"account"`
		Actions []string `json:"actions,omitempty"`
	}
)

// exactRARRegistry registers the type "p", held in T, with no hooks, so
// the default exact match judges it.
func exactRARRegistry[T any](t *testing.T) *extension.RARRegistry {
	t.Helper()
	reg, err := extension.NewRARRegistry(4096, 4, extension.RARDefinition[T]{Type: "p", MaxObjects: 3, MaxBytesPerObject: 512})
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return reg
}

// rarObjects is raw, an authorization_details array, split into its
// objects.
func rarObjects(t *testing.T, raw string) []json.RawMessage {
	t.Helper()
	var objects []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &objects); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return objects
}

// mustNarrow is Narrow of granted to narrowed, both arrays, failing t
// unless it accepts.
func mustNarrow(t *testing.T, reg *extension.RARRegistry, granted, narrowed string) string {
	t.Helper()
	issued, err := reg.Narrow(mustParseRAR(t, reg, granted), rarObjects(t, narrowed), nil)
	if err != nil {
		t.Fatalf("Narrow(%s, %s): %v", granted, narrowed, err)
	}
	return string(issued)
}

// TestRARRegistryNarrowIssuesTheGrantedObject: where only the exact match
// judges an object, Narrow issues the granted object it matched, as
// granted holds it. The exact match compares the two decoded into the
// type's Go value, where a member left out, null or -0 reads as the zero
// value a grant holds, and numbers that round to the same float64 read
// as one, so the narrowed object's own bytes may say less than the
// grant.
func TestRARRegistryNarrowIssuesTheGrantedObject(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reg      *extension.RARRegistry
		granted  string
		narrowed []string
	}{
		{"int zero", exactRARRegistry[narrowLimit](t), `[{"account":"a","limit":0,"type":"p"}]`, []string{
			`[{"type":"p","account":"a"}]`,
			`[{"type":"p","account":"a","limit":null}]`,
			`[{"type":"p","account":"a","limit":-0}]`,
			`[{"limit":0,"type":"p","account":"a"}]`,
		}},
		{"bool false", exactRARRegistry[narrowFlag](t), `[{"account":"a","international":false,"type":"p"}]`, []string{
			`[{"type":"p","account":"a"}]`,
			`[{"type":"p","account":"a","international":null}]`,
		}},
		{"zero nested struct", exactRARRegistry[narrowNested](t), `[{"account":"a","constraints":{"maxPayments":0},"type":"p"}]`, []string{
			`[{"type":"p","account":"a"}]`,
			`[{"type":"p","account":"a","constraints":{}}]`,
			`[{"type":"p","account":"a","constraints":null}]`,
		}},
		{"float64", exactRARRegistry[narrowFloat](t), `[{"account":12345678901234568,"type":"p"}]`, []string{
			`[{"type":"p","account":12345678901234567}]`,
			`[{"type":"p","account":12345678901234569}]`,
			`[{"type":"p","account":1.2345678901234568e16}]`,
		}},
		{"map[string]any number", exactRARRegistry[map[string]any](t), `[{"account":12345678901234568,"limit":0,"type":"p"}]`, []string{
			`[{"type":"p","account":12345678901234569,"limit":0}]`,
			`[{"limit":0.0,"account":12345678901234567,"type":"p"}]`,
		}},
		{"omitempty empty list", exactRARRegistry[narrowActions](t), `[{"type":"p","account":"a","actions":[]}]`, []string{
			`[{"type":"p","account":"a"}]`,
			`[{"type":"p","account":"a","actions":null}]`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, narrowed := range tc.narrowed {
				if got := mustNarrow(t, tc.reg, tc.granted, narrowed); got != tc.granted {
					t.Errorf("Narrow(%s, %s) = %s, want the grant", tc.granted, narrowed, got)
				}
			}
		})
	}
}

// TestRARRegistryNarrowKeepsTheOrderAndEachMatch: Narrow issues
// narrowed's objects in narrowed's own order, each the granted object it
// matched. Of two granted objects the exact match can't tell apart, each
// narrowed object takes one, so each is issued once, as granted holds
// it, and a third is refused.
func TestRARRegistryNarrowKeepsTheOrderAndEachMatch(t *testing.T) {
	reg := exactRARRegistry[narrowLimit](t)
	const (
		twoAccounts = `[{"account":"a","limit":0,"type":"p"},{"account":"b","limit":0,"type":"p"}]`
		twins       = `[{"account":"a","limit":0,"type":"p"},{"type":"p","account":"a"}]`
		oneA        = `{"type":"p","account":"a","limit":null}`
	)
	for _, tc := range []struct {
		name, granted, narrowed, want string
	}{
		{"reversed", twoAccounts, `[{"type":"p","account":"b"},` + oneA + `]`, `[{"account":"b","limit":0,"type":"p"},{"account":"a","limit":0,"type":"p"}]`},
		{"one of twins", twins, `[` + oneA + `]`, `[{"account":"a","limit":0,"type":"p"}]`},
		{"both twins", twins, `[` + oneA + `,` + oneA + `]`, twins},
	} {
		if got := mustNarrow(t, reg, tc.granted, tc.narrowed); got != tc.want {
			t.Errorf("%s: Narrow(%s, %s) = %s, want %s", tc.name, tc.granted, tc.narrowed, got, tc.want)
		}
	}
	_, err := reg.Narrow(mustParseRAR(t, reg, twins), rarObjects(t, `[`+oneA+`,`+oneA+`,`+oneA+`]`), nil)
	if !errors.Is(err, extension.ErrRARGrantExceedsRequest) {
		t.Fatalf("Narrow(a third of twins) = %v, want errors.Is ErrRARGrantExceedsRequest", err)
	}
}

// lowerNarrowLimit lets a narrowed object lower the granted limit on the
// same account.
func lowerNarrowLimit(granted, narrowed narrowLimit) error {
	if narrowed.Account != granted.Account || narrowed.Limit > granted.Limit {
		return extension.ErrRARGrantExceedsRequest
	}
	return nil
}

// TestRARRegistryNarrowIssuesWhatAHookJudged: under a ValidateNarrowing
// hook, or a ValidateGrant hook it falls back to, Narrow issues the
// object the client sent, the one the hook judged, compacted but
// otherwise as sent. In an array mixing types, each object is issued by
// its own type's rule, in narrowed's order.
func TestRARRegistryNarrowIssuesWhatAHookJudged(t *testing.T) {
	reg, err := extension.NewRARRegistry(4096, 4,
		extension.RARDefinition[narrowLimit]{Type: "narrowing", MaxObjects: 1, MaxBytesPerObject: 512, ValidateNarrowing: lowerNarrowLimit},
		extension.RARDefinition[narrowLimit]{Type: "grant", MaxObjects: 1, MaxBytesPerObject: 512, ValidateGrant: lowerNarrowLimit},
		extension.RARDefinition[narrowLimit]{Type: "exact", MaxObjects: 1, MaxBytesPerObject: 512},
	)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	const (
		granted  = `[{"type":"narrowing","account":"a","limit":50},{"type":"exact","account":"a","limit":0},{"type":"grant","account":"a","limit":50}]`
		narrowed = `[{"type":"grant", "account":"a", "limit":20}, {"type":"exact","account":"a"}, {"account":"a","type":"narrowing"}]`
		want     = `[{"type":"grant","account":"a","limit":20},{"type":"exact","account":"a","limit":0},{"account":"a","type":"narrowing"}]`
	)
	if got := mustNarrow(t, reg, granted, narrowed); got != want {
		t.Fatalf("Narrow(%s, %s) = %s, want %s", granted, narrowed, got, want)
	}
}

// keepAllRARRegistry registers narrowLimit as "p", at most two objects,
// refusing every omission, and returns it with a grant of two of them.
func keepAllRARRegistry(t *testing.T) (*extension.RARRegistry, extension.RARValues) {
	t.Helper()
	reg, err := extension.NewRARRegistry(4096, 4, extension.RARDefinition[narrowLimit]{
		Type: "p", MaxObjects: 2, MaxBytesPerObject: 512, ValidateOmission: refuseOmission[narrowLimit],
	})
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return reg, mustParseRAR(t, reg, `[{"account":"a","limit":0,"type":"p"},{"account":"b","limit":0,"type":"p"}]`)
}

// TestRARRegistryNarrowRefuses: Narrow refuses what ValidateNarrowing
// refuses, and what Parse refuses of narrowed's objects, with their
// errors.
func TestRARRegistryNarrowRefuses(t *testing.T) {
	reg, granted := keepAllRARRegistry(t)
	for _, tc := range []struct {
		name     string
		narrowed []json.RawMessage
		want     error
	}{
		{"wider", rarObjects(t, `[{"type":"p","account":"a","limit":1},{"type":"p","account":"b"}]`), extension.ErrRARGrantExceedsRequest},
		{"one left out", rarObjects(t, `[{"type":"p","account":"a"}]`), extension.ErrRAROmissionRefused},
		{"empty", nil, extension.ErrRAROmissionRefused},
		{"unregistered type", rarObjects(t, `[{"type":"q"}]`), extension.ErrRARUnregisteredType},
		{"too many", rarObjects(t, `[{"type":"p","account":"a"},{"type":"p","account":"b"},{"type":"p","account":"c"}]`), extension.ErrRARTooManyObjects},
	} {
		if issued, err := reg.Narrow(granted, tc.narrowed, nil); !errors.Is(err, tc.want) || issued != nil {
			t.Errorf("%s: Narrow = %s, %v; want errors.Is %v", tc.name, issued, err, tc.want)
		}
	}
}

// TestRARRegistryNarrowRefusesMalformedObjects: Narrow refuses a
// narrowed object Parse wouldn't decode, or that isn't JSON at all.
func TestRARRegistryNarrowRefusesMalformedObjects(t *testing.T) {
	reg, granted := keepAllRARRegistry(t)
	for name, narrowed := range map[string][]json.RawMessage{
		"unknown member": rarObjects(t, `[{"type":"p","account":"a","extra":true},{"type":"p","account":"b"}]`),
		"not JSON":       {json.RawMessage(`{"type":"p"`)},
	} {
		if issued, err := reg.Narrow(granted, narrowed, nil); err == nil || issued != nil {
			t.Errorf("%s: Narrow = %s, %v; want an error", name, issued, err)
		}
	}
}

// TestRARRegistryNarrowToNothing: an empty narrowed that every omission
// allows issues no authorization_details at all.
func TestRARRegistryNarrowToNothing(t *testing.T) {
	reg := exactRARRegistry[narrowLimit](t)
	granted := mustParseRAR(t, reg, `[{"account":"a","limit":0,"type":"p"}]`)
	for _, narrowed := range [][]json.RawMessage{nil, {}} {
		if issued, err := reg.Narrow(granted, narrowed, nil); err != nil || issued != nil {
			t.Errorf("Narrow(%q) = %s, %v; want nil, nil", narrowed, issued, err)
		}
	}
}
