package extension_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

// mintedIDsDetail has a member, "ids", that only the authorization server
// sets: consent may add identifiers to it, a client's narrowing may only
// keep a subset of those granted.
type mintedIDsDetail struct {
	Type string   `json:"type"`
	IDs  []string `json:"ids,omitempty"`
}

// grantMayAddIDs lets a grant add identifiers.
func grantMayAddIDs(requested, granted mintedIDsDetail) error {
	if len(requested.IDs) > 0 && !slices.Equal(requested.IDs, granted.IDs) {
		return errors.New("ids differ")
	}
	return nil
}

// narrowingKeepsSubsetOfIDs lets a narrowing keep only granted
// identifiers.
func narrowingKeepsSubsetOfIDs(granted, narrowed mintedIDsDetail) error {
	for _, id := range narrowed.IDs {
		if !slices.Contains(granted.IDs, id) {
			return errors.New("id not granted")
		}
	}
	return nil
}

func mustParseRAR(t *testing.T, reg *extension.RARRegistry, raw string) extension.RARValues {
	t.Helper()
	values, err := reg.Parse(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("Parse(%s): %v", raw, err)
	}
	return values
}

const (
	mintedNoIDs   = `[{"type":"minted"}]`
	mintedIDAB    = `[{"type":"minted","ids":["a","b"]}]`
	mintedIDA     = `[{"type":"minted","ids":["a"]}]`
	mintedIDChose = `[{"type":"minted","ids":["chosen"]}]`
)

// RARRegistry.ValidateNarrowing applies RARDefinition.ValidateNarrowing
// when set, falls back to ValidateGrant when not, and to exact match when
// neither is; RARRegistry.ValidateGrant never consults ValidateNarrowing.
func TestRARRegistryValidateNarrowing(t *testing.T) {
	both := extension.RARDefinition[mintedIDsDetail]{
		Type: "minted", MaxObjects: 2, MaxBytesPerObject: 512,
		ValidateGrant: grantMayAddIDs, ValidateNarrowing: narrowingKeepsSubsetOfIDs,
	}
	grantOnly := both
	grantOnly.ValidateNarrowing = nil
	neither := grantOnly
	neither.ValidateGrant = nil

	for _, tc := range []struct {
		name         string
		def          extension.RARDefinition[mintedIDsDetail]
		base, subset string
		grantOK      bool
		narrowingOK  bool
	}{
		{"both hooks, ids added", both, mintedNoIDs, mintedIDChose, true, false},
		{"both hooks, ids kept", both, mintedIDAB, mintedIDAB, true, true},
		{"both hooks, ids subset", both, mintedIDAB, mintedIDA, false, true},
		{"ValidateGrant only, ids added", grantOnly, mintedNoIDs, mintedIDChose, true, true},
		{"ValidateGrant only, ids subset", grantOnly, mintedIDAB, mintedIDA, false, false},
		{"neither, identical", neither, mintedIDAB, mintedIDAB, true, true},
		{"neither, ids added", neither, mintedNoIDs, mintedIDChose, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg, err := extension.NewRARRegistry(4096, 4, tc.def)
			if err != nil {
				t.Fatalf("NewRARRegistry: %v", err)
			}
			base, subset := mustParseRAR(t, reg, tc.base), mustParseRAR(t, reg, tc.subset)
			assertRARCheck(t, "ValidateGrant", reg.ValidateGrant(base, subset), tc.grantOK)
			assertRARCheck(t, "ValidateNarrowing", reg.ValidateNarrowing(base, subset), tc.narrowingOK)
		})
	}
}

func assertRARCheck(t *testing.T, what string, err error, wantOK bool) {
	t.Helper()
	if wantOK && err != nil {
		t.Fatalf("%s = %v, want nil", what, err)
	}
	if !wantOK && !errors.Is(err, extension.ErrRARGrantExceedsRequest) {
		t.Fatalf("%s = %v, want errors.Is ErrRARGrantExceedsRequest", what, err)
	}
}

// ValidateNarrowing matches objects as ValidateGrant does: each narrowed
// object takes a distinct granted one.
func TestRARRegistryValidateNarrowingRejectsMoreObjectsThanGranted(t *testing.T) {
	def := extension.RARDefinition[mintedIDsDetail]{
		Type: "minted", MaxObjects: 2, MaxBytesPerObject: 512,
		ValidateNarrowing: narrowingKeepsSubsetOfIDs,
	}
	reg, err := extension.NewRARRegistry(4096, 4, def)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	granted := mustParseRAR(t, reg, mintedIDAB)
	narrowed := mustParseRAR(t, reg, `[{"type":"minted","ids":["a"]},{"type":"minted","ids":["b"]}]`)
	assertRARCheck(t, "ValidateNarrowing", reg.ValidateNarrowing(granted, narrowed), false)
}
