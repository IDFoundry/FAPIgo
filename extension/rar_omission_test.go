package extension_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

// scopedDetail authorizes, more narrowly, what the scope it names would
// authorize on its own, as OpenID4VCI 1.0 §5.1.2's openid_credential
// object does a credential configuration's scope.
type scopedDetail struct {
	Type   string   `json:"type"`
	Scope  string   `json:"scope"`
	Claims []string `json:"claims,omitempty"`
}

var errScopeStillCovers = errors.New("the access token keeps the scope this object narrows")

// keepWhileScopeCovers refuses to leave out an object whose scope the
// access token still carries.
func keepWhileScopeCovers(granted scopedDetail, scope []string) error {
	if slices.Contains(scope, granted.Scope) {
		return errScopeStillCovers
	}
	return nil
}

var scopedDef = extension.RARDefinition[scopedDetail]{
	Type: "scoped", MaxObjects: 3, MaxBytesPerObject: 512,
	ValidateOmission: keepWhileScopeCovers,
}

const (
	scopedDiplomaAndLicence = `[{"type":"scoped","scope":"diploma","claims":["given_name"]},{"type":"scoped","scope":"licence"}]`
	scopedDiploma           = `[{"type":"scoped","scope":"diploma","claims":["given_name"]}]`
	scopedLicence           = `[{"type":"scoped","scope":"licence"}]`
)

func newScopedRegistry(t *testing.T, def extension.RARDefinition[scopedDetail]) *extension.RARRegistry {
	t.Helper()
	reg, err := extension.NewRARRegistry(4096, 4, def, paymentDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return reg
}

// RARRegistry.ValidateNarrowing puts each granted object a token request
// leaves out to its type's ValidateOmission, with the access token's
// scope: an empty array leaves out every object, and an object of a type
// the request doesn't name at all is left out too.
func TestRARRegistryValidateNarrowingAsksAboutEachOmission(t *testing.T) {
	reg := newScopedRegistry(t, scopedDef)
	granted := mustParseRAR(t, reg, scopedDiplomaAndLicence)
	for _, tc := range []struct {
		name     string
		narrowed string
		scope    []string
		ok       bool
	}{
		{"nothing left out", scopedDiplomaAndLicence, []string{"diploma", "licence"}, true},
		{"left out, its scope dropped too", scopedDiploma, []string{"openid", "diploma"}, true},
		{"left out while its scope covers it", scopedDiploma, []string{"diploma", "licence"}, false},
		{"the other left out while its scope covers it", scopedLicence, []string{"diploma"}, false},
		{"empty array, no scope", `[]`, nil, true},
		{"empty array, its scope covers one", `[]`, []string{"openid", "licence"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := reg.ValidateNarrowing(granted, mustParseRAR(t, reg, tc.narrowed), tc.scope)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("ValidateNarrowing = %v, want nil", err)
			case !tc.ok && !errors.Is(err, extension.ErrRAROmissionRefused):
				t.Fatalf("ValidateNarrowing = %v, want errors.Is ErrRAROmissionRefused", err)
			case !tc.ok && !errors.Is(err, errScopeStillCovers):
				t.Fatalf("ValidateNarrowing = %v, want it to wrap the hook's own error", err)
			case !tc.ok && !strings.Contains(err.Error(), `"scoped"`):
				t.Fatalf("ValidateNarrowing = %v, want it to name the type", err)
			}
		})
	}
}

// A request that names only another type leaves out every object of this
// one.
func TestRARValidateNarrowingAsksAboutATypeTheRequestDoesNotName(t *testing.T) {
	reg := newScopedRegistry(t, scopedDef)
	granted := mustParseRAR(t, reg, `[{"type":"scoped","scope":"diploma"},{"type":"payment_initiation","instructed_amount":"1.00"}]`)
	payment := mustParseRAR(t, reg, `[{"type":"payment_initiation","instructed_amount":"1.00"}]`)
	if err := reg.ValidateNarrowing(granted, payment, []string{"diploma"}); !errors.Is(err, extension.ErrRAROmissionRefused) {
		t.Fatalf("ValidateNarrowing to the payment alone, scope diploma = %v, want ErrRAROmissionRefused", err)
	}
	if err := reg.ValidateNarrowing(granted, payment, []string{"openid"}); err != nil {
		t.Fatalf("ValidateNarrowing to the payment alone, scope openid = %v, want nil", err)
	}
}

// ValidateOmission sees only the granted objects no narrowed object
// matched, each as granted, and never the objects a request keeps. A
// ValidateGrant at consent never consults it: what a resource owner
// leaves out of a request is the server's own decision.
func TestRARValidateOmissionSeesOnlyWhatIsLeftOut(t *testing.T) {
	var seen []scopedDetail
	def := scopedDef
	def.ValidateOmission = func(granted scopedDetail, _ []string) error {
		seen = append(seen, granted)
		return errScopeStillCovers
	}
	reg := newScopedRegistry(t, def)
	both := mustParseRAR(t, reg, scopedDiplomaAndLicence)
	diploma := mustParseRAR(t, reg, scopedDiploma)

	if err := reg.ValidateNarrowing(both, diploma, nil); !errors.Is(err, extension.ErrRAROmissionRefused) {
		t.Fatalf("ValidateNarrowing = %v, want ErrRAROmissionRefused", err)
	}
	if len(seen) != 1 || seen[0].Scope != "licence" {
		t.Fatalf("ValidateOmission saw %+v, want only the licence object", seen)
	}

	seen = nil
	if err := reg.ValidateNarrowing(both, both, nil); err != nil {
		t.Fatalf("ValidateNarrowing leaving nothing out = %v", err)
	}
	if err := reg.ValidateGrant(both, diploma); err != nil {
		t.Fatalf("ValidateGrant granting less than was requested = %v", err)
	}
	if len(seen) != 0 {
		t.Fatalf("ValidateOmission saw %+v, want no calls", seen)
	}
}

// Without ValidateOmission, any granted object may be left out (RFC 9396
// §6.1).
func TestRARValidateNarrowingWithoutOmissionHookLeavesOutAnything(t *testing.T) {
	def := scopedDef
	def.ValidateOmission = nil
	reg := newScopedRegistry(t, def)
	granted := mustParseRAR(t, reg, scopedDiplomaAndLicence)
	for _, narrowed := range []string{`[]`, scopedDiploma, scopedLicence} {
		if err := reg.ValidateNarrowing(granted, mustParseRAR(t, reg, narrowed), []string{"diploma", "licence"}); err != nil {
			t.Fatalf("ValidateNarrowing(%s) = %v, want nil", narrowed, err)
		}
	}
}

// Each ValidateOmission call gets its own copy of the scope: a hook that
// changes it changes neither the caller's scope, which the server issues
// the access token with, nor what the next call sees.
func TestRARValidateOmissionGetsACopyOfTheScope(t *testing.T) {
	var seen [][]string
	def := scopedDef
	def.ValidateOmission = func(_ scopedDetail, scope []string) error {
		seen = append(seen, slices.Clone(scope))
		scope[0] = "changed"
		return nil
	}
	reg := newScopedRegistry(t, def)
	scope := []string{"openid", "diploma"}
	if err := reg.ValidateNarrowing(mustParseRAR(t, reg, scopedDiplomaAndLicence), mustParseRAR(t, reg, `[]`), scope); err != nil {
		t.Fatalf("ValidateNarrowing = %v", err)
	}
	if !slices.Equal(scope, []string{"openid", "diploma"}) {
		t.Fatalf("caller's scope = %q after the hook changed its copy", scope)
	}
	if len(seen) != 2 || !slices.Equal(seen[0], scope) || !slices.Equal(seen[1], scope) {
		t.Fatalf("ValidateOmission saw %q, want the original scope twice", seen)
	}
}

// A granted object that doesn't decode into its type's Go value, as
// RARValues restored from JSON may hold, is refused as malformed rather
// than put to ValidateOmission.
func TestRARValidateOmissionRefusesAGrantedObjectItCannotDecode(t *testing.T) {
	called := false
	def := scopedDef
	def.ValidateOmission = func(scopedDetail, []string) error {
		called = true
		return nil
	}
	reg := newScopedRegistry(t, def)
	var granted extension.RARValues
	if err := json.Unmarshal([]byte(`[{"type":"scoped","scope":5}]`), &granted); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	err := reg.ValidateNarrowing(granted, extension.RARValues{}, nil)
	if err == nil || errors.Is(err, extension.ErrRAROmissionRefused) || !strings.Contains(err.Error(), "malformed granted value") {
		t.Fatalf("ValidateNarrowing leaving out an undecodable object = %v, want a malformed granted value error", err)
	}
	if called {
		t.Fatal("ValidateOmission was asked about an object that didn't decode")
	}
}

// A granted object whose type the registry doesn't register can't be put
// to any ValidateOmission, so leaving it out is refused. RARValues decoded
// from JSON, a stored grant say, never went through this registry's
// Parse.
func TestRARValidateNarrowingRefusesLeavingOutAnUnregisteredType(t *testing.T) {
	reg := newScopedRegistry(t, scopedDef)
	var granted extension.RARValues
	if err := json.Unmarshal([]byte(`[{"type":"unregistered_x"}]`), &granted); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if err := reg.ValidateNarrowing(granted, extension.RARValues{}, nil); !errors.Is(err, extension.ErrRARUnregisteredType) {
		t.Fatalf("ValidateNarrowing leaving out an unregistered type = %v, want ErrRARUnregisteredType", err)
	}
}
