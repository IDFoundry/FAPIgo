package server_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/server"
)

// notIssuedYet is the error New gives every configuration in which a
// client could be pairwise, while pairwise subjects aren't issued.
const notIssuedYet = "doesn't issue pairwise subjects yet"

var pairwiseTestKey = bytes.Repeat([]byte{0x11, 0x22}, 16)

func testHMACDeriver(t *testing.T, opts ...keys.CustodyOption) pairwise.Deriver {
	t.Helper()
	d, err := pairwise.NewHMAC(pairwiseTestKey, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func testPrefix(t *testing.T, s string) pairwise.Prefix {
	t.Helper()
	p, err := pairwise.NewPrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// pairwiseSubjects is a valid configuration in which a client can be
// pairwise.
func pairwiseSubjects(t *testing.T) server.SubjectConfig {
	return server.SubjectConfig{
		Default:     fapi.SubjectTypePairwise,
		Enforcement: server.SubjectTypesPerClient,
		Derivation:  pairwise.OneWay,
		Prefix:      testPrefix(t, "ppid:"),
	}
}

func newErr(t *testing.T, cfg server.Config, deps server.Dependencies) error {
	t.Helper()
	_, err := server.New(cfg, deps)
	return err
}

func TestPublicSubjects(t *testing.T) {
	got := server.PublicSubjects()
	if got.Default != fapi.SubjectTypePublic || got.Enforcement != server.SubjectTypesPerClient || got.Derivation != 0 || got.Prefix.IsSet() {
		t.Errorf("PublicSubjects() = %+v", got)
	}
	if got.IsZero() || !(server.SubjectConfig{}).IsZero() {
		t.Error("IsZero is wrong")
	}
}

func TestNewRequiresSubjects(t *testing.T) {
	cfg, deps := validConfig(t), validDependencies()
	cfg.Subjects = server.SubjectConfig{}
	if err := newErr(t, cfg, deps); err == nil || !strings.Contains(err.Error(), "subjects.default is required") {
		t.Fatalf("New(zero Subjects) = %v, want subjects.default is required", err)
	}
}

func TestNewOAuthOnlyTreatsZeroSubjectsAsPublic(t *testing.T) {
	cfg, deps := validConfig(t), validDependencies()
	cfg.OAuthOnly = true
	cfg.Subjects = server.SubjectConfig{}
	if err := newErr(t, cfg, deps); err != nil {
		t.Fatalf("New(OAuthOnly, zero Subjects) = %v, want nil", err)
	}
	// An OAuthOnly server that sets Subjects gets the same rules.
	cfg.Subjects = server.SubjectConfig{Default: fapi.SubjectTypePublic}
	if err := newErr(t, cfg, deps); err == nil || !strings.Contains(err.Error(), "subjects.enforcement is required") {
		t.Fatalf("New(OAuthOnly, Subjects without Enforcement) = %v", err)
	}
}

func TestNewRefusesInvalidSubjects(t *testing.T) {
	tests := map[string]struct {
		subjects func(t *testing.T) server.SubjectConfig
		deriver  bool
		want     string
	}{
		"invalid default": {func(*testing.T) server.SubjectConfig {
			return server.SubjectConfig{Default: 9, Enforcement: server.SubjectTypesPerClient}
		}, false, "subjects.default is invalid"},
		"no enforcement": {func(*testing.T) server.SubjectConfig {
			return server.SubjectConfig{Default: fapi.SubjectTypePublic}
		}, false, "subjects.enforcement is required"},
		"invalid enforcement": {func(*testing.T) server.SubjectConfig {
			return server.SubjectConfig{Default: fapi.SubjectTypePublic, Enforcement: 9}
		}, false, "subjects.enforcement is invalid"},
		"pairwise-only with a public default": {func(*testing.T) server.SubjectConfig {
			return server.SubjectConfig{Default: fapi.SubjectTypePublic, Enforcement: server.SubjectTypesPairwiseOnly}
		}, false, "requires a pairwise subjects.default"},
		"derivation without pairwise": {func(*testing.T) server.SubjectConfig {
			c := server.PublicSubjects()
			c.Derivation = pairwise.OneWay
			return c
		}, false, "apply only when a client can be pairwise"},
		"prefix without pairwise": {func(t *testing.T) server.SubjectConfig {
			c := server.PublicSubjects()
			c.Prefix = testPrefix(t, "")
			return c
		}, false, "apply only when a client can be pairwise"},
		"pairwise default without a deriver": {pairwiseSubjects, false, "pairwise_subjects is required"},
		"no derivation": {func(t *testing.T) server.SubjectConfig {
			c := pairwiseSubjects(t)
			c.Derivation = 0
			return c
		}, true, "subjects.derivation is required"},
		"invalid derivation": {func(t *testing.T) server.SubjectConfig {
			c := pairwiseSubjects(t)
			c.Derivation = 9
			return c
		}, true, "subjects.derivation is invalid"},
		"unset prefix": {func(t *testing.T) server.SubjectConfig {
			c := pairwiseSubjects(t)
			c.Prefix = pairwise.Prefix{}
			return c
		}, true, "subjects.prefix is required"},
		"reversible with a one-way deriver": {func(t *testing.T) server.SubjectConfig {
			c := pairwiseSubjects(t)
			c.Derivation = pairwise.Reversible
			return c
		}, true, "requires dependencies.pairwise_subjects to implement pairwise.Lookup"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies()
			cfg.Subjects = tc.subjects(t)
			if tc.deriver {
				deps.PairwiseSubjects = testHMACDeriver(t)
			}
			if err := newErr(t, cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// TestNewRefusesPairwiseUntilIssued: a valid configuration in which a
// client could be pairwise passes every check, then is refused, since
// this release doesn't issue pairwise subjects.
func TestNewRefusesPairwiseUntilIssued(t *testing.T) {
	for name, mutate := range map[string]func(*server.SubjectConfig){
		"pairwise default":          func(*server.SubjectConfig) {},
		"pairwise only":             func(c *server.SubjectConfig) { c.Enforcement = server.SubjectTypesPairwiseOnly },
		"public default, a deriver": func(c *server.SubjectConfig) { c.Default = fapi.SubjectTypePublic },
		"empty prefix":              func(c *server.SubjectConfig) { c.Prefix = testPrefix(t, "") },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies()
			cfg.Subjects = pairwiseSubjects(t)
			mutate(&cfg.Subjects)
			deps.PairwiseSubjects = testHMACDeriver(t)
			if err := newErr(t, cfg, deps); err == nil || !strings.Contains(err.Error(), notIssuedYet) {
				t.Fatalf("New = %v, want %q", err, notIssuedYet)
			}
		})
	}
}

// probeDeriver is a Deriver (and Lookup) whose answers a test controls.
type probeDeriver struct {
	body      string
	err       error
	looksUpTo string
	lookupErr error
}

func (d probeDeriver) DerivePairwiseSubject(context.Context, pairwise.Input) (string, error) {
	return d.body, d.err
}

func (d probeDeriver) LookupInternalSubject(context.Context, string, string, string) (string, error) {
	return d.looksUpTo, d.lookupErr
}

func TestNewProbesThePairwiseDeriver(t *testing.T) {
	tests := map[string]struct {
		deriver    probeDeriver
		derivation pairwise.Derivation
		want       string
	}{
		"derivation fails":   {probeDeriver{err: errors.New("kms down")}, pairwise.OneWay, "can't derive a subject: kms down"},
		"empty body":         {probeDeriver{body: ""}, pairwise.OneWay, "derived an unusable subject"},
		"body with a space":  {probeDeriver{body: "a b"}, pairwise.OneWay, "derived an unusable subject"},
		"lookup fails":       {probeDeriver{body: "abc", lookupErr: errors.New("store down")}, pairwise.Reversible, "can't look up the subject it derived: store down"},
		"lookup is wrong":    {probeDeriver{body: "abc", looksUpTo: "someone-else"}, pairwise.Reversible, `can't look up the subject it derived: it returned "someone-else"`},
		"reversible, sound":  {probeDeriver{body: "abc", looksUpTo: "fapigo-pairwise-probe"}, pairwise.Reversible, notIssuedYet},
		"one-way, no lookup": {probeDeriver{body: "abc", lookupErr: errors.New("never called")}, pairwise.OneWay, notIssuedYet},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies()
			cfg.Subjects = pairwiseSubjects(t)
			cfg.Subjects.Derivation = tc.derivation
			deps.PairwiseSubjects = tc.deriver
			if err := newErr(t, cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestProductionRequiresPairwiseKeyCustody(t *testing.T) {
	tests := map[string]struct {
		deployment server.Deployment
		custody    []keys.CustodyOption
		want       string
	}{
		"none declared": {server.DeploymentSingleInstance, nil, "pairwise_subjects must implement keys.KeyCustodyAssurance"},
		"not durable": {server.DeploymentSingleInstance, []keys.CustodyOption{keys.DeclareCustody(keys.KeyCustody{})},
			"pairwise_subjects must declare Durable"},
		"scaled, not cross-instance": {server.DeploymentHorizontallyScaled, []keys.CustodyOption{keys.DeclareCustody(keys.KeyCustody{Durable: true})},
			"pairwise_subjects must declare CrossInstanceConsistent"},
		"durable": {server.DeploymentSingleInstance, []keys.CustodyOption{keys.DeclareCustody(keys.KeyCustody{Durable: true})}, notIssuedYet},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionConfigAndDeps(t)
			// Under DeploymentHorizontallyScaled the baseline's stores are
			// refused too; the refusals are joined, so the pairwise one is
			// still reported.
			cfg.Deployment = tc.deployment
			cfg.Subjects = pairwiseSubjects(t)
			deps.PairwiseSubjects = testHMACDeriver(t, tc.custody...)
			if err := newErr(t, cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	t.Run("public needs no deriver", func(t *testing.T) {
		cfg, deps := productionConfigAndDeps(t)
		cfg.Subjects = server.PublicSubjects()
		if err := newErr(t, cfg, deps); err != nil {
			t.Fatalf("New(production, public) = %v", err)
		}
	})
}

func TestMetadataSubjectTypesSupported(t *testing.T) {
	srv, err := server.New(validConfig(t), validDependencies())
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.Metadata(context.Background()).SubjectTypesSupported; !slices.Equal(got, []string{"public"}) {
		t.Errorf("subject_types_supported = %q, want [public]", got)
	}
}
