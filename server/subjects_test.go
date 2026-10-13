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
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// opaqueAccessTokens is the access token issuer pairwise.OneWay
// requires: the internal subject stays in its server-side records.
func opaqueAccessTokens() server.OpaqueAccessTokens {
	return server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
}

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
	if got.Default != fapi.SubjectTypePublic || got.Enforcement != server.SubjectTypesPerClient || got.Prefix.IsSet() {
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
		"prefix without pairwise": {func(t *testing.T) server.SubjectConfig {
			c := server.PublicSubjects()
			c.Prefix = testPrefix(t, "")
			return c
		}, false, "apply only when a client can be pairwise"},
		"pairwise default without a deriver": {pairwiseSubjects, false, "pairwise_subjects is required"},
		"unset prefix": {func(t *testing.T) server.SubjectConfig {
			c := pairwiseSubjects(t)
			c.Prefix = pairwise.Prefix{}
			return c
		}, true, "subjects.prefix is required"},
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

// TestNewAcceptsPairwiseSubjects: a valid configuration in which a
// client could be pairwise builds a server.
func TestNewAcceptsPairwiseSubjects(t *testing.T) {
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
			deps.AccessTokens = opaqueAccessTokens()
			if err := newErr(t, cfg, deps); err != nil {
				t.Fatalf("New = %v, want a server", err)
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

// oneWayProbe is a probeDeriver without its Lookup: a one-way Deriver.
type oneWayProbe struct{ d probeDeriver }

func (o oneWayProbe) DerivePairwiseSubject(ctx context.Context, in pairwise.Input) (string, error) {
	return o.d.DerivePairwiseSubject(ctx, in)
}

func TestNewProbesThePairwiseDeriver(t *testing.T) {
	tests := map[string]struct {
		deriver pairwise.Deriver
		want    string
	}{
		"derivation fails":   {oneWayProbe{probeDeriver{err: errors.New("kms down")}}, "can't derive a subject: kms down"},
		"empty body":         {oneWayProbe{probeDeriver{body: ""}}, "derived an unusable subject"},
		"body with a space":  {oneWayProbe{probeDeriver{body: "a b"}}, "derived an unusable subject"},
		"lookup fails":       {probeDeriver{body: "abc", lookupErr: errors.New("store down")}, "can't look up the subject it derived: store down"},
		"lookup is wrong":    {probeDeriver{body: "abc", looksUpTo: "someone-else"}, `can't look up the subject it derived: it returned "someone-else"`},
		"reversible, sound":  {probeDeriver{body: "abc", looksUpTo: "fapigo-pairwise-probe"}, ""},
		"one-way, no lookup": {oneWayProbe{probeDeriver{body: "abc"}}, ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies()
			cfg.Subjects = pairwiseSubjects(t)
			deps.PairwiseSubjects = tc.deriver
			deps.AccessTokens = opaqueAccessTokens()
			checkNewErr(t, newErr(t, cfg, deps), tc.want)
		})
	}
}

func TestProductionRequiresPairwiseKeyCustody(t *testing.T) {
	tests := map[string]struct {
		deployment server.Deployment
		custody    []keys.CustodyOption
		want       string
	}{
		"none declared": {server.DeploymentSingleInstance, nil, "pairwise_subjects must declare Durable"},
		"not durable": {server.DeploymentSingleInstance, []keys.CustodyOption{keys.DeclareCustody(keys.KeyCustody{})},
			"pairwise_subjects must declare Durable"},
		"scaled, not cross-instance": {server.DeploymentHorizontallyScaled, []keys.CustodyOption{keys.DeclareCustody(keys.KeyCustody{Durable: true})},
			"pairwise_subjects must declare CrossInstanceConsistent"},
		"durable": {server.DeploymentSingleInstance, []keys.CustodyOption{keys.DeclareCustody(keys.KeyCustody{Durable: true})}, ""},
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
			deps.AccessTokens = server.OpaqueAccessTokens{Store: capAccessTokenStore{caps: storage.Capabilities{Durable: true, CrossInstanceConsistent: true}}}
			checkNewErr(t, newErr(t, cfg, deps), tc.want)
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

// checkNewErr fails t unless err contains want, or, for an empty want,
// is nil.
func checkNewErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("New = %v, want a server", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("New = %v, want an error containing %q", err, want)
	}
}

// TestNewRefusesSelfContainedAccessTokensForOneWayPairwise: with a
// one-way deriver a pairwise sub can't be mapped back to its end user,
// so a self-contained access token issuer is refused; with a reversible
// one (a pairwise.Lookup) it's accepted, and a public-only server is
// unaffected.
func TestNewRefusesSelfContainedAccessTokensForOneWayPairwise(t *testing.T) {
	t.Run("one-way, JWT", func(t *testing.T) {
		cfg, deps := validConfig(t), validDependencies()
		cfg.Subjects = pairwiseSubjects(t)
		deps.PairwiseSubjects = testHMACDeriver(t)
		checkNewErr(t, newErr(t, cfg, deps), "access_tokens must be OpaqueAccessTokens with a one-way pairwise_subjects")
	})
	t.Run("one-way, opaque pointer", func(t *testing.T) {
		cfg, deps := validConfig(t), validDependencies()
		cfg.Subjects = pairwiseSubjects(t)
		deps.PairwiseSubjects = testHMACDeriver(t)
		opaque := opaqueAccessTokens()
		deps.AccessTokens = &opaque
		checkNewErr(t, newErr(t, cfg, deps), "")
	})
	t.Run("reversible, JWT", func(t *testing.T) {
		cfg, deps := validConfig(t), validDependencies()
		cfg.Subjects = pairwiseSubjects(t)
		deps.PairwiseSubjects = probeDeriver{body: "abc", looksUpTo: "fapigo-pairwise-probe"}
		checkNewErr(t, newErr(t, cfg, deps), "")
	})
	t.Run("public, JWT", func(t *testing.T) {
		checkNewErr(t, newErr(t, validConfig(t), validDependencies()), "")
	})
}

// subResolver is an embedder's own mapping for a one-way deriver: the
// subs it knows, by issuer, sector and sub.
type subResolver struct {
	subjects map[[3]string]string
}

func (r subResolver) ResolveSubject(_ context.Context, issuer, sector, sub string) (string, error) {
	if internal, ok := r.subjects[[3]string{issuer, sector, sub}]; ok {
		return internal, nil
	}
	return "", pairwise.ErrSubjectNotFound
}

// custodySubResolver is a subResolver declaring custody.
type custodySubResolver struct {
	subResolver
	custody keys.KeyCustody
}

func (r custodySubResolver) KeyCustody() keys.KeyCustody { return r.custody }

// TestNewAcceptsOneWayJWTWithAResolver: with a one-way deriver a
// declared resolver lets the server issue JWT access tokens; a resolver
// is refused where it would have no effect (a reversible deriver, or no
// client can be pairwise).
func TestNewAcceptsOneWayJWTWithAResolver(t *testing.T) {
	t.Run("one-way, JWT, resolver", func(t *testing.T) {
		cfg, deps := validConfig(t), validDependencies()
		cfg.Subjects = pairwiseSubjects(t)
		deps.PairwiseSubjects = testHMACDeriver(t)
		deps.PairwiseSubjectResolver = subResolver{}
		checkNewErr(t, newErr(t, cfg, deps), "")
	})
	t.Run("reversible, resolver", func(t *testing.T) {
		cfg, deps := validConfig(t), validDependencies()
		cfg.Subjects = pairwiseSubjects(t)
		deps.PairwiseSubjects = probeDeriver{body: "abc", looksUpTo: "fapigo-pairwise-probe"}
		deps.PairwiseSubjectResolver = subResolver{}
		checkNewErr(t, newErr(t, cfg, deps), "pairwise_subject_resolver applies only to a one-way pairwise_subjects")
	})
	t.Run("public, resolver", func(t *testing.T) {
		cfg, deps := validConfig(t), validDependencies()
		deps.PairwiseSubjectResolver = subResolver{}
		checkNewErr(t, newErr(t, cfg, deps), "apply only when a client can be pairwise")
	})
}

// TestProductionRequiresResolverCustody: under production the declared
// resolver must be durable, like the deriver.
func TestProductionRequiresResolverCustody(t *testing.T) {
	for name, tc := range map[string]struct {
		resolver pairwise.SubjectResolver
		want     string
	}{
		"undeclared":  {subResolver{}, "pairwise_subject_resolver must implement keys.KeyCustodyAssurance"},
		"not durable": {custodySubResolver{}, "pairwise_subject_resolver must declare Durable"},
		"durable":     {custodySubResolver{custody: keys.KeyCustody{Durable: true}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionConfigAndDeps(t)
			cfg.Subjects = pairwiseSubjects(t)
			deps.PairwiseSubjects = testHMACDeriver(t, keys.DeclareCustody(keys.KeyCustody{Durable: true}))
			deps.PairwiseSubjectResolver = tc.resolver
			checkNewErr(t, newErr(t, cfg, deps), tc.want)
		})
	}
}
