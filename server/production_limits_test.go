package server_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestNewBoundsProductionLifetimes covers the windows FAPI 2.0 leaves
// open, which AssuranceProduction bounds: each limit is accepted at its
// bound and refused just past it, while AssuranceDevelopment leaves it to
// the embedder.
func TestNewBoundsProductionLifetimes(t *testing.T) {
	cases := map[string]struct {
		set   func(*server.Limits, time.Duration)
		bound time.Duration
		want  string
	}{
		"dpop proof age":       {func(l *server.Limits, d time.Duration) { l.MaxDPoPProofAge = d }, 5 * time.Minute, "limits.max_dpop_proof_age"},
		"dpop nonce lifetime":  {func(l *server.Limits, d time.Duration) { l.DPoPNonceLifetime = d }, 15 * time.Minute, "limits.dpop_nonce_lifetime"},
		"jarm response":        {func(l *server.Limits, d time.Duration) { l.JARMResponseLifetime = d }, 10 * time.Minute, "limits.jarm_response_lifetime"},
		"interaction lifetime": {func(l *server.Limits, d time.Duration) { l.InteractionLifetime = d }, time.Hour, "limits.interaction_lifetime"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionConfigAndDeps(t)
			tc.set(&cfg.Limits, tc.bound)
			if _, err := server.New(cfg, deps); err != nil {
				t.Fatalf("New(production, %s = %v): %v", tc.want, tc.bound, err)
			}
			over := tc.bound + time.Second
			tc.set(&cfg.Limits, over)
			if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(production, %s = %v) = %v, want it refused", tc.want, over, err)
			}
			cfg.Assurance = server.AssuranceDevelopment
			if _, err := server.New(cfg, deps); err != nil {
				t.Fatalf("New(development, %s = %v) = %v, want it accepted", tc.want, over, err)
			}
		})
	}
}

// undeclaredClock is a Clock that doesn't declare server.ClockAssurance.
type undeclaredClock struct{ now time.Time }

func (c undeclaredClock) Now() time.Time { return c.now }

// declaredClock is a Clock declaring server.ClockAssurance, whatever its
// reading.
type declaredClock struct {
	now      time.Time
	declares bool
}

func (c declaredClock) Now() time.Time        { return c.now }
func (c declaredClock) ReadsSystemTime() bool { return c.declares }

// TestNewProductionRequiresSystemClock covers AssuranceProduction's
// clock checks: a Clock must declare ClockAssurance, as SystemClock does,
// and read within MaxClockSkew (10 seconds here) of the system's time; a
// frozen or zero-time clock is refused even when it declares it.
// AssuranceDevelopment accepts any Clock.
func TestNewProductionRequiresSystemClock(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		clock server.Clock
		want  string // "" for accepted
	}{
		"SystemClock":                  {server.SystemClock{}, ""},
		"declared, current":            {declaredClock{now: now, declares: true}, ""},
		"declared, 5s behind":          {declaredClock{now: now.Add(-5 * time.Second), declares: true}, ""},
		"undeclared, current":          {undeclaredClock{now: now}, "declare server.ClockAssurance"},
		"declaring false":              {declaredClock{now: now, declares: false}, "declare server.ClockAssurance"},
		"declared, frozen an hour ago": {declaredClock{now: now.Add(-time.Hour), declares: true}, "away from the system's time"},
		"declared, a minute ahead":     {declaredClock{now: now.Add(time.Minute), declares: true}, "away from the system's time"},
		"declared, zero time":          {declaredClock{declares: true}, "away from the system's time"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionConfigAndDeps(t)
			deps.Clock = tc.clock
			_, err := server.New(cfg, deps)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("New(production) = %v, want it accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(production) = %v, want %q", err, tc.want)
			}
			cfg.Assurance = server.AssuranceDevelopment
			if _, err := server.New(cfg, deps); err != nil {
				t.Fatalf("New(development) = %v, want it accepted", err)
			}
		})
	}
}

// TestNewRejectsTypedNilDependencies covers a Dependencies field holding
// a typed nil, which isn't == nil: New refuses it, under either
// assurance level, rather than panicking inside New or on the first
// request. Every interface field validDependencies sets is tried, as a
// nil pointer of its own type (or a pointer to it, for a value type).
func TestNewRejectsTypedNilDependencies(t *testing.T) {
	base := validDependencies()
	base.Audit = &fakeAuditSink{}
	base.Nonces = memstore.NewNonceStore()
	v := reflect.ValueOf(base)
	for i := range v.NumField() {
		field := v.Type().Field(i)
		value := v.Field(i)
		if field.Type.Kind() != reflect.Interface || value.IsNil() {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			typed := value.Elem().Type()
			if typed.Kind() != reflect.Pointer {
				typed = reflect.PointerTo(typed)
			}
			if !typed.Implements(field.Type) {
				t.Skipf("%v doesn't implement %v", typed, field.Type)
			}
			deps := base
			reflect.ValueOf(&deps).Elem().Field(i).Set(reflect.Zero(typed))
			cfg := validConfig(t)
			cfg.Limits.DPoPNonceLifetime = time.Minute
			assertTypedNilRefused(t, cfg, deps)
		})
	}
}

// assertTypedNilRefused checks New refuses deps with a "is a nil"
// error rather than accepting it or panicking.
func assertTypedNilRefused(t *testing.T, cfg server.Config, deps server.Dependencies) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New panicked: %v", r)
		}
	}()
	_, err := server.New(cfg, deps)
	if err == nil || !strings.Contains(err.Error(), "is a nil") {
		t.Fatalf("New = %v, want a typed nil refused", err)
	}
}
