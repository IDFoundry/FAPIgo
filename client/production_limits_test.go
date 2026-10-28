package client_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
)

// productionClientSetup is validConfig and productionDeps with every
// AssuranceProduction requirement met.
func productionClientSetup(t *testing.T) (client.Config, client.Dependencies) {
	t.Helper()
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	deps := productionDeps(t)
	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(production baseline): %v", err)
	}
	return cfg, deps
}

// TestNewBoundsProductionLimits covers AssuranceProduction's bounds on
// Limits: each is accepted at its bound and refused just past it, while
// AssuranceDevelopment leaves it to the embedder.
func TestNewBoundsProductionLimits(t *testing.T) {
	cases := map[string]struct {
		set       func(*client.Limits, time.Duration)
		in, out   time.Duration
		errorName string
	}{
		"clock skew at 60s":           {func(l *client.Limits, d time.Duration) { l.MaxClockSkew = d }, 60 * time.Second, 61 * time.Second, "limits.max_clock_skew"},
		"clock skew at 10s":           {func(l *client.Limits, d time.Duration) { l.MaxClockSkew = d }, 10 * time.Second, 9 * time.Second, "limits.max_clock_skew"},
		"session lifetime":            {func(l *client.Limits, d time.Duration) { l.SessionLifetime = d }, time.Hour, time.Hour + time.Second, "limits.session_lifetime"},
		"client assertion lifetime":   {func(l *client.Limits, d time.Duration) { l.ClientAssertionLifetime = d }, 5 * time.Minute, 5*time.Minute + time.Second, "limits.client_assertion_lifetime"},
		"ID token lifetime":           {func(l *client.Limits, d time.Duration) { l.MaxIDTokenLifetime = d }, 24 * time.Hour, 24*time.Hour + time.Second, "limits.max_id_token_lifetime"},
		"JARM response lifetime":      {func(l *client.Limits, d time.Duration) { l.MaxJARMResponseLifetime = d }, 10 * time.Minute, 10*time.Minute + time.Second, "limits.max_jarm_response_lifetime"},
		"ID token lifetime of a year": {func(l *client.Limits, d time.Duration) { l.MaxIDTokenLifetime = d }, time.Hour, 365 * 24 * time.Hour, "limits.max_id_token_lifetime"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionClientSetup(t)
			tc.set(&cfg.Limits, tc.in)
			if _, err := client.New(cfg, deps); err != nil {
				t.Fatalf("New(production, %s = %v): %v", tc.errorName, tc.in, err)
			}
			tc.set(&cfg.Limits, tc.out)
			if _, err := client.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.errorName) {
				t.Fatalf("New(production, %s = %v) = %v, want it refused", tc.errorName, tc.out, err)
			}
			cfg.Assurance = client.AssuranceDevelopment
			if _, err := client.New(cfg, validDependencies(t)); err != nil {
				t.Fatalf("New(development, %s = %v) = %v, want it accepted", tc.errorName, tc.out, err)
			}
		})
	}
}

// TestNewProductionReportsEveryLimit covers the one-restart rule: every
// limit out of bounds is reported at once.
func TestNewProductionReportsEveryLimit(t *testing.T) {
	cfg, deps := productionClientSetup(t)
	cfg.Limits.MaxClockSkew = 24 * time.Hour
	cfg.Limits.MaxIDTokenLifetime = 365 * 24 * time.Hour
	cfg.Limits.SessionLifetime = 30 * 24 * time.Hour
	cfg.Limits.ClientAssertionLifetime = 24 * time.Hour
	_, err := client.New(cfg, deps)
	for _, want := range []string{"limits.max_clock_skew", "limits.max_id_token_lifetime", "limits.session_lifetime", "limits.client_assertion_lifetime"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("New = %v, want it to report %s", err, want)
		}
	}
}

// TestRecommendedLimitsMeetProduction: RecommendedLimits, with the
// MaxIDTokenLifetime it leaves to the caller set, passes
// AssuranceProduction.
func TestRecommendedLimitsMeetProduction(t *testing.T) {
	cfg, deps := productionClientSetup(t)
	cfg.Limits = client.RecommendedLimits()
	cfg.Limits.MaxIDTokenLifetime = time.Hour
	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(production, RecommendedLimits) = %v", err)
	}
}

// undeclaredClock is a Clock that doesn't declare client.ClockAssurance.
type undeclaredClock struct{ now time.Time }

func (c undeclaredClock) Now() time.Time { return c.now }

// declaredClock declares client.ClockAssurance, whatever it reads.
type declaredClock struct{ now time.Time }

func (c declaredClock) Now() time.Time      { return c.now }
func (declaredClock) ReadsSystemTime() bool { return true }

// TestNewProductionRequiresSystemClock covers AssuranceProduction's
// clock checks: a Clock must declare ClockAssurance, as SystemClock does,
// and read within MaxClockSkew (10 seconds) of the system's time.
// AssuranceDevelopment accepts any Clock.
func TestNewProductionRequiresSystemClock(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		clock client.Clock
		want  string
	}{
		"SystemClock":           {client.SystemClock{}, ""},
		"declared, 5s ahead":    {declaredClock{now.Add(5 * time.Second)}, ""},
		"undeclared":            {undeclaredClock{now}, "declare client.ClockAssurance"},
		"declared, frozen":      {declaredClock{now.Add(-time.Hour)}, "away from the system's time"},
		"declared, zero time":   {declaredClock{}, "away from the system's time"},
		"declared, a day ahead": {declaredClock{now.Add(24 * time.Hour)}, "away from the system's time"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionClientSetup(t)
			deps.Clock = tc.clock
			_, err := client.New(cfg, deps)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("New(production) = %v, want it accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(production) = %v, want %q", err, tc.want)
			}
			dev := validDependencies(t)
			dev.Clock = tc.clock
			if _, err := client.New(validConfig(t), dev); err != nil {
				t.Fatalf("New(development) = %v, want it accepted", err)
			}
		})
	}
}

// TestNewRejectsTypedNilDependencies covers a Dependencies field holding
// a typed nil, which isn't == nil: New refuses it, under development
// assurance, rather than failing on first use. Every interface field
// validDependencies sets is tried, as a nil pointer of its own type (or
// a pointer to it, for a value type).
func TestNewRejectsTypedNilDependencies(t *testing.T) {
	base := validDependencies(t)
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
			deps := base
			reflect.ValueOf(&deps).Elem().Field(i).Set(reflect.Zero(typed))
			_, err := client.New(validConfig(t), deps)
			if err == nil || !strings.Contains(err.Error(), "is a nil") {
				t.Fatalf("New = %v, want a typed nil refused", err)
			}
		})
	}
}
