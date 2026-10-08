package server

import (
	"math"
	"testing"
	"time"
)

// TestGrantRevocationHorizonSaturates: lifetimes long enough to
// overflow the sum give the longest horizon, never a negative one that
// would write an already-expired revocation record.
func TestGrantRevocationHorizonSaturates(t *testing.T) {
	year := 365 * 24 * time.Hour
	s := &Server{cfg: Config{Limits: Limits{
		RefreshTokenLifetime: 200 * year,
		AccessTokenLifetime:  100 * year,
		MaxClockSkew:         time.Minute,
	}}}
	if got := s.grantRevocationHorizon(); got != math.MaxInt64 {
		t.Fatalf("grantRevocationHorizon() = %v, want the largest Duration", got)
	}

	s.cfg.Limits = Limits{RefreshTokenLifetime: time.Hour, AuthorizationCodeLifetime: time.Minute, AccessTokenLifetime: 10 * time.Minute, MaxClockSkew: 5 * time.Second}
	if got, want := s.grantRevocationHorizon(), time.Hour+10*time.Minute+5*time.Second; got != want {
		t.Fatalf("grantRevocationHorizon() = %v, want %v", got, want)
	}
}
