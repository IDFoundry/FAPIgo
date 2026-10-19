package federation

import (
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// A statement's exp may sit up to MaxLifetime plus MaxClockSkew away, so
// one from an entity whose clock runs ahead within the skew still
// verifies.
func TestVerifyLifetimeAllowsClockSkew(t *testing.T) {
	key := generateKey(t)
	const entityID = "https://rp.example.org"
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		want     error
	}{
		{"at MaxLifetime plus the skew", time.Hour + 10*time.Second, nil},
		{"past it", time.Hour + 11*time.Second, ErrLifetimeExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := entityConfigParams(t, key, entityID, now)
			params.Lifetime = tc.lifetime
			token, err := Create(params)
			if err != nil {
				t.Fatal(err)
			}
			stmt, err := Parse(token)
			if err != nil {
				t.Fatal(err)
			}
			_, err = stmt.Verify(&key.PublicKey, VerifyPolicy{
				ExpectedIssuer: entityID, ExpectedSubject: entityID,
				Algorithm: fapi.ES256, Now: now, MaxLifetime: time.Hour, MaxClockSkew: 10 * time.Second,
			})
			if !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}
