package resource

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/pairwise"
)

// deadlineLookup records the deadline of the context it was called with,
// as a pairwise.Lookup and a pairwise.SubjectResolver.
type deadlineLookup struct{ deadline *time.Time }

func (d deadlineLookup) LookupInternalSubject(ctx context.Context, _, _, _ string) (string, error) {
	*d.deadline, _ = ctx.Deadline()
	return "alice", nil
}

func (d deadlineLookup) ResolveSubject(ctx context.Context, issuer, sector, sub string) (string, error) {
	return d.LookupInternalSubject(ctx, issuer, sector, sub)
}

// TestPairwiseLookupIsBounded: a resource server's pairwise lookup and
// resolver calls run under pairwiseLookupTimeout, as the server's own
// do, so a store or key service that hangs can't hold a request open.
func TestPairwiseLookupIsBounded(t *testing.T) {
	prefix, err := pairwise.NewPrefix("pw:")
	if err != nil {
		t.Fatal(err)
	}
	body := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	resolved := ResolvedAccessToken{
		Subject: "pw:" + body, Issuer: "https://as.example",
		Claims: map[string]json.RawMessage{token.PairwiseSectorClaim: json.RawMessage(`"rp.example"`)},
	}
	for name, deps := range map[string]func(deadlineLookup) Dependencies{
		"lookup":   func(d deadlineLookup) Dependencies { return Dependencies{PairwiseSubjects: d} },
		"resolver": func(d deadlineLookup) Dependencies { return Dependencies{PairwiseSubjectResolver: d} },
	} {
		t.Run(name, func(t *testing.T) {
			var deadline time.Time
			v := &Verifier{cfg: Config{PairwisePrefix: prefix}, deps: deps(deadlineLookup{&deadline})}
			before := time.Now()
			if subject, _, verr := v.resolveSubjects(context.Background(), resolved); verr != nil || subject != "alice" {
				t.Fatalf("resolveSubjects = %q, %v", subject, verr)
			}
			if deadline.IsZero() || deadline.After(before.Add(pairwiseLookupTimeout+time.Second)) {
				t.Errorf("lookup deadline = %v, want within %v", deadline, pairwiseLookupTimeout)
			}
		})
	}
}
