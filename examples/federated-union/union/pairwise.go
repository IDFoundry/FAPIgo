package union

import (
	"sort"
	"sync"
)

// issuedSub is one pairwise sub an identity provider gave a service for
// a citizen. Only the console sees the citizen and the sub together:
// each service sees only its own sub.
type issuedSub struct {
	Citizen, CitizenSub, Provider, Service, Sub string
}

// issuedLog is every distinct issuedSub, for the console's pairwise
// subjects panel.
type issuedLog struct {
	mu   sync.Mutex
	subs map[issuedSub]struct{}
}

func (l *issuedLog) record(s issuedSub) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.subs == nil {
		l.subs = map[issuedSub]struct{}{}
	}
	l.subs[s] = struct{}{}
}

// list is every issuedSub, ordered by citizen, then provider, then
// service, so one citizen's subs at different services sit together.
func (l *issuedLog) list() []issuedSub {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]issuedSub, 0, len(l.subs))
	for s := range l.subs {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.CitizenSub != b.CitizenSub {
			return a.CitizenSub < b.CitizenSub
		}
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		return a.Service < b.Service
	})
	return out
}
