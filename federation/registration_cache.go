package federation

import (
	"container/list"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// maxCachedRegistrations bounds how many successful registrations
// AutomaticClientRepository caches at once. An entity that can have
// subordinates registered under a trusted Trust Anchor can mint new
// client_ids, each costing one resolution, so the cache must not grow
// with them either.
const maxCachedRegistrations = 4096

// maxCachedPerSuperior bounds the cached registrations whose Trust Chain
// runs through any one immediate superior — the entity that issued the
// Relying Party's Subordinate Statement, and so the only one able to
// mint more Relying Parties beside it.
const maxCachedPerSuperior = maxCachedRegistrations / 8

// maxCachedPerBranch bounds the cached registrations under any one
// subordinate of a Trust Anchor (the branch the Trust Anchor itself
// vouched for). An intermediate can mint intermediates beneath it, each
// a new immediate superior with its own maxCachedPerSuperior, but all of
// them sit in the one branch it was vouched into.
const maxCachedPerBranch = maxCachedRegistrations / 2

// registrationCache is AutomaticClientRepository's cache of successful
// registrations, bounded so that no federation member can crowd out
// Relying Parties it doesn't control:
//
//   - Each entry is counted against its immediate superior and against
//     its branch, the Trust Anchor's own subordinate its chain runs
//     through. A Relying Party registered directly under a Trust Anchor
//     has no branch: a Trust Anchor is trusted, and such a Relying Party
//     can't mint others beside it, so those count only against
//     maxCachedRegistrations.
//   - A new entry for a superior at maxCachedPerSuperior evicts that
//     superior's own least recently cached entry, so its newest
//     registrations stay cached without touching anyone else's.
//   - Otherwise, a new entry that would take its branch past
//     maxCachedPerBranch, or the cache past maxCachedRegistrations, first
//     drops every expired entry, and if that isn't enough the new entry
//     simply isn't cached. A still-valid entry is never evicted for
//     another superior's registration, so an attacker able to mint
//     Relying Parties can only ever displace its own.
//
// An entry also leaves the cache when found expired on lookup. Every
// method requires the AutomaticClientRepository's mutex.
type registrationCache struct {
	entries      map[fapi.ClientID]*cacheSlot
	bySuperior   map[string]*list.List
	branchCounts map[string]int
}

// cacheSlot is one cached registration and its place in its superior's
// list, oldest first.
type cacheSlot struct {
	entry cachedClient
	elem  *list.Element
}

func newRegistrationCache() *registrationCache {
	return &registrationCache{
		entries:      make(map[fapi.ClientID]*cacheSlot),
		bySuperior:   make(map[string]*list.List),
		branchCounts: make(map[string]int),
	}
}

// get returns id's entry if cached and not expired at now, removing it
// when expired.
func (c *registrationCache) get(id fapi.ClientID, now time.Time) (cachedClient, bool) {
	slot, ok := c.entries[id]
	if !ok {
		return cachedClient{}, false
	}
	if !now.Before(slot.entry.expiresAt) {
		c.remove(id)
		return cachedClient{}, false
	}
	return slot.entry, true
}

// len reports how many registrations are cached.
func (c *registrationCache) len() int { return len(c.entries) }

// put caches entry as id's registration at now, within the limits
// registrationCache's doc comment sets out, and reports whether it did.
// Re-caching an id replaces its entry.
func (c *registrationCache) put(id fapi.ClientID, entry cachedClient, now time.Time) bool {
	c.remove(id)
	if entry.branch != "" {
		if own := c.bySuperior[entry.superior]; own != nil && own.Len() >= maxCachedPerSuperior {
			c.remove(own.Front().Value.(fapi.ClientID))
		}
		if c.branchCounts[entry.branch] >= maxCachedPerBranch {
			c.dropExpired(now)
			if c.branchCounts[entry.branch] >= maxCachedPerBranch {
				return false
			}
		}
	}
	if len(c.entries) >= maxCachedRegistrations {
		c.dropExpired(now)
		if len(c.entries) >= maxCachedRegistrations {
			return false
		}
	}
	own := c.bySuperior[entry.superior]
	if own == nil {
		own = list.New()
		c.bySuperior[entry.superior] = own
	}
	c.entries[id] = &cacheSlot{entry: entry, elem: own.PushBack(id)}
	if entry.branch != "" {
		c.branchCounts[entry.branch]++
	}
	return true
}

// remove drops id's entry, if cached.
func (c *registrationCache) remove(id fapi.ClientID) {
	slot, ok := c.entries[id]
	if !ok {
		return
	}
	delete(c.entries, id)
	if own := c.bySuperior[slot.entry.superior]; own != nil {
		own.Remove(slot.elem)
		if own.Len() == 0 {
			delete(c.bySuperior, slot.entry.superior)
		}
	}
	if b := slot.entry.branch; b != "" {
		if c.branchCounts[b]--; c.branchCounts[b] <= 0 {
			delete(c.branchCounts, b)
		}
	}
}

// dropExpired removes every entry expired at now. It's called only when
// a limit is reached, not per request.
func (c *registrationCache) dropExpired(now time.Time) {
	for id, slot := range c.entries {
		if !now.Before(slot.entry.expiresAt) {
			c.remove(id)
		}
	}
}

// chainPosition returns, for a Relying Party resolved through chain
// (the Relying Party first, its Trust Anchor last), the immediate
// superior and the branch registrationCache counts it against. A chain
// of one or two entities — a Relying Party that is its own Trust Anchor,
// or one directly under it — has no branch.
func chainPosition(chain []string) (superior, branch string) {
	switch {
	case len(chain) == 0:
		return "", ""
	case len(chain) == 1:
		return chain[0], ""
	case len(chain) == 2:
		return chain[1], ""
	default:
		return chain[1], chain[len(chain)-2]
	}
}
