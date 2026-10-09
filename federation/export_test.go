package federation

import fapi "github.com/idfoundry/fapigo"

// CachedChainPosition reports where id's cached registration sits in its
// Trust Chain (see chainPosition), for tests in package federation_test.
func CachedChainPosition(r *AutomaticClientRepository, id fapi.ClientID) (superior, branch string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	slot, ok := r.cache.entries[id]
	if !ok {
		return "", "", false
	}
	return slot.entry.superior, slot.entry.branch, true
}
