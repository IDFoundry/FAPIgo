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

// MaxFailedResolutions is maxFailedResolutions, for tests in package
// federation_test.
const MaxFailedResolutions = maxFailedResolutions

// MaxEntityIDBytes is maxEntityIDBytes, for tests in package
// federation_test.
const MaxEntityIDBytes = maxEntityIDBytes

// RetainedStrings returns every string r keeps for the client_ids it
// was asked to resolve: the keys of its in-flight resolutions,
// remembered failures (and their messages) and cached registrations, its
// superiors' lists of those, and each cached registration's own client
// ID and Trust Chain position, for tests in package federation_test.
func RetainedStrings(r *AutomaticClientRepository) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var kept []string
	for id := range r.inflight {
		kept = append(kept, string(id))
	}
	for id, failed := range r.failures {
		kept = append(kept, string(id), failed.err.Error())
	}
	for id, slot := range r.cache.entries {
		kept = append(kept, string(id), string(slot.entry.client.ID()), slot.entry.superior, slot.entry.branch)
	}
	for superior, own := range r.cache.bySuperior {
		kept = append(kept, superior)
		for e := own.Front(); e != nil; e = e.Next() {
			kept = append(kept, string(e.Value.(fapi.ClientID)))
		}
	}
	for branch := range r.cache.branchCounts {
		kept = append(kept, branch)
	}
	return kept
}

// ResolutionState is what r holds for its Trust Chain resolutions, for
// tests in package federation_test: how many are running, how many are
// in flight, how many callers wait on id's, and whether a failure is
// remembered for id.
func ResolutionState(r *AutomaticClientRepository, id fapi.ClientID) (running, inflight, waiters int, remembered bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if call, ok := r.inflight[id]; ok {
		waiters = call.waiters
	}
	_, remembered = r.failures[id]
	return r.running, len(r.inflight), waiters, remembered
}
