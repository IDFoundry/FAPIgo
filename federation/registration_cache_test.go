package federation

import (
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

var cacheTestNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func cacheEntry(superior, branch string, expiresAt time.Time) cachedClient {
	return cachedClient{superior: superior, branch: branch, expiresAt: expiresAt}
}

func rpID(prefix string, i int) fapi.ClientID {
	return fapi.ClientID(fmt.Sprintf("https://%s%d.example", prefix, i))
}

// TestRegistrationCacheContainsOneSuperiorsLeaves: an intermediate that
// mints more Relying Parties than maxCachedPerSuperior only ever
// displaces its own, oldest first, and a Relying Party under another
// superior is still cached and stays cached.
func TestRegistrationCacheContainsOneSuperiorsLeaves(t *testing.T) {
	c := newRegistrationCache()
	valid := cacheTestNow.Add(time.Hour)
	if !c.put("https://honest-rp.example", cacheEntry("https://honest-int.example", "https://honest-int.example", valid), cacheTestNow) {
		t.Fatal("honest registration not cached")
	}
	for i := range maxCachedPerSuperior * 3 {
		c.put(rpID("attack", i), cacheEntry("https://evil-int.example", "https://evil-int.example", valid), cacheTestNow)
	}
	if got := c.bySuperior["https://evil-int.example"].Len(); got != maxCachedPerSuperior {
		t.Fatalf("attacker's superior holds %d entries, want its quota %d", got, maxCachedPerSuperior)
	}
	if _, ok := c.get("https://honest-rp.example", cacheTestNow); !ok {
		t.Fatal("the attacker's registrations displaced another superior's")
	}
	// The attacker's newest registrations are the ones kept.
	if _, ok := c.entries[rpID("attack", 0)]; ok {
		t.Fatal("the attacker's oldest registration is still cached")
	}
	if _, ok := c.entries[rpID("attack", maxCachedPerSuperior*3-1)]; !ok {
		t.Fatal("the attacker's newest registration isn't cached")
	}
	if !c.put("https://second-honest.example", cacheEntry("https://other-int.example", "https://other-int.example", valid), cacheTestNow) {
		t.Fatal("a Relying Party under another superior wasn't cached after the attack")
	}
}

// TestRegistrationCacheBoundsABranch: intermediates minted beneath one
// intermediate are each a new immediate superior, but share the branch
// the Trust Anchor vouched for. Once that branch is full, a new entry in
// it isn't cached, and nothing outside the branch is evicted for it.
func TestRegistrationCacheBoundsABranch(t *testing.T) {
	c := newRegistrationCache()
	valid := cacheTestNow.Add(time.Hour)
	c.put("https://outside.example", cacheEntry("https://other-int.example", "https://other-int.example", valid), cacheTestNow)
	n := 0
	for s := 0; n < maxCachedPerBranch; s++ {
		sup := fmt.Sprintf("https://sub%d.evil-int.example", s)
		for i := 0; i < maxCachedPerSuperior/2 && n < maxCachedPerBranch; i++ {
			if !c.put(rpID(fmt.Sprintf("s%d-", s), i), cacheEntry(sup, "https://evil-int.example", valid), cacheTestNow) {
				t.Fatalf("entry %d refused before the branch filled", n)
			}
			n++
		}
	}
	if got := c.branchCounts["https://evil-int.example"]; got != maxCachedPerBranch {
		t.Fatalf("branch holds %d, want %d", got, maxCachedPerBranch)
	}
	if c.put("https://one-more.example", cacheEntry("https://new-sub.evil-int.example", "https://evil-int.example", valid), cacheTestNow) {
		t.Fatal("an entry past its branch's cap was cached")
	}
	if _, ok := c.get("https://outside.example", cacheTestNow); !ok {
		t.Fatal("an entry outside the full branch was evicted")
	}
	// Once the branch's entries expire, it accepts new ones again.
	later := valid.Add(time.Second)
	if !c.put("https://one-more.example", cacheEntry("https://new-sub.evil-int.example", "https://evil-int.example", later.Add(time.Hour)), later) {
		t.Fatal("branch didn't accept a new entry after its old ones expired")
	}
}

// TestRegistrationCacheGlobalCapNeverEvictsValidEntries: when the whole
// cache is full of still-valid entries, a new one under a superior below
// its quota isn't cached; no other superior's entry is evicted for it.
func TestRegistrationCacheGlobalCapNeverEvictsValidEntries(t *testing.T) {
	c := newRegistrationCache()
	valid := cacheTestNow.Add(time.Hour)
	for i := range maxCachedRegistrations {
		// Directly under the Trust Anchor: no branch, so only the global
		// cap applies.
		c.put(rpID("ta", i), cacheEntry("https://ta.example", "", valid), cacheTestNow)
	}
	if c.len() != maxCachedRegistrations {
		t.Fatalf("cache holds %d, want %d", c.len(), maxCachedRegistrations)
	}
	if c.put("https://new.example", cacheEntry("https://int.example", "https://int.example", valid), cacheTestNow) {
		t.Fatal("a new entry was cached in a full cache with nothing expired")
	}
	if _, ok := c.entries[rpID("ta", 0)]; !ok {
		t.Fatal("a still-valid entry was evicted")
	}
}

// TestRegistrationCacheTrustAnchorLeavesHaveNoQuota: Relying Parties
// directly under a Trust Anchor can't mint siblings, so they count only
// against the global cap, not against maxCachedPerSuperior.
func TestRegistrationCacheTrustAnchorLeavesHaveNoQuota(t *testing.T) {
	c := newRegistrationCache()
	valid := cacheTestNow.Add(time.Hour)
	for i := range maxCachedPerSuperior + 10 {
		if !c.put(rpID("ta", i), cacheEntry("https://ta.example", "", valid), cacheTestNow) {
			t.Fatalf("Trust Anchor leaf %d refused below the global cap", i)
		}
	}
	if got := c.bySuperior["https://ta.example"].Len(); got != maxCachedPerSuperior+10 {
		t.Fatalf("Trust Anchor leaves cached = %d, want %d", got, maxCachedPerSuperior+10)
	}
}

// TestRegistrationCacheRefreshKeepsOneEntry: re-caching a client_id
// replaces its entry and moves it to the back of its superior's order,
// without counting it twice.
func TestRegistrationCacheRefreshKeepsOneEntry(t *testing.T) {
	c := newRegistrationCache()
	sup, br := "https://int.example", "https://int.example"
	c.put("https://a.example", cacheEntry(sup, br, cacheTestNow.Add(time.Hour)), cacheTestNow)
	c.put("https://b.example", cacheEntry(sup, br, cacheTestNow.Add(time.Hour)), cacheTestNow)
	c.put("https://a.example", cacheEntry(sup, br, cacheTestNow.Add(2*time.Hour)), cacheTestNow)
	if c.len() != 2 || c.branchCounts[br] != 2 || c.bySuperior[sup].Len() != 2 {
		t.Fatalf("after refresh: len %d, branch %d, superior %d, want 2 each", c.len(), c.branchCounts[br], c.bySuperior[sup].Len())
	}
	if got := c.bySuperior[sup].Front().Value.(fapi.ClientID); got != "https://b.example" {
		t.Fatalf("oldest after refresh = %q, want b (a was refreshed)", got)
	}
	if got := c.entries["https://a.example"].entry.expiresAt; !got.Equal(cacheTestNow.Add(2 * time.Hour)) {
		t.Fatalf("refreshed expiry = %v", got)
	}
}

// TestRegistrationCacheExpiredLookupReleasesQuota: an entry found
// expired on lookup is removed, freeing its superior's and branch's
// counts.
func TestRegistrationCacheExpiredLookupReleasesQuota(t *testing.T) {
	c := newRegistrationCache()
	sup, br := "https://int.example", "https://int.example"
	c.put("https://a.example", cacheEntry(sup, br, cacheTestNow.Add(time.Minute)), cacheTestNow)
	if _, ok := c.get("https://a.example", cacheTestNow.Add(2*time.Minute)); ok {
		t.Fatal("expired entry returned")
	}
	if c.len() != 0 || c.branchCounts[br] != 0 || c.bySuperior[sup] != nil {
		t.Fatalf("expired entry left counts: len %d, branch %d, superior list %v", c.len(), c.branchCounts[br], c.bySuperior[sup])
	}
}

// TestChainPosition: the immediate superior is the chain's second
// entry, and the branch is the Trust Anchor's own subordinate, with no
// branch for a Relying Party directly under (or being) its Trust Anchor.
func TestChainPosition(t *testing.T) {
	for _, tc := range []struct {
		chain            []string
		superior, branch string
	}{
		{nil, "", ""},
		{[]string{"ta"}, "ta", ""},
		{[]string{"rp", "ta"}, "ta", ""},
		{[]string{"rp", "int", "ta"}, "int", "int"},
		{[]string{"rp", "sub", "int", "ta"}, "sub", "int"},
	} {
		sup, br := chainPosition(tc.chain)
		if sup != tc.superior || br != tc.branch {
			t.Errorf("chainPosition(%v) = %q, %q, want %q, %q", tc.chain, sup, br, tc.superior, tc.branch)
		}
	}
}
