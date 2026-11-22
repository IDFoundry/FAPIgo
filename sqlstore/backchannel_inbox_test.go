package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// inboxAddsAcrossHandles is how many adds
// TestBackchannelInboxListsAddsMadeThroughAnotherHandle makes at once.
const inboxAddsAcrossHandles = 64

// inboxEntry is an entry of the subject "s1" named name.
func inboxEntry(name string) storage.NewBackchannelInboxEntry {
	return storage.NewBackchannelInboxEntry{
		HandleHash: sha256.Sum256([]byte("inbox entry " + name)), SubjectKey: "s1", ClientID: "c",
		Record: []byte(`{"v":1}`), ExpiresAt: time.Now().Add(time.Hour),
	}
}

// missingFrom is how many of want inbox lists for "s1" leaves out, or an
// error if it couldn't list.
func missingFrom(inbox storage.BackchannelInbox, want map[[32]byte]bool) (int, error) {
	listed, err := inbox.ListBackchannelRequests(context.Background(), storage.BackchannelInboxListing{SubjectKey: "s1", Now: time.Now()})
	if err != nil {
		return 0, err
	}
	missing := maps.Clone(want)
	for _, entry := range listed {
		delete(missing, entry.HandleHash)
	}
	return len(missing), nil
}

// The CIBA inbox lists, on every instance sharing a database, each add
// that has returned: two handles on one database, each on a *sql.DB of
// its own as two server instances' are, list what the other added,
// before and while both add at once. storage.TestBackchannelInboxContract
// can't show it, with the one store its factory hands each subtest.
func TestBackchannelInboxListsAddsMadeThroughAnotherHandle(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		p.migrated()
		first, _ := p.openPool()
		second, _ := p.openPool()
		inboxes := [2]storage.BackchannelInbox{first.BackchannelInbox(), second.BackchannelInbox()}
		checkAddsListedAcross(t, inboxes)
		checkConcurrentAddsListedAcross(t, inboxes)
	})
}

// checkAddsListedAcross adds an entry through each of inboxes in turn,
// and lists through the other: each listing includes every entry added
// so far.
func checkAddsListedAcross(t *testing.T, inboxes [2]storage.BackchannelInbox) {
	t.Helper()
	want := map[[32]byte]bool{}
	for i, name := range []string{"through the first", "through the second"} {
		entry := inboxEntry(name)
		must(t, inboxes[i].AddBackchannelRequest(context.Background(), entry))
		want[entry.HandleHash] = true
		missing, err := missingFrom(inboxes[1-i], want)
		must(t, err)
		if missing != 0 {
			t.Fatalf("a listing through the other handle, after an add %s returned, left out %d of %d entries", name, missing, len(want))
		}
	}
}

// checkConcurrentAddsListedAcross adds inboxAddsAcrossHandles entries
// at once, through both of inboxes in turn, each adder then listing
// through the other handle: each listing includes every entry whose add
// had returned before it began, the adder's own among them.
func checkConcurrentAddsListedAcross(t *testing.T, inboxes [2]storage.BackchannelInbox) {
	t.Helper()
	var mu sync.Mutex
	added := map[[32]byte]bool{}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range inboxAddsAcrossHandles {
		wg.Go(func() {
			<-start
			entry := inboxEntry(fmt.Sprintf("concurrent %d", i))
			if err := inboxes[i%2].AddBackchannelRequest(context.Background(), entry); err != nil {
				t.Errorf("AddBackchannelRequest: %v", err)
				return
			}
			mu.Lock()
			added[entry.HandleHash] = true
			want := maps.Clone(added)
			mu.Unlock()
			missing, err := missingFrom(inboxes[1-i%2], want)
			if err != nil || missing != 0 {
				t.Errorf("a listing through the other handle begun after %d adds had returned left out %d of them (%v)", len(want), missing, err)
			}
		})
	}
	close(start)
	wg.Wait()
}
