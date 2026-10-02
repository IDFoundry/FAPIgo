package linked_test

import (
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/examples/internal/demokit"
	"github.com/idfoundry/fapigo/examples/linked-accounts/linked"
)

// demo is the whole demo running on a free local port, and a browser.
type demo struct {
	t     *testing.T
	world *linked.World
	http  *http.Client
	// interaction is the last consent form's interactioncookie tag.
	interaction string
}

func start(t *testing.T) *demo {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n, err := demokit.New(listener.Addr().String(), linked.Hosts(), "", "Test CA")
	if err != nil {
		t.Fatalf("demokit.New: %v", err)
	}
	world, err := linked.New(listener.Addr().(*net.TCPAddr).Port, n)
	if err != nil {
		t.Fatalf("linked.New: %v", err)
	}
	srv := &http.Server{Handler: world.Handler(), TLSConfig: n.ServerTLS(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &demo{t: t, world: world, http: n.Browser(jar)}
}

func (d *demo) get(host, path string) string {
	d.t.Helper()
	res, err := d.http.Get(d.world.URL(host, path))
	if err != nil {
		d.t.Fatalf("GET %s%s: %v", host, path, err)
	}
	return d.page(res)
}

func (d *demo) post(host, path string, form url.Values) string {
	d.t.Helper()
	res, err := d.http.PostForm(d.world.URL(host, path), withInteraction(path, d.interaction, form))
	if err != nil {
		d.t.Fatalf("POST %s%s: %v", host, path, err)
	}
	return d.page(res)
}

// interactionField finds the consent form's interactioncookie tag.
var interactionField = regexp.MustCompile(`name="interaction" value="([^"]*)"`)

// page reads res's body, remembering any consent form's tag in it.
func (d *demo) page(res *http.Response) string {
	body := readBody(d.t, res)
	if m := interactionField.FindStringSubmatch(body); m != nil {
		d.interaction = m[1]
	}
	return body
}

// withInteraction adds the last consent form's tag to a submission of
// it, as a browser submitting that form would.
func withInteraction(path, interaction string, form url.Values) url.Values {
	if path != "/authorize" || form.Has("interaction") || interaction == "" {
		return form
	}
	out := url.Values{"interaction": {interaction}}
	for k, v := range form {
		out[k] = v
	}
	return out
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func mustContain(t *testing.T, where, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("%s doesn't show %q", where, want)
		}
	}
}

const (
	everyday = "XA21ALDR00001234567890"
	savings  = "XA87ALDR00009876543210"
)

// linkAccounts links Pocketwise to the given accounts and returns
// Pocketwise's page.
func (d *demo) linkAccounts(accounts ...string) string {
	d.t.Helper()
	consent := d.post("pocketwise.localhost", "/link", nil)
	mustContain(d.t, "the consent page", consent, "Pocketwise", "read balances, read transactions", "Joint with Alex")
	return d.post("bank.localhost", "/authorize", url.Values{
		"decision": {"approve"}, "username": {"sam"}, "pin": {"2468"}, "account": accounts,
	})
}

// latestLog is the newest sync log entry on a Pocketwise page.
func latestLog(page string) string {
	i := strings.Index(page, "<h2>Sync log</h2>")
	rows := page[i:]
	start := strings.Index(rows, "<tr><td class=\"muted\">")
	end := strings.Index(rows[start:], "</tr>")
	return rows[start : start+end]
}

func TestLinkAndSync(t *testing.T) {
	d := start(t)
	page := d.linkAccounts(everyday, savings)
	mustContain(t, "Pocketwise after linking", page, `pill ok">linked`, "Everyday", "Savings", "First sync")
	if strings.Contains(page, "Joint with Alex") && strings.Contains(page, "XA43ALDR00005555222211</span></td>") {
		t.Error("Pocketwise reads the joint account Sam didn't share")
	}

	page = d.post("pocketwise.localhost", "/sync", nil)
	mustContain(t, "a sync", latestLog(page), `pill ok">ok`, "Read Everyday, Savings")
	mustContain(t, "a sync", page, "Token request: refresh", "not rotated")

	d.post("pocketwise.localhost", "/rotate-key", nil)
	d.post("console.localhost", "/clock", url.Values{"days": {"1"}})
	page = d.post("pocketwise.localhost", "/sync", nil)
	mustContain(t, "a sync after rotating the DPoP key", latestLog(page), `pill ok">ok`, "Read Everyday, Savings")
}

func TestAttacks(t *testing.T) {
	d := start(t)
	d.linkAccounts(everyday)
	kinds := map[string]string{
		"thriftly":       "invalid_grant",
		"no-client-auth": "invalid_client",
		"widen":          "invalid_scope",
		"other-key":      "invalid_token",
	}
	for kind := range kinds {
		d.post("pocketwise.localhost", "/attack", url.Values{"kind": {kind}})
	}
	page := d.get("pocketwise.localhost", "/")
	if refused, allowed := strings.Count(page, `pill ok">refused`), strings.Count(page, `pill bad">allowed`); refused != len(kinds) || allowed != 0 {
		t.Errorf("attacks: %d refused, %d allowed; want all %d refused", refused, allowed, len(kinds))
	}
	attempts := page[strings.Index(page, `id="attempts"`):strings.Index(page, "<h2>Sync log</h2>")]
	for kind, want := range kinds {
		if !strings.Contains(attempts, want) {
			t.Errorf("attack %s: no %s among the refusals", kind, want)
		}
	}
	t.Log(attempts)
}

func TestRevokeFromConnectedApps(t *testing.T) {
	d := start(t)
	d.linkAccounts(everyday)
	apps := d.get("bank.localhost", "/connected-apps")
	mustContain(t, "Connected apps", apps, "Pocketwise", `pill ok">active`, "Everyday ····7890")
	grantID := regexp.MustCompile(`name="grant_id" value="([A-Za-z0-9]+)"`).FindStringSubmatch(apps)
	if grantID == nil {
		t.Fatalf("no grant to revoke:\n%s", apps)
	}
	apps = d.post("bank.localhost", "/connected-apps", url.Values{"grant_id": {grantID[1]}})
	mustContain(t, "Connected apps after revoking", apps, `pill bad">revoked`)

	page := d.post("pocketwise.localhost", "/sync", nil)
	log := page[strings.Index(page, "<h2>Sync log</h2>"):]
	mustContain(t, "the sync after revocation", log, "invalid_grant", "the grant has been revoked", "Sync: the last access token", "invalid_token")
	// Newest first: the sync's two entries come before the first sync's.
	if strings.Count(log[:strings.Index(log, "First sync")], `pill ok">ok`) != 0 {
		t.Errorf("a sync step succeeded after revocation:\n%s", log)
	}
}

func TestConsentExpires(t *testing.T) {
	d := start(t)
	d.linkAccounts(everyday)
	d.post("console.localhost", "/clock", url.Values{"days": {"91"}})
	page := d.post("pocketwise.localhost", "/sync", nil)
	mustContain(t, "the sync after 91 days", page, "invalid_grant")
	mustContain(t, "Connected apps after 91 days", d.get("bank.localhost", "/connected-apps"), `pill bad">expired`)
}
