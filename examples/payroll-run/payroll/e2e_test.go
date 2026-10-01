package payroll_test

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
	"github.com/idfoundry/fapigo/examples/payroll-run/payroll"
)

// demo is the whole demo running on a free local port, and a browser.
type demo struct {
	t     *testing.T
	world *payroll.World
	http  *http.Client
}

func start(t *testing.T) *demo {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n, err := demokit.New(listener.Addr().String(), payroll.Hosts(), "", "Test CA")
	if err != nil {
		t.Fatalf("demokit.New: %v", err)
	}
	world, err := payroll.New(listener.Addr().(*net.TCPAddr).Port, n)
	if err != nil {
		t.Fatalf("payroll.New: %v", err)
	}
	srv := &http.Server{Handler: world.Handler(), TLSConfig: n.ServerTLS(payroll.ClientCertificateHosts()...), ReadHeaderTimeout: 5 * time.Second}
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
	return readBody(d.t, res)
}

func (d *demo) post(path string, form url.Values) (string, string) {
	d.t.Helper()
	res, err := d.http.PostForm(d.world.URL("ledgerline.localhost", path), form)
	if err != nil {
		d.t.Fatalf("POST %s: %v", path, err)
	}
	return readBody(d.t, res), res.Request.URL.String()
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

// outcomes counts a page's refused and allowed attempts.
func outcomes(page string) (refused, allowed int) {
	return strings.Count(page, `pill ok">refused`), strings.Count(page, `pill bad">allowed`)
}

func TestRunPayroll(t *testing.T) {
	d := start(t)
	page, at := d.post("/run", nil)
	if !strings.Contains(at, "/run?id=") {
		t.Fatalf("the run landed on %s:\n%s", at, page)
	}
	mustContain(t, "the run", page, `pill ok">paid`, "€22,840.00", "Harbour Coffee ····4242", "&#34;payments&#34;: 12",
		"Token request (client credentials)", "TLS client certificate:", "CN=ledgerline-payroll", "x5t#S256", "Payroll API call",
		"ledgerline-payroll ← Alder Bank client CA 2 ← Alder Bank root CA")

	id := regexp.MustCompile(`name="id" value="([A-Z0-9]+)"`).FindStringSubmatch(page)
	if id == nil {
		t.Fatalf("no run ID on the run page:\n%s", page)
	}
	for _, kind := range []string{"stolen", "stolen-copperfield", "overspend", "again"} {
		d.post("/run/attack", url.Values{"id": {id[1]}, "kind": {kind}})
	}
	page = d.get("ledgerline.localhost", "/run?id="+id[1])
	if refused, allowed := outcomes(page); refused != 4 || allowed != 0 {
		t.Errorf("attacks on the token: %d refused, %d allowed; want all 4 refused\n%s", refused, allowed, page)
	}
	mustContain(t, "the attacks on the token", page, "invalid_token", "grants EUR 22840.00 in total, not EUR 27840.00", "has been paid")
}

func TestTokenEndpointAttacks(t *testing.T) {
	d := start(t)
	for _, tc := range []struct{ kind, want string }{
		{"no-cert", "client certificate is required"},
		{"self-signed", "does not chain to a trusted root"},
		{"impostor", "does not chain to a trusted root"},
		{"expired", "does not chain to a trusted root"},
		{"revoked", "revoked"},
		{"retired-ca", "revoked"},
		{"copperfield", "does not match the registered subject"},
		{"other-account", "invalid_authorization_details"},
		{"over-limit", "invalid_authorization_details"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			d.post("/attack", url.Values{"kind": {tc.kind}})
			page := d.get("ledgerline.localhost", "/")
			// The newest attempt is listed first.
			first := page[strings.Index(page, `id="attempts"`):]
			first = first[:strings.Index(first, "</pre>")]
			if !strings.Contains(first, `pill ok">refused`) {
				t.Fatalf("%s wasn't refused:\n%s", tc.kind, first)
			}
			mustContain(t, tc.kind, first, tc.want)
		})
	}
}

func TestRotateCertificate(t *testing.T) {
	d := start(t)
	before := d.get("ledgerline.localhost", "/")
	page, _ := d.post("/rotate", nil)
	rotation := page[strings.Index(page, `id="rotation"`):]
	if refused, allowed := outcomes(rotation); refused != 1 || allowed != 2 {
		t.Fatalf("rotation: %d refused, %d allowed; want the old token refused and both tokens issued\n%s", refused, allowed, rotation)
	}
	mustContain(t, "the rotation", rotation, "Issued, bound to the old certificate", "Issued, bound to the new certificate", "x5t#S256", "invalid_token")

	thumb := regexp.MustCompile(`x5t#S256</dt><dd><code>([A-Za-z0-9_-]+)</code>`)
	old, current := thumb.FindStringSubmatch(before), thumb.FindStringSubmatch(page)
	if old == nil || current == nil || old[1] == current[1] {
		t.Fatalf("Ledgerline's certificate didn't change: before %v, after %v", old, current)
	}

	// A run after the rotation uses the new certificate.
	run, _ := d.post("/run", nil)
	mustContain(t, "a run after rotation", run, `pill ok">paid`, current[1])
}

func TestLedgerlineRefusesCrossSiteRequests(t *testing.T) {
	d := start(t)
	req, err := http.NewRequest(http.MethodPost, d.world.URL("ledgerline.localhost", "/run"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	res, err := d.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site run = %s, want 403", res.Status)
	}
}
