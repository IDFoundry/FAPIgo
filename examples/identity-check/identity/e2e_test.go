package identity_test

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

	"github.com/idfoundry/fapigo/examples/identity-check/identity"
	"github.com/idfoundry/fapigo/examples/internal/demokit"
)

// demo is the whole demo running on a free local port, and a browser.
type demo struct {
	t     *testing.T
	world *identity.World
	http  *http.Client
}

func start(t *testing.T) *demo {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n, err := demokit.New(listener.Addr().String(), identity.Hosts(), "", "Test CA")
	if err != nil {
		t.Fatalf("demokit.New: %v", err)
	}
	world, err := identity.New(listener.Addr().(*net.TCPAddr).Port, n)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
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
	return readBody(d.t, res)
}

func (d *demo) post(host, path string, form url.Values) (string, string) {
	d.t.Helper()
	res, err := d.http.PostForm(d.world.URL(host, path), form)
	if err != nil {
		d.t.Fatalf("POST %s%s: %v", host, path, err)
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

var allClaims = []string{"given_name", "family_name", "birthdate", "address", "email", "phone_number"}

// verify starts an identity check at host and answers the bank's page:
// sign in by method, sharing claims. It returns the check page.
func (d *demo) verify(host, method string, claims []string) (string, string) {
	d.t.Helper()
	consent, at := d.post(host, "/start", url.Values{"scenario": {"normal"}})
	if !strings.Contains(at, "bank.localhost") {
		d.t.Fatalf("the check landed on %s, want Alder Bank; page:\n%s", at, consent)
	}
	return d.post("bank.localhost", "/authorize", url.Values{
		"decision": {"approve"}, "username": {"sam"}, "pin": {"2468"}, "method": {method}, "claim": claims,
	})
}

func TestVerifyWithFernway(t *testing.T) {
	d := start(t)
	consent, _ := d.post("fernway.localhost", "/start", url.Values{"scenario": {"normal"}})
	mustContain(t, "the consent page", consent, "Fernway", "Date of birth", "Home address", "approved in the Alder Bank app", "10m0s")

	page, at := d.post("bank.localhost", "/authorize", url.Values{
		"decision": {"approve"}, "username": {"sam"}, "pin": {"2468"}, "method": {"app"}, "claim": allClaims,
	})
	if !strings.Contains(at, "fernway.localhost") || !strings.Contains(at, "/check?id=") {
		t.Fatalf("approval landed on %s:\n%s", at, page)
	}
	mustContain(t, "the verified check", page, `pill ok">verified`,
		"Rivera", "1991-04-12", "14 Quay Street", "sam.rivera@example.com", "urn:alder-bank:acr:app",
		"Pushed authorization request (PAR)", "max_age: 600", "acr_values: urn:alder-bank:acr:app",
		"encrypted (JWE, 5 parts)", "UserInfo request")
}

func TestWithheldClaimsStayWithheld(t *testing.T) {
	d := start(t)
	page, _ := d.verify("fernway.localhost", "app", []string{"given_name", "family_name", "birthdate", "email"})
	mustContain(t, "the verified check", page, `pill ok">verified`, "sam.rivera@example.com")
	if strings.Contains(page, "Quay Street") || strings.Contains(page, "+44") {
		t.Fatalf("the check shows a withheld claim:\n%s", page)
	}
	id := regexp.MustCompile(`name="id" value="([A-Z0-9]+)"`).FindStringSubmatch(page)
	if id == nil {
		t.Fatalf("no check ID:\n%s", page)
	}
	page, _ = d.post("fernway.localhost", "/attack", url.Values{"id": {id[1]}, "kind": {"withheld"}})
	mustContain(t, "asking again", page, `pill ok">refused`, "still withheld: address, phone_number")
}

func TestWeakOrOldSignInIsRefused(t *testing.T) {
	for _, tc := range []struct{ method, want string }{
		{"pin", "acr urn:alder-bank:acr:pin"},
		{"remembered", "login_required"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			d := start(t)
			page, _ := d.verify("fernway.localhost", tc.method, allClaims)
			mustContain(t, "the check", page, `pill bad">not verified`, tc.want)
		})
	}
}

func TestAttacks(t *testing.T) {
	d := start(t)
	page, _ := d.verify("fernway.localhost", "app", allClaims)
	id := regexp.MustCompile(`name="id" value="([A-Z0-9]+)"`).FindStringSubmatch(page)
	if id == nil {
		t.Fatalf("no check ID:\n%s", page)
	}
	kinds := []string{"eavesdrop", "swap-alex", "swap-brightline", "other-userinfo", "tamper-userinfo", "stolen"}
	for _, kind := range kinds {
		d.post("fernway.localhost", "/attack", url.Values{"id": {id[1]}, "kind": {kind}})
	}
	page = d.get("fernway.localhost", "/check?id="+id[1])
	if refused, allowed := strings.Count(page, `pill ok">refused`), strings.Count(page, `pill bad">allowed`); refused != len(kinds) || allowed != 0 {
		t.Errorf("attacks: %d refused, %d allowed; want all %d refused\n%s", refused, allowed, len(kinds), page)
	}
	t.Log(page[strings.Index(page, `id="attempts"`):strings.Index(page, "Protocol trace")])
}

func TestVerifyWithBrightline(t *testing.T) {
	d := start(t)
	page, _ := d.verify("brightline.localhost", "pin", []string{"given_name", "family_name", "birthdate"})
	mustContain(t, "Brightline's check", page, `pill ok">verified`, "Rivera", "signed (JWS)")
	if strings.Contains(page, "Quay Street") {
		t.Error("Brightline shows the address Sam withheld")
	}
}
