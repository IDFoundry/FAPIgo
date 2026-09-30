package payment_test

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
	"github.com/idfoundry/fapigo/examples/payment-consent/payment"
)

// demo is the whole demo running on a free local port, and a browser.
type demo struct {
	t     *testing.T
	world *payment.World
	http  *http.Client
}

func start(t *testing.T) *demo {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n, err := demokit.New(listener.Addr().String(), payment.Hosts(), "", "Test CA")
	if err != nil {
		t.Fatalf("demokit.New: %v", err)
	}
	world, err := payment.New(listener.Addr().(*net.TCPAddr).Port, n)
	if err != nil {
		t.Fatalf("payment.New: %v", err)
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

func (d *demo) get(rawURL string) (string, string) {
	d.t.Helper()
	res, err := d.http.Get(rawURL)
	if err != nil {
		d.t.Fatalf("GET %s: %v", rawURL, err)
	}
	return readBody(d.t, res), res.Request.URL.String()
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

// checkout starts a payment and returns the bank's consent page.
func (d *demo) checkout() string {
	d.t.Helper()
	page, at := d.post("shop.localhost", "/pay", url.Values{"scenario": {"normal"}})
	if !strings.Contains(at, "bank.localhost") {
		d.t.Fatalf("checkout landed on %s, want Alder Bank; page:\n%s", at, page)
	}
	return page
}

// approve signs in at the bank and approves, returning the shop's order
// page.
func (d *demo) approve(username, pin string) (string, string) {
	d.t.Helper()
	return d.post("bank.localhost", "/authorize", url.Values{"username": {username}, "pin": {pin}, "decision": {"approve"}})
}

func TestPayByBank(t *testing.T) {
	d := start(t)
	consent := d.checkout()
	mustContain(t, "the consent page", consent, "Northgate Outfitters", "€129.00", "name matches account", "not checked by Alder Bank")

	retry, _ := d.approve("sam", "0000")
	mustContain(t, "a wrong PIN", retry, "username and PIN", "€129.00")

	order, at := d.approve("sam", "2468")
	if !strings.Contains(at, "shop.localhost") {
		t.Fatalf("approval landed on %s", at)
	}
	mustContain(t, "the order", order, "your payment went through", "executed", "Everyday ····7890",
		"Pushed authorization request (PAR)", "signed request object", "Authorization response (JARM)", "Token request", "Payments API call")

	id := regexp.MustCompile(`name="id" value="([A-Z0-9]+)"`).FindStringSubmatch(order)
	if id == nil {
		t.Fatalf("no order ID on the order page:\n%s", order)
	}
	for _, kind := range []string{"overcharge", "again", "stolen", "reuse", "replay", "forged"} {
		d.post("shop.localhost", "/attack", url.Values{"id": {id[1]}, "kind": {kind}})
	}
	page, _ := d.get(d.world.URL("shop.localhost", "/order?id="+id[1]))
	if refused, allowed := strings.Count(page, `pill ok">refused`), strings.Count(page, `pill bad">allowed`); refused != 6 || allowed != 0 {
		t.Errorf("attacks: %d refused, %d allowed; want all 6 refused\n%s", refused, allowed, page)
	}
	mustContain(t, "the attacks", page, "approve paying EUR 1290.00", "has been made", "invalid_grant", "revoked")
}

func TestCancelAtTheBank(t *testing.T) {
	d := start(t)
	d.checkout()
	order, _ := d.post("bank.localhost", "/authorize", url.Values{"decision": {"deny"}})
	mustContain(t, "the order", order, "declined", "access_denied")
}

func TestAttacksBeforePayment(t *testing.T) {
	for _, tc := range []struct {
		name, path, scenario string
		want                 []string
	}{
		{"tampered request object", "/pay", "tamper", []string{"refused", "tampered in flight"}},
		{"unregistered redirect URI", "/pay", "redirect", []string{"refused", "redirect_uri"}},
		{"no PAR", "/direct", "", []string{"refused", "Alder Bank answered"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := start(t)
			page, at := d.post("shop.localhost", tc.path, url.Values{"scenario": {tc.scenario}})
			if strings.Contains(at, "bank.localhost") {
				t.Fatalf("the attack reached the bank's consent page")
			}
			mustContain(t, tc.name, page, tc.want...)
		})
	}
}

func TestAuthorizationCodeInjection(t *testing.T) {
	d := start(t)
	page, _ := d.post("shop.localhost", "/inject", nil)
	link := regexp.MustCompile(`href="(https://shop\.localhost:\d+/callback\?[^"]+)"`).FindStringSubmatch(page)
	if link == nil {
		t.Fatalf("no attacker response on the page:\n%s", page)
	}
	result, _ := d.get(strings.ReplaceAll(link[1], "&amp;", "&"))
	mustContain(t, "the injected response", result, `pill ok">refused`)
	if strings.Contains(result, "your payment went through") {
		t.Error("the attacker's response was accepted in the victim's browser")
	}
}

func TestBankRefusesCrossSiteApproval(t *testing.T) {
	d := start(t)
	d.checkout()
	req, err := http.NewRequest(http.MethodPost, d.world.URL("bank.localhost", "/authorize"),
		strings.NewReader(url.Values{"username": {"sam"}, "pin": {"2468"}, "decision": {"approve"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	res, err := d.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site approval = %s, want 403", res.Status)
	}
}
