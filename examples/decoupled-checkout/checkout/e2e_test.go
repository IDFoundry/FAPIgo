package checkout_test

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

	"github.com/idfoundry/fapigo/examples/decoupled-checkout/checkout"
	"github.com/idfoundry/fapigo/examples/internal/demokit"
)

// demo is the whole demo running on a free local port, and a browser.
type demo struct {
	t     *testing.T
	world *checkout.World
	http  *http.Client
}

func start(t *testing.T) *demo {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n, err := demokit.New(listener.Addr().String(), checkout.Hosts(), "", "Test CA")
	if err != nil {
		t.Fatalf("demokit.New: %v", err)
	}
	world, err := checkout.New(listener.Addr().(*net.TCPAddr).Port, n)
	if err != nil {
		t.Fatalf("checkout.New: %v", err)
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
	return readBody(d.t, res), res.Request.URL.RequestURI()
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

var requestLink = regexp.MustCompile(`/request\?id=([^"&]+)`)

// pendingOnPhone is the auth_req_id of the one request waiting on Sam's
// phone.
func (d *demo) pendingOnPhone() string {
	d.t.Helper()
	m := requestLink.FindAllStringSubmatch(d.get("phone.localhost", "/"), -1)
	if len(m) != 1 {
		d.t.Fatalf("phone shows %d requests, want 1", len(m))
	}
	return m[0][1]
}

// waitFor reloads host's path until it contains want.
func (d *demo) waitFor(host, path, want string) string {
	d.t.Helper()
	var body string
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		if body = d.get(host, path); strings.Contains(body, want) {
			return body
		}
	}
	d.t.Fatalf("%s%s never showed %q; last:\n%s", host, path, want, body)
	return ""
}

func mustContain(t *testing.T, where, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("%s doesn't show %q", where, want)
		}
	}
}

func TestPayAtTheTill(t *testing.T) {
	d := start(t)
	_, order := d.post("till.localhost", "/pay", url.Values{"customer": {"sam"}, "scenario": {"coffee"}})
	id := d.pendingOnPhone()

	approval := d.get("phone.localhost", "/request?id="+id)
	mustContain(t, "the phone", approval, "Harbour Coffee", "€42.50", "name matches account", "Everyday ····7890", "not checked by Alder Bank")

	d.post("phone.localhost", "/decide", url.Values{"id": {id}, "decision": {"approve"}})
	page := d.waitFor("till.localhost", order, "approved")
	mustContain(t, "the till", page, "Paid.", "executed", "payment_initiation")

	for _, kind := range []string{"overcharge", "again", "stolen", "reuse"} {
		d.post("till.localhost", "/attack", url.Values{"id": {orderID(order)}, "kind": {kind}})
	}
	page = d.get("till.localhost", order)
	if refused, allowed := strings.Count(page, `pill ok">refused`), strings.Count(page, `pill bad">allowed`); refused != 4 || allowed != 0 {
		t.Errorf("attacks: %d refused, %d allowed; want all 4 refused\n%s", refused, allowed, page)
	}
	mustContain(t, "the till", page, "approve paying EUR 420.00", "has been made", "invalid_grant")
}

func orderID(orderPath string) string {
	u, _ := url.Parse(orderPath)
	return u.Query().Get("id")
}

func TestMisleadingMessageIsDenied(t *testing.T) {
	d := start(t)
	_, order := d.post("till.localhost", "/pay", url.Values{"customer": {"sam"}, "scenario": {"misleading"}})
	id := d.pendingOnPhone()

	approval := d.get("phone.localhost", "/request?id="+id)
	mustContain(t, "the phone", approval, "€500.00", "Refund of €500 to you", "the device you're using should show the same")

	d.post("phone.localhost", "/decide", url.Values{"id": {id}, "decision": {"deny"}})
	d.waitFor("till.localhost", order, "access_denied")
}

func TestUnknownCustomer(t *testing.T) {
	d := start(t)
	body, _ := d.post("till.localhost", "/pay", url.Values{"customer": {"nobody"}, "scenario": {"coffee"}})
	mustContain(t, "the till", body, "unknown_user_id")
}

func TestLinkPocketwiseSharingLess(t *testing.T) {
	d := start(t)
	_, link := d.post("pocketwise.localhost", "/link", url.Values{"customer": {"sam"}, "scenario": {"accounts"}})
	id := d.pendingOnPhone()

	approval := d.get("phone.localhost", "/request?id="+id)
	mustContain(t, "the phone", approval, "Pocketwise", "Everyday ····7890", "Savings ····3210", "See standing orders")

	// Only the Everyday account, and not standing orders.
	d.post("phone.localhost", "/decide", url.Values{
		"id": {id}, "decision": {"approve"},
		"account": {"XA21ALDR00001234567890"}, "action": {"read_balances", "read_transactions"},
	})
	page := d.waitFor("pocketwise.localhost", link, "linked")
	if allowed, refused := strings.Count(page, `pill ok">allowed`), strings.Count(page, `pill bad">refused`); allowed != 2 || refused != 4 {
		t.Errorf("reads: %d allowed, %d refused; want Everyday's balances and transactions only\n%s", allowed, refused, page)
	}
}

func TestPocketwiseCantAskForPayments(t *testing.T) {
	d := start(t)
	body, _ := d.post("pocketwise.localhost", "/link", url.Values{"customer": {"sam"}, "scenario": {"payment"}})
	mustContain(t, "Pocketwise", body, "invalid_authorization_details")
	if phone := d.get("phone.localhost", "/"); requestLink.MatchString(phone) {
		t.Error("the refused request reached the phone")
	}
}

func TestPhoneRefusesCrossSitePost(t *testing.T) {
	d := start(t)
	d.post("till.localhost", "/pay", url.Values{"customer": {"sam"}, "scenario": {"coffee"}})
	id := d.pendingOnPhone()
	req, err := http.NewRequest(http.MethodPost, d.world.URL("phone.localhost", "/decide"), strings.NewReader(url.Values{"id": {id}, "decision": {"approve"}}.Encode()))
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
	if d.pendingOnPhone() != id {
		t.Error("the request is no longer pending")
	}
}

// TestPocketwiseRefusesForgedPing covers the CIBA ping endpoint: a
// notification without the token Pocketwise sent for that request is
// refused, and doesn't make Pocketwise collect.
func TestPocketwiseRefusesForgedPing(t *testing.T) {
	d := start(t)
	_, link := d.post("pocketwise.localhost", "/link", url.Values{"customer": {"sam"}, "scenario": {"accounts"}})
	authReqID := orderID(link)
	for name, token := range map[string]string{"wrong token": "Bearer guessed", "no token": ""} {
		req, err := http.NewRequest(http.MethodPost, d.world.URL("pocketwise.localhost", "/ciba-notify"), strings.NewReader(`{"auth_req_id":"`+authReqID+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", token)
		}
		res, err := d.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode/100 != 4 {
			t.Errorf("%s: ping = %s, want refused", name, res.Status)
		}
	}
	mustContain(t, "Pocketwise", d.get("pocketwise.localhost", link), "Waiting for Alder Bank")
}
