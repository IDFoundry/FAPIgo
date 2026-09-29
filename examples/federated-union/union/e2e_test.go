package union_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/examples/federated-union/internal/demonet"
	"github.com/idfoundry/fapigo/examples/federated-union/union"
)

// startUnion runs the whole federation on a free local port.
func startUnion(t *testing.T) (*union.World, *demonet.Net) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	n, err := demonet.New(listener.Addr().String(), union.Hosts(), "")
	if err != nil {
		t.Fatalf("demonet.New: %v", err)
	}
	w, err := union.New(port, n)
	if err != nil {
		t.Fatalf("union.New: %v", err)
	}
	srv := &http.Server{Handler: w.Handler()}
	go func() { _ = srv.Serve(tls.NewListener(listener, n.ServerTLS())) }()
	t.Cleanup(func() { _ = srv.Close() })
	return w, n
}

type browser struct {
	t *testing.T
	c *http.Client
}

func newBrowser(t *testing.T, n *demonet.Net) browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return browser{t: t, c: n.Browser(jar)}
}

func (b browser) get(u string) (int, string, *url.URL) {
	b.t.Helper()
	res, err := b.c.Get(u)
	if err != nil {
		b.t.Fatalf("GET %s: %v", u, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body), res.Request.URL
}

func (b browser) post(u string, form url.Values) (int, string, *url.URL) {
	b.t.Helper()
	res, err := b.c.PostForm(u, form)
	if err != nil {
		b.t.Fatalf("POST %s: %v", u, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body), res.Request.URL
}

func mustContain(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Fatalf("page is missing %q:\n%s", w, body)
		}
	}
}

// signIn runs a sign-in from service with provider, sharing only share.
func signIn(t *testing.T, w *union.World, b browser, service, provider, citizen string, share ...string) (int, string) {
	t.Helper()
	status, body, at := b.get(w.URL(service, "/login?provider="+url.QueryEscape(w.URL(provider, ""))))
	if status != http.StatusOK || at.Hostname() != provider {
		return status, body
	}
	mustContain(t, body, "What may")
	form := url.Values{"citizen": {citizen}, "decision": {"approve"}, "claim": share}
	status, body, _ = b.post(w.URL(provider, "/authorize"), form)
	return status, body
}

func TestCrossBorderSignInSharesOnlyApprovedClaims(t *testing.T) {
	w, n := startUnion(t)
	b := newBrowser(t, n)

	status, body, _ := b.get(w.URL("bank.southport.localhost", "/"))
	if status != http.StatusOK {
		t.Fatalf("bank home = %d:\n%s", status, body)
	}
	if strings.Count(body, "high assurance") < 3 {
		t.Fatalf("bank home doesn't show all three providers as accredited:\n%s", body)
	}

	status, body = signIn(t, w, b, "bank.southport.localhost", "id.eastmark.localhost", "em-3306", "given_name", "family_name", "nationality")
	if status != http.StatusOK {
		t.Fatalf("sign-in = %d:\n%s", status, body)
	}
	mustContain(t, body, "signed in", "cross-border", "Tomas", "Novak", "Eastmark", "not shared")
	if strings.Contains(body, "Linden Square") {
		t.Fatalf("the unshared address reached the bank:\n%s", body)
	}
}

func TestDomesticSignIn(t *testing.T) {
	w, n := startUnion(t)
	status, body := signIn(t, w, newBrowser(t, n), "telco.eastmark.localhost", "id.eastmark.localhost", "em-5512", "given_name")
	if status != http.StatusOK {
		t.Fatalf("sign-in = %d:\n%s", status, body)
	}
	mustContain(t, body, "signed in", "Ilse")
}

func TestForgedAssuranceMarkIsRejected(t *testing.T) {
	w, n := startUnion(t)
	w.Scenes().ForgeEastmarkMark.Store(true)
	b := newBrowser(t, n)

	_, body, _ := b.get(w.URL("bank.southport.localhost", "/"))
	mustContain(t, body, "does not accredit")
	status, body := signIn(t, w, b, "bank.southport.localhost", "id.eastmark.localhost", "em-3306", "given_name")
	if status != http.StatusForbidden {
		t.Fatalf("sign-in with a forged mark = %d, want 403:\n%s", status, body)
	}
}

func TestSuspensionCutsOffCrossBorderOnly(t *testing.T) {
	w, n := startUnion(t)
	w.Scenes().SuspendEastmark.Store(true)

	status, _ := signIn(t, w, newBrowser(t, n), "bank.southport.localhost", "id.eastmark.localhost", "em-3306", "given_name")
	if status != http.StatusForbidden {
		t.Fatalf("cross-border sign-in while suspended = %d, want 403", status)
	}
	status, body := signIn(t, w, newBrowser(t, n), "telco.eastmark.localhost", "id.eastmark.localhost", "em-3306", "given_name")
	if status != http.StatusOK {
		t.Fatalf("domestic sign-in while suspended = %d:\n%s", status, body)
	}
	mustContain(t, body, "signed in")
}

func TestNamingConstraintsContainACompromisedAuthority(t *testing.T) {
	w, n := startUnion(t)
	w.Scenes().CompromiseEastmark.Store(true)
	b := newBrowser(t, n)
	impostor := url.QueryEscape(w.URL("bank.northland.localhost", ""))

	_, body, _ := b.get(w.URL("console.localhost", "/resolve?via=union&subject="+impostor))
	mustContain(t, body, "not trusted", "naming_constraints")
	_, body, _ = b.get(w.URL("console.localhost", "/resolve?via=eastmark&subject="+impostor))
	mustContain(t, body, "Trust Chain, trusting")
}

func TestConsolePagesRender(t *testing.T) {
	w, n := startUnion(t)
	b := newBrowser(t, n)
	for _, path := range []string{"/", "/entity?id=" + url.QueryEscape(w.URL("union.localhost", "")), "/resolve?via=union&subject=" + url.QueryEscape(w.URL("bank.southport.localhost", ""))} {
		status, body, _ := b.get(w.URL("console.localhost", path))
		if status != http.StatusOK {
			t.Fatalf("console %s = %d:\n%s", path, status, body)
		}
	}
	// The resolved bank metadata shows the Union's policy narrowing its
	// grant types.
	_, body, _ := b.get(w.URL("console.localhost", "/resolve?via=union&subject="+url.QueryEscape(w.URL("bank.southport.localhost", ""))))
	mustContain(t, body, "client_credentials", "Metadata after every superior")
}

func TestTourAndSceneReset(t *testing.T) {
	w, n := startUnion(t)
	b := newBrowser(t, n)
	console := w.URL("console.localhost", "/")

	_, body, _ := b.get(console)
	mustContain(t, body, "Start here", "Sign in across a border", "Contain a compromised authority")
	if strings.Contains(body, "Scene on:") {
		t.Fatalf("console warns of a scene with none on:\n%s", body)
	}

	for _, key := range []string{"forge", "suspend"} {
		if status, body, _ := b.post(console+"scene", url.Values{"scene": {key}, "on": {"true"}}); status != http.StatusOK {
			t.Fatalf("turn on %s = %d:\n%s", key, status, body)
		}
	}
	if !w.Scenes().ForgeEastmarkMark.Load() || !w.Scenes().SuspendEastmark.Load() {
		t.Fatal("scene form didn't turn the scenes on")
	}
	// Every page, not just the console, says a scene is on.
	_, body, _ = b.get(w.URL("bank.southport.localhost", "/"))
	mustContain(t, body, "Scene on:", "EastID forges its assurance mark", "Suspend Eastmark", "Turn every scene off")

	if status, body, _ := b.post(console+"scene/reset", nil); status != http.StatusOK {
		t.Fatalf("reset = %d:\n%s", status, body)
	}
	s := w.Scenes()
	if s.ForgeEastmarkMark.Load() || s.SuspendEastmark.Load() || s.CompromiseEastmark.Load() {
		t.Fatal("reset left a scene on")
	}
	_, body, _ = b.get(w.URL("bank.southport.localhost", "/"))
	if strings.Contains(body, "Scene on:") {
		t.Fatalf("bank still warns of a scene after reset:\n%s", body)
	}
}
