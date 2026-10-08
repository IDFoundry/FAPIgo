package payroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/storage"
)

const ledgerlineName = "Ledgerline"

// employee is one of Harbour Coffee's staff, paid monthly.
type employee struct {
	Name, IBAN string
	Pay        int64 // cents
}

var harbourStaff = []employee{
	{"Maya Chen", "XA11ALDR00003100000101", 2150_00},
	{"Tomás Ferreira", "XA27BRKE00003100000102", 1980_00},
	{"Aisha Okafor", "XA43ALDR00003100000103", 2310_00},
	{"Jonas Lindqvist", "XA59NRDB00003100000104", 1760_00},
	{"Priya Nair", "XA75ALDR00003100000105", 1840_00},
	{"Leo Brandt", "XA91BRKE00003100000106", 1690_00},
	{"Sofia Rossi", "XA08ALDR00003100000107", 2040_00},
	{"Kwame Mensah", "XA24NRDB00003100000108", 1720_00},
	{"Hana Sato", "XA40ALDR00003100000109", 1880_00},
	{"Ruairí Byrne", "XA56BRKE00003100000110", 1610_00},
	{"Elena Popescu", "XA72ALDR00003100000111", 1930_00},
	{"Noah Fischer", "XA88NRDB00003100000112", 1930_00},
}

const payrollReference = "Harbour Coffee payroll, October"

func payrollTotal() int64 {
	var total int64
	for _, e := range harbourStaff {
		total += e.Pay
	}
	return total
}

// ledgerline is Ledgerline, a payroll provider: it runs Harbour Coffee's
// payroll through Alder Bank's API, and the attack lab against it.
type ledgerline struct {
	w     *World
	certs certificates
	// client presents Ledgerline's current certificate. The others are
	// the same client software presenting another certificate, or none.
	client                                                          *lazyClient
	noCert, selfSigned, impostor, expired, leaked, retired, copperf *lazyClient

	mu       sync.Mutex
	current  *tls.Certificate // Ledgerline's certificate now
	runs     map[string]*run
	attempts []attempt // the attack lab's token requests, newest first
	rotation *rotation
}

// run is one payroll run: a token request, then the batch.
type run struct {
	ID      string
	Status  string // paid, failed
	Problem string
	trace   *trace
	// token, and the certificate it was issued to.
	token    client.ClientCredentialsTokenResult
	boundTo  *x509.Certificate
	Payment  *apiResponse
	Attempts []attempt
}

type attempt struct {
	Title, Result string
	Refused       bool
	Trace         []traceStep
}

type apiResponse struct {
	Status int
	Body   string
}

func (r apiResponse) OK() bool { return r.Status/100 == 2 }

// rotation is what the rotation panel showed last.
type rotation struct {
	Old, New certificateView
	Steps    []attempt
}

func (w *World) newLedgerline(certs certificates) *ledgerline {
	l := &ledgerline{w: w, certs: certs, current: certs.ledgerline, runs: map[string]*run{}}
	fixed := func(cert *tls.Certificate) *lazyClient {
		return &lazyClient{w: w, cert: func() *tls.Certificate { return cert }}
	}
	l.client = &lazyClient{w: w, cert: l.currentCertificate}
	l.noCert = fixed(nil)
	l.selfSigned = fixed(certs.selfSigned)
	l.impostor = fixed(certs.impostor)
	l.expired = fixed(certs.expired)
	l.leaked = fixed(certs.leaked)
	l.retired = fixed(certs.retired)
	l.copperf = fixed(certs.copperfield)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", l.home)
	mux.HandleFunc("GET /run", l.show)
	protect := http.NewCrossOriginProtection()
	for path, h := range map[string]http.HandlerFunc{"/run": l.runPayroll, "/attack": l.attack, "/run/attack": l.attackRun, "/rotate": l.rotate} {
		mux.Handle("POST "+path, protect.Handler(h))
	}
	w.router[ledgerlineHost] = mux
	return l
}

func (l *ledgerline) currentCertificate() *tls.Certificate {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.current
}

// lazyClient is a FAPIgo client presenting the certificate cert returns,
// built from Alder Bank's published metadata the first time it's needed
// (the bank isn't listening yet when the demo starts).
type lazyClient struct {
	w    *World
	cert func() *tls.Certificate

	mu sync.Mutex
	c  *client.Client
}

func (l *lazyClient) get(ctx context.Context) (*client.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c != nil {
		return l.c, nil
	}
	fetcher, err := l.w.fetcher(ledgerlineHost)
	if err != nil {
		return nil, err
	}
	issuer, err := fapi.ParseIssuerURL(l.w.URL(bankHost, ""))
	if err != nil {
		return nil, err
	}
	discovered, err := client.Discover(ctx, fetcher, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover Alder Bank: %w", err)
	}
	// Token requests go to the bank's mTLS endpoint alias (RFC 8705 §5),
	// the host that asks for a client certificate. There's no
	// redirect-based flow: client credentials only.
	endpoints := discovered.Endpoints
	if discovered.MTLSEndpointAliases == nil || !discovered.MTLSEndpointAliases.ApplyForClientAuth(&endpoints) {
		return nil, errors.New("the bank advertises no mTLS token endpoint")
	}
	endpoints.Authorization, endpoints.PushedAuthorizationRequest = fapi.URL{}, fapi.URL{}
	c, err := client.NewFromDiscovery(discovered, client.Config{
		ClientID: ledgerlineClientID, Endpoints: endpoints,
		Profile: client.ProfileFAPISecurity, Assurance: client.AssuranceDevelopment,
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		Limits:                         client.RecommendedLimits(),
		// RFC 8705: the client authenticates with its TLS certificate,
		// and its tokens are bound to it. The certificate is the HTTP
		// client's own business: FAPIgo never sees its key, and with
		// nothing else to sign, the client needs no Keys of its own.
		ClientAuthMethod: storage.ClientAuthMethodTLSClientAuth,
		SenderConstrain:  storage.SenderConstrainMTLS,
		OAuthOnly:        true,
	}, client.Dependencies{
		HTTP:  tracingClient{next: l.w.net.ClientWithCertificate(ledgerlineHost, l.cert), cert: l.cert},
		Clock: client.SystemClock{}, Random: rand.Reader,
	})
	if err != nil {
		return nil, err
	}
	l.c = c
	return c, nil
}

// batchGrant is the payroll_batch Ledgerline asks for: total cents from
// debtor.
func batchGrant(debtor string, total int64) (json.RawMessage, error) {
	return extension.RARSet(payrollBatchType, payrollBatch{
		DebtorAccount: account{IBAN: debtor}, TotalAmount: amount{Currency: "EUR", Amount: decimal(total)},
		NumberOfPayments: len(harbourStaff), Reference: payrollReference,
	})
}

// requestToken asks Alder Bank for a payroll token through lc, for a
// batch of total cents from debtor.
func requestToken(ctx context.Context, lc *lazyClient, debtor string, total int64) (client.ClientCredentialsTokenResult, error) {
	c, err := lc.get(ctx)
	if err != nil {
		return client.ClientCredentialsTokenResult{}, err
	}
	detail, err := batchGrant(debtor, total)
	if err != nil {
		return client.ClientCredentialsTokenResult{}, err
	}
	return c.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{
		Scope: []string{payrollScope}, AuthorizationDetails: []json.RawMessage{detail},
	})
}

// payrollBatchBody is Harbour Coffee's payroll, with extra cents added
// to the first salary.
func payrollBatchBody(extra int64) ([]byte, error) {
	b := batch{DebtorAccount: account{IBAN: harbourIBAN}, Reference: payrollReference}
	for i, e := range harbourStaff {
		pay := e.Pay
		if i == 0 {
			pay += extra
		}
		b.Payments = append(b.Payments, salary{
			CreditorName: e.Name, CreditorAccount: account{IBAN: e.IBAN},
			InstructedAmount: amount{Currency: "EUR", Amount: decimal(pay)},
		})
	}
	return json.Marshal(b)
}

// submit sends the payroll batch (with extra cents) to the API with
// token, through lc: so presenting lc's certificate.
func (l *ledgerline) submit(ctx context.Context, lc *lazyClient, token client.ClientCredentialsTokenResult, extra int64) (apiResponse, error) {
	c, err := lc.get(ctx)
	if err != nil {
		return apiResponse{}, err
	}
	body, err := payrollBatchBody(extra)
	if err != nil {
		return apiResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.w.URL(apiHost, batchesPath), bytes.NewReader(body))
	if err != nil {
		return apiResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Under mTLS the token goes as a plain Bearer token: what binds it
	// is the certificate the connection presents.
	res, err := c.ClientCredentialsResource(token).Do(ctx, req)
	if err != nil {
		return apiResponse{}, err
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		return apiResponse{}, err
	}
	return apiResponse{Status: res.StatusCode, Body: prettyJSON(bytes.TrimSpace(out))}, nil
}

// runPayroll runs Harbour Coffee's payroll: a token for this batch, then
// the batch.
func (l *ledgerline) runPayroll(w http.ResponseWriter, r *http.Request) {
	rn := &run{ID: randomCode(8), trace: &trace{}}
	l.mu.Lock()
	l.runs[rn.ID] = rn
	l.mu.Unlock()
	ctx := withTrace(r.Context(), rn.trace)
	cert := l.currentCertificate()
	token, err := requestToken(ctx, l.client, harbourIBAN, payrollTotal())
	if err != nil {
		// This demo shows err.Error() to the browser, here and below, so
		// each refusal is visible. A real deployment logs internal errors
		// and shows a generic message.
		l.finish(rn, "failed", err.Error(), nil)
		http.Redirect(w, r, runURL(rn.ID), http.StatusSeeOther)
		return
	}
	l.mu.Lock()
	rn.token, rn.boundTo = token, cert.Leaf
	l.mu.Unlock()
	res, err := l.submit(ctx, l.client, rn.token, 0)
	if err != nil {
		l.finish(rn, "failed", err.Error(), nil)
	} else if !res.OK() {
		l.finish(rn, "failed", "Alder Bank refused the batch", &res)
	} else {
		l.finish(rn, "paid", "", &res)
	}
	http.Redirect(w, r, runURL(rn.ID), http.StatusSeeOther)
}

func (l *ledgerline) finish(rn *run, status, problem string, res *apiResponse) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rn.Status, rn.Problem, rn.Payment = status, problem, res
}

func runURL(id string) string { return "/run?id=" + id }

func (l *ledgerline) lookup(id string) (*run, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rn, ok := l.runs[id]
	return rn, ok
}

// tokenAttack is an attack at the bank's token endpoint.
type tokenAttack struct {
	title  string
	client func(*ledgerline) *lazyClient
	debtor string
	total  int64
}

var tokenAttacks = map[string]tokenAttack{
	"no-cert":       {"Ask for a token without a certificate", func(l *ledgerline) *lazyClient { return l.noCert }, harbourIBAN, payrollTotal()},
	"self-signed":   {"Present a self-signed certificate naming Ledgerline", func(l *ledgerline) *lazyClient { return l.selfSigned }, harbourIBAN, payrollTotal()},
	"impostor":      {"Present a certificate naming Ledgerline from another CA", func(l *ledgerline) *lazyClient { return l.impostor }, harbourIBAN, payrollTotal()},
	"expired":       {"Present Ledgerline's expired certificate", func(l *ledgerline) *lazyClient { return l.expired }, harbourIBAN, payrollTotal()},
	"revoked":       {"Present Ledgerline's leaked, revoked certificate", func(l *ledgerline) *lazyClient { return l.leaked }, harbourIBAN, payrollTotal()},
	"retired-ca":    {"Present a certificate from Alder Bank's retired, revoked client CA", func(l *ledgerline) *lazyClient { return l.retired }, harbourIBAN, payrollTotal()},
	"copperfield":   {"Claim to be Ledgerline with Copperfield's certificate", func(l *ledgerline) *lazyClient { return l.copperf }, harbourIBAN, payrollTotal()},
	"other-account": {"Pay from Brightwater Bakery's account", func(l *ledgerline) *lazyClient { return l.client }, brightwaterIBAN, payrollTotal()},
	"over-limit":    {"Pay a €40,000.00 batch", func(l *ledgerline) *lazyClient { return l.client }, harbourIBAN, 40_000_00},
}

// attack runs one of the token endpoint attacks.
func (l *ledgerline) attack(w http.ResponseWriter, r *http.Request) {
	a, ok := tokenAttacks[r.FormValue("kind")]
	if !ok {
		l.w.renderError(w, ledgerlineHost, http.StatusBadRequest, "Unknown attack", r.FormValue("kind"))
		return
	}
	t := &trace{}
	_, err := requestToken(withTrace(r.Context(), t), a.client(l), a.debtor, a.total)
	at := attempt{Title: a.title, Refused: err != nil, Trace: t.Steps()}
	if err != nil {
		at.Result = err.Error()
	} else {
		at.Result = "Alder Bank issued a token."
	}
	l.mu.Lock()
	l.attempts = append([]attempt{at}, l.attempts...)
	l.mu.Unlock()
	http.Redirect(w, r, "/#attempts", http.StatusSeeOther)
}

// attackRun misuses a paid run's token.
func (l *ledgerline) attackRun(w http.ResponseWriter, r *http.Request) {
	rn, ok := l.lookup(r.FormValue("id"))
	if !ok || rn.Status != "paid" {
		l.w.renderError(w, ledgerlineHost, http.StatusNotFound, "No such payroll run", "Run the payroll first.")
		return
	}
	var title string
	var lc *lazyClient
	var extra int64
	switch r.FormValue("kind") {
	case "stolen":
		title, lc = "Use the token without Ledgerline's certificate", l.noCert
	case "stolen-copperfield":
		title, lc = "Use the token with Copperfield's certificate", l.copperf
	case "overspend":
		title, lc, extra = "Add €5,000.00 to the batch", l.client, 5_000_00
	case "again":
		title, lc = "Pay the batch again", l.client
	default:
		l.w.renderError(w, ledgerlineHost, http.StatusBadRequest, "Unknown attack", r.FormValue("kind"))
		return
	}
	t := &trace{}
	res, err := l.submit(withTrace(r.Context(), t), lc, rn.token, extra)
	at := attempt{Title: title, Trace: t.Steps()}
	switch {
	case err != nil:
		at.Result, at.Refused = err.Error(), true
	default:
		at.Result, at.Refused = fmt.Sprintf("%d\n%s", res.Status, res.Body), !res.OK()
	}
	l.mu.Lock()
	rn.Attempts = append(rn.Attempts, at)
	l.mu.Unlock()
	http.Redirect(w, r, runURL(rn.ID)+"#attempts", http.StatusSeeOther)
}

// rotate replaces Ledgerline's certificate with a new one from the
// bank's CA, with the same subject: the registration, which names the
// subject rather than a certificate, doesn't change. Tokens are bound to
// a certificate, though, so one issued before the rotation stops
// working with the new certificate.
func (l *ledgerline) rotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	old := l.currentCertificate()
	var rot rotation
	step := func(title string, refused bool, result string, t *trace) {
		rot.Steps = append(rot.Steps, attempt{Title: title, Refused: refused, Result: result, Trace: t.Steps()})
	}

	before := &trace{}
	token, err := requestToken(withTrace(ctx, before), l.client, harbourIBAN, payrollTotal())
	if err != nil {
		step("Get a token with the old certificate", true, err.Error(), before)
		l.saveRotation(&rot, old, old)
		http.Redirect(w, r, "/#rotation", http.StatusSeeOther)
		return
	}
	step("Get a token with the old certificate", false, "Issued, bound to the old certificate:\n"+tokenBinding(token), before)

	now := time.Now()
	next, err := l.w.clientCA.issue(ledgerlineSubject, now.Add(-time.Minute), now.Add(certificateLifetime))
	if err != nil {
		l.w.renderError(w, ledgerlineHost, http.StatusInternalServerError, "Rotation failed", err.Error())
		return
	}
	l.mu.Lock()
	l.current = next
	l.mu.Unlock()

	reuse := &trace{}
	res, err := l.submit(withTrace(ctx, reuse), l.client, token, 0)
	switch {
	case err != nil:
		step("Use that token with the new certificate", true, err.Error(), reuse)
	default:
		step("Use that token with the new certificate", !res.OK(), fmt.Sprintf("%d\n%s", res.Status, res.Body), reuse)
	}

	after := &trace{}
	fresh, err := requestToken(withTrace(ctx, after), l.client, harbourIBAN, payrollTotal())
	if err != nil {
		step("Get a token with the new certificate", true, err.Error(), after)
	} else {
		step("Get a token with the new certificate", false, "Issued, bound to the new certificate:\n"+tokenBinding(fresh), after)
	}
	l.saveRotation(&rot, old, next)
	http.Redirect(w, r, "/#rotation", http.StatusSeeOther)
}

func (l *ledgerline) saveRotation(rot *rotation, old, next *tls.Certificate) {
	rot.Old, rot.New = describeCertificate(old.Leaf), describeCertificate(next.Leaf)
	l.mu.Lock()
	l.rotation = rot
	l.mu.Unlock()
}

// tokenBinding is the cnf claim of a JWT access token.
func tokenBinding(t client.ClientCredentialsTokenResult) string {
	claims := jwtPayload(t.AccessToken.Reveal())
	var payload struct {
		Cnf json.RawMessage `json:"cnf"`
	}
	if json.Unmarshal(claims, &payload) != nil || payload.Cnf == nil {
		return "(no cnf claim)"
	}
	return `"cnf": ` + prettyJSON(payload.Cnf)
}

// certificateView is a certificate as the dashboard shows it. Chain is
// set only where a page shows it.
type certificateView struct {
	Subject, Issuer, Serial, Thumbprint, Expires, Chain string
}

// chain names the CAs from c up to Alder Bank's root, like
// "ledgerline-payroll ← Alder Bank client CA 2 ← Alder Bank root CA",
// or "" when c doesn't chain to it. It ignores revocation: it's for
// showing, not deciding.
func (w *World) chain(c *x509.Certificate) string {
	chains, err := c.Verify(x509.VerifyOptions{
		Roots: w.rootCA.pool, Intermediates: intermediates(w.clientCA, w.retiredCA),
		CurrentTime: c.NotBefore.Add(time.Minute), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return ""
	}
	names := make([]string, len(chains[0]))
	for i, cert := range chains[0] {
		names[i] = cert.Subject.CommonName
	}
	return strings.Join(names, " ← ")
}

func describeCertificate(c *x509.Certificate) certificateView {
	serial := c.SerialNumber.Text(16)
	if len(serial) > 12 {
		serial = serial[:12] + "…"
	}
	return certificateView{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: serial,
		Thumbprint: thumbprint(c), Expires: c.NotAfter.Format("2 Jan 2006"),
	}
}

type staffRow struct{ Name, IBAN, Pay string }

func (l *ledgerline) home(w http.ResponseWriter, _ *http.Request) {
	l.mu.Lock()
	current := l.current.Leaf
	page := ledgerlinePage{
		Page: l.w.page(ledgerlineName, ledgerlineHost), Certificate: describeCertificate(current),
		Total: euros(payrollTotal()), Limit: euros(mandateLimit),
		Attempts: append([]attempt(nil), l.attempts...), Rotation: l.rotation,
	}
	l.mu.Unlock()
	page.Certificate.Chain = l.w.chain(current)
	for _, e := range harbourStaff {
		page.Staff = append(page.Staff, staffRow{Name: e.Name, IBAN: e.IBAN, Pay: euros(e.Pay)})
	}
	l.w.render(w, "ledgerline-home", page)
}

func (l *ledgerline) show(w http.ResponseWriter, r *http.Request) {
	rn, ok := l.lookup(r.URL.Query().Get("id"))
	if !ok {
		l.w.renderError(w, ledgerlineHost, http.StatusNotFound, "No such payroll run", "This run doesn't exist, or the demo has restarted since.")
		return
	}
	l.mu.Lock()
	view := runView{ID: rn.ID, Status: rn.Status, Problem: rn.Problem, Payment: rn.Payment, Attempts: append([]attempt(nil), rn.Attempts...)}
	if rn.boundTo != nil {
		c := describeCertificate(rn.boundTo)
		c.Chain = l.w.chain(rn.boundTo)
		view.BoundTo = &c
	}
	l.mu.Unlock()
	l.w.render(w, "ledgerline-run", runPage{Page: l.w.page(ledgerlineName, ledgerlineHost), Run: view, Trace: rn.trace.Steps()})
}

// runView is a run as its page shows it.
type runView struct {
	ID, Status, Problem string
	BoundTo             *certificateView
	Payment             *apiResponse
	Attempts            []attempt
}
