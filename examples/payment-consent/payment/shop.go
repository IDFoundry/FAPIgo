package payment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const (
	shopName      = "Northgate Outfitters"
	callbackPath  = "/callback"
	sessionCookie = "northgate_session"
	orderCookie   = "northgate_order"
	price         = "129.00"
)

// shop is Northgate Outfitters: it takes payment by bank through Alder
// Bank, and runs the attack lab against its own flow.
type shop struct {
	w        *World
	sessions storage.SessionStore
	// client is the shop's FAPIgo client. thief holds the same client
	// software without the shop's DPoP key — what someone who stole an
	// access token could do with it. misdirected registers a redirect
	// URI Alder Bank never saw.
	client, thief, misdirected *lazyClient

	mu     sync.Mutex
	orders map[string]*order
}

// order is one checkout.
type order struct {
	ID, Scenario, Amount string
	Status               string // redirected, paid, declined, failed
	Problem              string
	trace                *trace
	session              client.SessionHandle
	callbackQuery        string
	validated            client.ValidatedAuthorizationResponse
	tokens               client.TokenSet
	Payment              *apiResponse
	Attempts             []attempt
	// Injected is an attacker's authorization response for this
	// browser to open, in the injection attack.
	Injected string
}

type attempt struct {
	Title, Result string
	Refused       bool
}

type apiResponse struct {
	Status int
	Body   string
}

func (r apiResponse) OK() bool { return r.Status/100 == 2 }

func (w *World) newShop(k clientKeys) (*shop, error) {
	thiefKeys, err := newClientKeys("stolen-device")
	if err != nil {
		return nil, err
	}
	s := &shop{w: w, sessions: memstore.NewSessionStore(), orders: map[string]*order{}}
	s.client = &lazyClient{w: w, keys: k, redirect: w.URL(shopHost, callbackPath), sessions: s.sessions}
	s.thief = &lazyClient{w: w, keys: thiefKeys, redirect: w.URL(shopHost, callbackPath), sessions: s.sessions}
	s.misdirected = &lazyClient{w: w, keys: k, redirect: "https://collect.example/callback", sessions: s.sessions}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /order", s.show)
	mux.HandleFunc("GET "+callbackPath, s.callback)
	protect := http.NewCrossOriginProtection()
	for path, h := range map[string]http.HandlerFunc{"/pay": s.pay, "/direct": s.direct, "/inject": s.inject, "/attack": s.attack} {
		mux.Handle("POST "+path, protect.Handler(h))
	}
	w.router[shopHost] = mux
	return s, nil
}

// lazyClient is a FAPIgo client built from Alder Bank's published
// metadata the first time it's needed (the bank isn't listening yet when
// the demo starts).
type lazyClient struct {
	w        *World
	keys     clientKeys
	redirect string
	sessions storage.SessionStore

	mu sync.Mutex
	c  *client.Client
}

func (l *lazyClient) get(ctx context.Context) (*client.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c != nil {
		return l.c, nil
	}
	fetcher, err := l.w.fetcher(shopHost)
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
	issuerKeys, err := discovered.IssuerKeySource(fetcher, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	limits := client.RecommendedLimits()
	limits.MaxIDTokenLifetime = 10 * time.Minute // Alder Bank's (server.RecommendedLimits)
	c, err := client.NewFromDiscovery(discovered, client.Config{
		ClientID: shopClientID, RedirectURI: l.redirect,
		// Message Signing: the request is a signed request object pushed
		// to PAR, and the response comes back signed (JARM).
		Profile:                        client.ProfileFAPISecurityWithMessageSigning,
		Assurance:                      client.AssuranceDevelopment,
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		Algorithms: client.Algorithms{
			ClientAuthentication: fapi.ES256, DPoP: fapi.ES256, IDToken: fapi.ES256,
			RequestObject: fapi.ES256, JARM: fapi.ES256,
		},
		Limits:           limits,
		SenderConstrain:  storage.SenderConstrainDPoP,
		ClientAuthMethod: storage.ClientAuthMethodPrivateKeyJWT,
	}, client.Dependencies{
		Sessions: l.sessions, Keys: l.keys.manager, IssuerKeys: issuerKeys,
		HTTP:  tracingClient{next: l.w.net.Client(shopHost)},
		Clock: client.SystemClock{}, Random: rand.Reader,
	})
	if err != nil {
		return nil, err
	}
	l.c = c
	return c, nil
}

// orderURL is the address of order id's page.
func orderURL(id string) string { return "/order?id=" + id }

func (s *shop) home(w http.ResponseWriter, _ *http.Request) {
	s.w.render(w, "shop-home", s.w.page(shopName, shopHost))
}

func (s *shop) newOrder(scenario string) *order {
	o := &order{ID: randomCode(8), Scenario: scenario, Amount: price, Status: "redirected", trace: &trace{}}
	s.mu.Lock()
	s.orders[o.ID] = o
	s.mu.Unlock()
	return o
}

func (s *shop) lookup(id string) (*order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[id]
	return o, ok
}

func paymentDetail(orderID string) (json.RawMessage, error) {
	return extension.RARSet(paymentInitiationType, paymentInitiation{
		InstructedAmount: amount{Currency: "EUR", Amount: price},
		CreditorName:     shopName, CreditorAccount: account{IBAN: shopIBAN},
		RemittanceMessage: "Order " + orderID,
	})
}

// begin pushes the payment request to Alder Bank and returns where to
// send the browser. The FAPIgo client signs the request object, adds
// PKCE and a DPoP key binding, and pushes it to PAR.
func (s *shop) begin(ctx context.Context, o *order, lc *lazyClient, tamper bool) (client.AuthorizationSession, error) {
	c, err := lc.get(ctx)
	if err != nil {
		return client.AuthorizationSession{}, err
	}
	detail, err := paymentDetail(o.ID)
	if err != nil {
		return client.AuthorizationSession{}, err
	}
	return c.BeginAuthorization(withTrace(ctx, traceOptions{trace: o.trace, tamperRequestObject: tamper}), client.BeginAuthorizationRequest{
		Scope: []string{"openid"}, AuthorizationDetails: []json.RawMessage{detail},
	})
}

// pay starts a checkout — or, for the attack lab, one whose request is
// tampered with or names a redirect URI the bank never registered.
func (s *shop) pay(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.w.renderError(w, shopHost, http.StatusBadRequest, "Malformed form", formUnreadable)
		return
	}
	o := s.newOrder(r.PostForm.Get("scenario"))
	lc := s.client
	if o.Scenario == "redirect" {
		lc = s.misdirected
	}
	session, err := s.begin(r.Context(), o, lc, o.Scenario == "tamper")
	if err != nil {
		o.Status, o.Problem = "failed", describeError(err)
		http.Redirect(w, r, orderURL(o.ID), http.StatusSeeOther)
		return
	}
	s.startSession(w, o, session)
	u := session.URL()
	// Not an open redirect: Alder Bank's authorization endpoint, from its
	// discovery metadata.
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: see above
}

// startSession binds the checkout to this browser: the callback is only
// accepted alongside this session cookie (RFC 9700 §4.7).
func (s *shop) startSession(w http.ResponseWriter, o *order, session client.AuthorizationSession) {
	o.session = session.Handle()
	for name, value := range map[string]string{sessionCookie: session.Handle().String(), orderCookie: o.ID} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}

// callback receives Alder Bank's signed authorization response,
// validates it, redeems the code and charges the approved payment.
func (s *shop) callback(w http.ResponseWriter, r *http.Request) {
	sessionC, err1 := r.Cookie(sessionCookie)
	orderC, err2 := r.Cookie(orderCookie)
	clearCookies(w, sessionCookie, orderCookie)
	o, ok := (*order)(nil), false
	if err2 == nil {
		o, ok = s.lookup(orderC.Value)
	}
	if err1 != nil || !ok {
		s.w.renderError(w, shopHost, http.StatusBadRequest, "No payment in progress", "This browser didn't start a checkout here.")
		return
	}
	handle, err := client.ParseSessionHandle(sessionC.Value)
	if err != nil {
		s.w.renderError(w, shopHost, http.StatusBadRequest, "No payment in progress", notStartedHere)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if jarm := r.URL.Query().Get("response"); jarm != "" {
		o.trace.add("Authorization response (JARM)", "GET "+callbackPath+"?response=…\nresponse (signed by Alder Bank): "+decodeJWT(jarm))
	}
	s.complete(r.Context(), o, handle, r.URL.RawQuery)
	http.Redirect(w, r, orderURL(o.ID), http.StatusSeeOther)
}

// complete validates the callback, exchanges the code and pays.
func (s *shop) complete(ctx context.Context, o *order, handle client.SessionHandle, rawQuery string) {
	ctx = withTrace(ctx, traceOptions{trace: o.trace})
	c, err := s.client.get(ctx)
	if err != nil {
		o.Status, o.Problem = "failed", err.Error()
		return
	}
	result, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: handle})
	if err != nil {
		o.Status, o.Problem = "failed", describeError(err)
		return
	}
	switch res := result.(type) {
	case client.CallbackDenied:
		o.Status, o.Problem = "declined", res.Code+": "+res.Description
		return
	case client.CallbackSuccess:
		o.callbackQuery, o.validated = rawQuery, res.Response
	}
	tokens, err := c.ExchangeCode(ctx, o.validated)
	if err != nil {
		o.Status, o.Problem = "failed", describeError(err)
		return
	}
	o.tokens, o.Status = tokens, "paid"
	payment, err := s.callAPI(ctx, s.client, o.tokens, o.order(price))
	if err != nil {
		o.Problem = err.Error()
		return
	}
	o.Payment = &payment
}

func (o *order) order(amt string) paymentOrder {
	return paymentOrder{InstructedAmount: amount{Currency: "EUR", Amount: amt}, CreditorAccount: account{IBAN: shopIBAN}}
}

func (s *shop) show(w http.ResponseWriter, r *http.Request) {
	o, ok := s.lookup(r.URL.Query().Get("id"))
	if !ok {
		s.w.renderError(w, shopHost, http.StatusNotFound, "Unknown order", "Start a new checkout.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.w.render(w, "shop-order", orderPage{Page: s.w.page(shopName, shopHost), Order: o, Trace: o.trace.Steps()})
}

// callAPI makes a DPoP-bound payment request to Alder Bank's API.
func (s *shop) callAPI(ctx context.Context, lc *lazyClient, tokens client.TokenSet, body paymentOrder) (apiResponse, error) {
	c, err := lc.get(ctx)
	if err != nil {
		return apiResponse{}, err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return apiResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.w.URL(apiHost, paymentsPath), bytes.NewReader(raw))
	if err != nil {
		return apiResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.ProtectedResource(tokens).Do(ctx, req)
	if err != nil {
		return apiResponse{}, err
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	return apiResponse{Status: res.StatusCode, Body: prettyJSON(out)}, nil
}

// direct sends the payment request straight to the authorization
// endpoint, as plain query parameters, skipping PAR.
func (s *shop) direct(w http.ResponseWriter, r *http.Request) {
	o := s.newOrder("direct")
	q := url.Values{
		"client_id": {string(shopClientID)}, "response_type": {"code"}, "scope": {"openid"},
		"redirect_uri": {s.w.URL(shopHost, callbackPath)}, "state": {"abc"},
		"authorization_details": {`[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"129.00"},"creditorAccount":{"iban":"` + shopIBAN + `"}}]`},
	}
	target := s.w.URL(bankHost, authorizePath) + "?" + q.Encode()
	res, err := s.w.net.Client(shopHost).Get(target)
	o.trace.add("Authorization request without PAR", "GET "+target)
	o.Status = "failed"
	if err != nil {
		o.Problem = err.Error()
	} else {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		_ = res.Body.Close()
		o.Problem = fmt.Sprintf("Alder Bank answered %s: %s", res.Status, pageError(body))
	}
	http.Redirect(w, r, orderURL(o.ID), http.StatusSeeOther)
}

// inject is the authorization code injection attack: an attacker
// approves a payment of their own on their own device, stops before
// their browser returns to the shop, and gets this browser — which has
// its own checkout in progress — to open their response instead.
func (s *shop) inject(w http.ResponseWriter, r *http.Request) {
	o := s.newOrder("inject")
	session, err := s.begin(r.Context(), o, s.client, false)
	if err != nil {
		o.Status, o.Problem = "failed", describeError(err)
		http.Redirect(w, r, orderURL(o.ID), http.StatusSeeOther)
		return
	}
	s.startSession(w, o, session)
	attackerResponse, err := s.w.approveOnAnotherDevice(r.Context(), "alex", "1357")
	if err != nil {
		o.Status, o.Problem = "failed", "the attacker's approval failed: "+err.Error()
	} else {
		o.Injected = attackerResponse
		o.trace.add("The attacker's own authorization response", "Alex approved a payment of their own on their own device, and stopped before returning to the shop:\n"+attackerResponse)
	}
	http.Redirect(w, r, orderURL(o.ID), http.StatusSeeOther)
}

// approveOnAnotherDevice checks out and approves the payment as
// username on a separate device, and returns the shop callback URL its
// browser would have opened.
func (w *World) approveOnAnotherDevice(ctx context.Context, username, pin string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	device := w.net.Browser(jar)
	device.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == strings.TrimPrefix(w.URL(shopHost, ""), "https://") && req.URL.Path == callbackPath {
			return http.ErrUseLastResponse // stop before returning to the shop
		}
		return nil
	}
	post := func(target string, form url.Values) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return device.Do(req)
	}
	res, err := post(w.URL(shopHost, "/pay"), url.Values{"scenario": {"normal"}})
	if err != nil {
		return "", err
	}
	_ = res.Body.Close()
	res, err = post(w.URL(bankHost, authorizePath), url.Values{"username": {username}, "pin": {pin}, "decision": {"approve"}})
	if err != nil {
		return "", err
	}
	_ = res.Body.Close()
	callback := res.Header.Get("Location")
	if res.StatusCode/100 != 3 || !strings.Contains(callback, callbackPath) {
		return "", fmt.Errorf("no authorization response (%s)", res.Status)
	}
	return callback, nil
}

// attack tries something the customer didn't approve, with the order's
// real tokens or authorization response.
func (s *shop) attack(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.w.renderError(w, shopHost, http.StatusBadRequest, "Malformed form", formUnreadable)
		return
	}
	o, ok := s.lookup(r.PostForm.Get("id"))
	if !ok || o.Status != "paid" {
		s.w.renderError(w, shopHost, http.StatusBadRequest, "No paid order", "These attacks need a completed payment's tokens.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := withTrace(r.Context(), traceOptions{trace: &trace{}}) // not the order's trace
	var a attempt
	switch r.PostForm.Get("kind") {
	case "overcharge":
		a = s.apiAttempt(ctx, "Charge €1,290.00 with the €129.00 approval", s.client, o.tokens, o.order("1290.00"))
	case "again":
		a = s.apiAttempt(ctx, "Charge the same payment again", s.client, o.tokens, o.order(price))
	case "stolen":
		a = s.apiAttempt(ctx, "Use the access token from another device", s.thief, o.tokens, o.order(price))
	case "reuse":
		a = s.reuseCode(ctx, o)
	case "replay":
		a = attempt{Title: "Replay the authorization response"}
		c, err := s.client.get(ctx)
		if err == nil {
			_, err = c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: o.callbackQuery, Session: o.session})
		}
		a.Refused, a.Result = err != nil, resultText(err, "accepted")
	case "forged":
		a = s.forgedResponse(ctx, o)
	default:
		s.w.renderError(w, shopHost, http.StatusBadRequest, "Unknown attack", r.PostForm.Get("kind"))
		return
	}
	o.Attempts = append(o.Attempts, a)
	http.Redirect(w, r, orderURL(o.ID)+"#attempts", http.StatusSeeOther)
}

func (s *shop) apiAttempt(ctx context.Context, title string, lc *lazyClient, tokens client.TokenSet, body paymentOrder) attempt {
	res, err := s.callAPI(ctx, lc, tokens, body)
	if err != nil {
		return attempt{Title: title, Result: err.Error(), Refused: true}
	}
	return attempt{Title: title, Result: http.StatusText(res.Status) + "\n" + res.Body, Refused: !res.OK()}
}

// reuseCode redeems the order's authorization code a second time: the
// bank refuses, and revokes the token the first redemption issued.
func (s *shop) reuseCode(ctx context.Context, o *order) attempt {
	a := attempt{Title: "Redeem the authorization code again"}
	c, err := s.client.get(ctx)
	if err == nil {
		_, err = c.ExchangeCode(ctx, o.validated)
	}
	a.Refused, a.Result = err != nil, resultText(err, "tokens issued again")
	if a.Refused {
		res, apiErr := s.callAPI(ctx, s.client, o.tokens, o.order("1.00"))
		if apiErr == nil {
			a.Result += "\n\nThe access token from the first redemption, afterwards:\n" + http.StatusText(res.Status) + "\n" + res.Body
		}
	}
	return a
}

// forgedResponse presents an authorization response signed by a key
// that isn't Alder Bank's, carrying a code of the attacker's choosing.
func (s *shop) forgedResponse(ctx context.Context, o *order) attempt {
	a := attempt{Title: "Present a forged authorization response"}
	q, _ := url.ParseQuery(o.callbackQuery)
	parts := strings.Split(q.Get("response"), ".")
	if len(parts) != 3 {
		return attempt{Title: a.Title, Result: "no response to forge from", Refused: true}
	}
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	claims["code"] = "attacker-chosen-code"
	forged, err := signForged(header, claims)
	if err != nil {
		return attempt{Title: a.Title, Result: err.Error(), Refused: true}
	}
	c, err := s.client.get(ctx)
	if err == nil {
		_, err = c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: url.Values{"response": {forged}}.Encode(), Session: o.session})
	}
	a.Refused, a.Result = err != nil, resultText(err, "accepted")
	return a
}

func resultText(err error, ok string) string {
	if err != nil {
		return describeError(err)
	}
	return ok
}

// describeError is err as a page shows it: the bank's OAuth error, when
// there is one.
func describeError(err error) string {
	var ce *client.Error
	if errors.As(err, &ce) {
		if resp, ok := ce.ServerResponse(); ok {
			return fmt.Sprintf("%s: %s", resp.Code, resp.Description)
		}
	}
	return err.Error()
}

// pageError is the message in one of the bank's error pages.
func pageError(body []byte) string {
	text := string(body)
	if i := strings.Index(text, `class="error">`); i >= 0 {
		text = text[i+len(`class="error">`):]
		if j := strings.Index(text, "<"); j >= 0 {
			return text[:j]
		}
	}
	return strings.TrimSpace(text)
}

// randomCode is n random characters that are easy to read aloud.
func randomCode(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// clearCookies expires the callback's cookies. The session they carry is
// single-use — consumed by this callback whatever its outcome — so
// nothing should keep presenting it.
func clearCookies(w http.ResponseWriter, names ...string) {
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}
