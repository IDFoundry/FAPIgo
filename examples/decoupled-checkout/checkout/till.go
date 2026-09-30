package checkout

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/storage"
)

// till is Harbour Coffee's checkout: it asks Alder Bank to have the
// customer approve a payment on their phone, polls until they decide,
// then charges the approved payment.
type till struct {
	w    *World
	bank *bankClient
	// thief is another device holding the same client software but not
	// the till's DPoP key: what someone who stole the till's access
	// token could do with it.
	thief *bankClient

	mu     sync.Mutex
	orders map[string]*order
}

// order is one checkout.
type order struct {
	ID       string
	Scenario string
	Amount   string // what the till asks the customer to approve
	Message  string // the binding message, shown on the till
	session  client.BackchannelAuthenticationSession
	lastPoll time.Time
	tokens   client.TokenSet

	Status   string // waiting, approved, denied, expired, failed
	Problem  string
	Granted  string // authorization_details echoed back with the tokens
	Payment  *apiResponse
	Attempts []attempt
}

// attempt is one of the attack buttons' results.
type attempt struct {
	Title, Result string
	Refused       bool
}

// Order scenarios.
const (
	scenarioCoffee     = "coffee"     // €42.50, an ordinary purchase
	scenarioMisleading = "misleading" // €500.00, with a binding message claiming it's a refund
)

func (w *World) newTill(keys clientKeys) (*till, error) {
	thiefKeys, err := newClientKeys("stolen-device")
	if err != nil {
		return nil, err
	}
	t := &till{
		w:      w,
		bank:   &bankClient{w: w, host: tillHost, clientID: tillClientID, keys: keys, mode: storage.BackchannelTokenDeliveryModePoll},
		thief:  &bankClient{w: w, host: tillHost, clientID: tillClientID, keys: thiefKeys, mode: storage.BackchannelTokenDeliveryModePoll},
		orders: map[string]*order{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", t.home)
	mux.HandleFunc("GET /order", t.show)
	protect := http.NewCrossOriginProtection()
	mux.Handle("POST /pay", protect.Handler(http.HandlerFunc(t.pay)))
	mux.Handle("POST /attack", protect.Handler(http.HandlerFunc(t.attack)))
	w.router[tillHost] = mux
	return t, nil
}

func (t *till) home(w http.ResponseWriter, _ *http.Request) {
	t.w.render(w, "till-home", t.w.page("Harbour Coffee", tillHost))
}

// pay starts a checkout: a signed CIBA request to Alder Bank naming the
// customer by login hint, with the payment as authorization_details.
func (t *till) pay(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		t.w.renderError(w, tillHost, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	o := &order{ID: randomCode(8), Scenario: r.PostForm.Get("scenario"), Amount: "42.50", Status: "waiting"}
	o.Message = "Harbour Coffee " + randomCode(4)
	if o.Scenario == scenarioMisleading {
		// The merchant's own text: CIBA leaves it to the client, and
		// Alder Bank shows it without vouching for it.
		o.Amount, o.Message = "500.00", "Refund of €500 to you"
	}
	payment, err := extension.RARSet(paymentInitiationType, paymentInitiation{
		InstructedAmount: amount{Currency: "EUR", Amount: o.Amount},
		CreditorName:     "Harbour Coffee", CreditorAccount: account{IBAN: tillIBAN},
		RemittanceMessage: "Order " + o.ID,
	})
	if err != nil {
		t.w.renderError(w, tillHost, http.StatusInternalServerError, "Checkout failed", err.Error())
		return
	}
	c, err := t.bank.get(r.Context())
	if err != nil {
		t.w.renderError(w, tillHost, http.StatusBadGateway, "Can't reach Alder Bank", err.Error())
		return
	}
	o.session, err = c.BeginBackchannelAuthentication(r.Context(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"}, LoginHint: r.PostForm.Get("customer"), BindingMessage: o.Message,
		AuthorizationDetails: []json.RawMessage{payment},
	})
	if err != nil {
		o.Status, o.Problem = "failed", describeError(err)
	}
	t.mu.Lock()
	t.orders[o.ID] = o
	t.mu.Unlock()
	http.Redirect(w, r, "/order?id="+o.ID, http.StatusSeeOther)
}

func (t *till) lookup(id string) (*order, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	o, ok := t.orders[id]
	return o, ok
}

// show is the order's page. While the customer hasn't decided, each
// view polls the bank — no more often than the interval it asked for —
// and refreshes itself.
func (t *till) show(w http.ResponseWriter, r *http.Request) {
	o, ok := t.lookup(r.URL.Query().Get("id"))
	if !ok {
		t.w.renderError(w, tillHost, http.StatusNotFound, "Unknown order", "Start a new checkout.")
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if o.Status == "waiting" && time.Since(o.lastPoll) >= o.session.Interval() {
		t.poll(r.Context(), o)
	}
	page := tillOrderPage{Page: t.w.page("Harbour Coffee", tillHost), Order: o}
	page.Refresh = o.Status == "waiting"
	t.w.render(w, "till-order", page)
}

func (t *till) poll(ctx context.Context, o *order) {
	o.lastPoll = time.Now()
	c, err := t.bank.get(ctx)
	if err != nil {
		o.Status, o.Problem = "failed", err.Error()
		return
	}
	result, err := c.PollBackchannelAuthentication(ctx, o.session)
	if err != nil {
		o.Status, o.Problem = "failed", describeError(err)
		return
	}
	switch res := result.(type) {
	case client.BackchannelAuthenticationPending:
	case client.BackchannelAuthenticationDenied:
		o.Status, o.Problem = "denied", res.Code+": "+res.Description
	case client.BackchannelAuthenticationExpired:
		o.Status = "expired"
	case client.BackchannelAuthenticationApproved:
		o.Status, o.tokens = "approved", res.Tokens
		o.Granted = prettyJSON(res.Tokens.AuthorizationDetails)
		// Charge exactly what was approved.
		payment, err := t.bank.callAPI(ctx, o.tokens, http.MethodPost, paymentsPath, o.paymentOrder(o.Amount))
		if err != nil {
			o.Problem = err.Error()
			return
		}
		o.Payment = &payment
	}
}

func (o *order) paymentOrder(amt string) paymentOrder {
	return paymentOrder{InstructedAmount: amount{Currency: "EUR", Amount: amt}, CreditorAccount: account{IBAN: tillIBAN}}
}

// attack tries something the customer didn't approve, with the order's
// real tokens.
func (t *till) attack(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		t.w.renderError(w, tillHost, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	o, ok := t.lookup(r.PostForm.Get("id"))
	if !ok || o.Status != "approved" {
		t.w.renderError(w, tillHost, http.StatusBadRequest, "No approved order", "Attacks need an approved order's tokens.")
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	ctx := r.Context()
	var a attempt
	switch r.PostForm.Get("kind") {
	case "overcharge":
		a = apiAttempt(ctx, "Charge €420.00 instead", t.bank, o.tokens, o.paymentOrder("420.00"))
	case "again":
		a = apiAttempt(ctx, "Charge the same payment again", t.bank, o.tokens, o.paymentOrder(o.Amount))
	case "stolen":
		a = apiAttempt(ctx, "Use the access token from another device", t.thief, o.tokens, o.paymentOrder(o.Amount))
	case "reuse":
		a = attempt{Title: "Collect tokens again with the same auth_req_id"}
		c, err := t.bank.get(ctx)
		if err == nil {
			_, err = c.PollBackchannelAuthentication(ctx, o.session)
		}
		if err != nil {
			a.Refused, a.Result = true, describeError(err)
		} else {
			a.Result = "tokens issued again"
		}
	default:
		t.w.renderError(w, tillHost, http.StatusBadRequest, "Unknown attack", r.PostForm.Get("kind"))
		return
	}
	o.Attempts = append(o.Attempts, a)
	http.Redirect(w, r, "/order?id="+o.ID+"#attempts", http.StatusSeeOther)
}

func apiAttempt(ctx context.Context, title string, b *bankClient, tokens client.TokenSet, order paymentOrder) attempt {
	res, err := b.callAPI(ctx, tokens, http.MethodPost, paymentsPath, order)
	if err != nil {
		return attempt{Title: title, Result: err.Error(), Refused: true}
	}
	return attempt{Title: title, Result: http.StatusText(res.Status) + "\n" + res.Body, Refused: !res.OK()}
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
