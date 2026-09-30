package checkout

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/storage"
)

// pocketwise is a budgeting app linking a customer's Alder Bank accounts.
// Unlike the till it doesn't poll: the bank pings it when the customer
// has decided (CIBA §10.2), and only then does it collect its tokens.
type pocketwise struct {
	w    *World
	bank *bankClient

	mu    sync.Mutex
	links map[string]*link // by auth_req_id
}

// link is one attempt to link a customer's accounts.
type link struct {
	ID       string // auth_req_id
	Scenario string
	session  client.BackchannelAuthenticationSession

	Status   string // waiting, linked, denied, expired, failed
	Problem  string
	Pinged   time.Time
	Granted  string
	Readings []reading
}

// reading is one API call Pocketwise makes after linking.
type reading struct {
	Account, What, Result string
	OK                    bool
}

// Link scenarios.
const (
	scenarioAccounts = "accounts" // read both accounts, three ways
	scenarioPayment  = "payment"  // try to get a payment approved too
)

const notifyPath = "/ciba-notify"

func (w *World) newPocketwise(keys clientKeys) *pocketwise {
	p := &pocketwise{
		w:     w,
		bank:  &bankClient{w: w, host: pocketwiseHost, clientID: pocketwiseClientID, keys: keys, mode: storage.BackchannelTokenDeliveryModePing},
		links: map[string]*link{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.home)
	mux.HandleFunc("GET /link", p.show)
	mux.Handle("POST /link", http.NewCrossOriginProtection().Handler(http.HandlerFunc(p.start)))
	// Called by the bank, not a browser: authenticated by the bearer
	// token sent with the request, instead.
	mux.HandleFunc("POST "+notifyPath, p.notify)
	w.router[pocketwiseHost] = mux
	return p
}

func (p *pocketwise) home(w http.ResponseWriter, _ *http.Request) {
	p.w.render(w, "pocketwise-home", p.w.page("Pocketwise", pocketwiseHost))
}

// requested is what Pocketwise asks for: both of the customer's accounts,
// read every way.
func requested(c customer) accountInformation {
	access := accountInformation{Actions: accountActions}
	for _, a := range c.accounts {
		access.Accounts = append(access.Accounts, account{IBAN: a.iban})
	}
	return access
}

func (p *pocketwise) start(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.w.renderError(w, pocketwiseHost, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	hint := r.PostForm.Get("customer")
	c, _ := customerByHint(hint) // an unknown customer asks for nothing; the bank refuses the hint
	scenario := r.PostForm.Get("scenario")
	var detail []byte
	var err error
	if scenario == scenarioPayment {
		// Pocketwise isn't entitled to payments: the bank refuses this
		// before the customer ever sees it.
		detail, err = extension.RARSet(paymentInitiationType, paymentInitiation{
			InstructedAmount: amount{Currency: "EUR", Amount: "9.99"}, CreditorName: "Pocketwise",
			CreditorAccount: account{IBAN: "XA90ALDR00005555555555"}, RemittanceMessage: "Pocketwise Premium",
		})
	} else {
		detail, err = extension.RARSet(accountInformationType, requested(c))
	}
	if err != nil {
		p.w.renderError(w, pocketwiseHost, http.StatusInternalServerError, "Linking failed", err.Error())
		return
	}
	bank, err := p.bank.get(r.Context())
	if err != nil {
		p.w.renderError(w, pocketwiseHost, http.StatusBadGateway, "Can't reach Alder Bank", err.Error())
		return
	}
	session, err := bank.BeginBackchannelAuthentication(r.Context(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"}, LoginHint: hint, BindingMessage: "Pocketwise " + randomCode(4),
		AuthorizationDetails: []json.RawMessage{detail},
	})
	if err != nil {
		p.w.render(w, "pocketwise-link", pocketwiseLinkPage{Page: p.w.page("Pocketwise", pocketwiseHost),
			Link: &link{Scenario: scenario, Status: "failed", Problem: describeError(err)}})
		return
	}
	l := &link{ID: session.AuthReqID(), Scenario: scenario, session: session, Status: "waiting"}
	p.mu.Lock()
	p.links[l.ID] = l
	p.mu.Unlock()
	http.Redirect(w, r, "/link?id="+l.ID, http.StatusSeeOther)
}

func (p *pocketwise) show(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	l, ok := p.links[r.URL.Query().Get("id")]
	var view link
	if ok {
		view = *l
	}
	p.mu.Unlock()
	if !ok {
		p.w.renderError(w, pocketwiseHost, http.StatusNotFound, "Unknown link", "Start linking again.")
		return
	}
	if view.Status == "waiting" && time.Now().After(view.session.ExpiresAt()) {
		view.Status = "expired"
	}
	page := pocketwiseLinkPage{Page: p.w.page("Pocketwise", pocketwiseHost), Link: &view}
	page.Refresh = view.Status == "waiting"
	p.w.render(w, "pocketwise-link", page)
}

// notify is Pocketwise's CIBA ping endpoint: the bank POSTs the
// auth_req_id of a decided request, authenticated with the
// client_notification_token Pocketwise sent with that request. Only a
// notification that authenticates against its session is trusted to
// mean "go and collect".
func (p *pocketwise) notify(w http.ResponseWriter, r *http.Request) {
	notification, err := client.ParseBackchannelNotification(r)
	if err != nil {
		http.Error(w, "malformed notification", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	l, ok := p.links[notification.AuthReqID()]
	p.mu.Unlock()
	if !ok || !notification.Authenticates(l.session) {
		http.Error(w, "unknown request or wrong token", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	// Collect after answering: the bank shouldn't wait on Pocketwise.
	go p.collect(context.WithoutCancel(r.Context()), l)
}

// collect fetches the tokens for a decided request, then reads
// everything it asked for, to show which reads the customer allowed.
func (p *pocketwise) collect(ctx context.Context, l *link) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p.mu.Lock()
	l.Pinged = time.Now()
	p.mu.Unlock()
	status, problem, granted, readings := p.fetch(ctx, l.session)
	p.mu.Lock()
	l.Status, l.Problem, l.Granted, l.Readings = status, problem, granted, readings
	p.mu.Unlock()
}

func (p *pocketwise) fetch(ctx context.Context, session client.BackchannelAuthenticationSession) (status, problem, granted string, readings []reading) {
	bank, err := p.bank.get(ctx)
	if err != nil {
		return "failed", err.Error(), "", nil
	}
	result, err := bank.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		return "failed", describeError(err), "", nil
	}
	switch res := result.(type) {
	case client.BackchannelAuthenticationDenied:
		return "denied", res.Code + ": " + res.Description, "", nil
	case client.BackchannelAuthenticationExpired:
		return "expired", "", "", nil
	case client.BackchannelAuthenticationPending:
		log.Printf("pocketwise: pinged for %s, but it's still pending", session.AuthReqID())
		return "waiting", "", "", nil
	case client.BackchannelAuthenticationApproved:
		c := customers[0]
		for _, acct := range requested(c).Accounts {
			for _, what := range accountEndpointOrder {
				res, err := p.bank.callAPI(ctx, res.Tokens, http.MethodGet, accountsPath+acct.IBAN+"/"+what, nil)
				account, _ := c.account(acct.IBAN)
				r := reading{Account: describeAccount(account), What: what}
				if err != nil {
					r.Result = err.Error()
				} else {
					r.OK, r.Result = res.OK(), res.Body
				}
				readings = append(readings, r)
			}
		}
		return "linked", "", prettyJSON(res.Tokens.AuthorizationDetails), readings
	}
	return "failed", "unexpected result", "", nil
}
