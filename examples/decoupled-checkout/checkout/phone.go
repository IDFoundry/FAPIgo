package checkout

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
)

// phone is Alder Bank's app on Sam's phone: where a request started on
// another device is shown, with what it's for, and approved or denied.
type phone struct {
	w     *World
	owner customer
}

func (w *World) newPhone() *phone {
	p := &phone{w: w, owner: customers[0]}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.home)
	mux.HandleFunc("GET /request", p.request)
	// Approvals only from the phone's own pages.
	mux.Handle("POST /decide", http.NewCrossOriginProtection().Handler(http.HandlerFunc(p.decide)))
	w.router[phoneHost] = mux
	return p
}

// notificationView is one pending request on the phone's home screen.
type notificationView struct {
	AuthReqID, ClientName, Summary string
	Age                            string
}

func (p *phone) home(w http.ResponseWriter, r *http.Request) {
	var views []notificationView
	for _, req := range p.w.bank.pendingFor(p.owner) {
		interaction, err := p.w.bank.interaction(r.Context(), req)
		if err != nil {
			continue // answered or expired since
		}
		views = append(views, notificationView{
			AuthReqID: req.authReqID, ClientName: clientName(interaction), Summary: summary(interaction.AuthorizationDetails),
			Age: time.Since(req.received).Round(time.Second).String(),
		})
	}
	page := phoneHomePage{Page: p.w.page("Alder Bank", phoneHost), Owner: p.owner.name, Notifications: views}
	page.Refresh = true // checks for new requests
	p.w.render(w, "phone-home", page)
}

func clientName(interaction server.BackchannelInteractionRequest) string {
	if interaction.ClientDisplay.Name != "" {
		return interaction.ClientDisplay.Name
	}
	return string(interaction.ClientID)
}

// summary is a one-line description of what a request asks for.
func summary(values extension.RARValues) string {
	var parts []string
	for _, pay := range paymentsOf(values) {
		parts = append(parts, "Pay €"+pay.InstructedAmount.Amount)
	}
	for range accountAccessOf(values) {
		parts = append(parts, "Read your accounts")
	}
	if len(parts) == 0 {
		return "Sign in"
	}
	return strings.Join(parts, " · ")
}

// paymentView is one payment on the approval screen. Payee is the name
// Alder Bank has on record for the account; CreditorName and Reference
// are only what the merchant wrote.
type paymentView struct {
	Amount, Payee, CreditorName, IBAN, Reference, DebitAccount string
	PayeeVerified                                              bool
}

// accessView is an account-access request on the approval screen, with
// every account and action it asks for, each one the customer can
// untick.
type accessView struct {
	Accounts []option
	Actions  []option
}

type option struct{ Value, Label string }

var actionLabels = map[string]string{
	readBalances: "See balances", readTransactions: "See transactions", readStandingOrders: "See standing orders",
}

func (p *phone) request(w http.ResponseWriter, r *http.Request) {
	req, ok := p.w.bank.lookup(p.owner, r.URL.Query().Get("id"))
	var interaction server.BackchannelInteractionRequest
	var err error
	if ok {
		interaction, err = p.w.bank.interaction(r.Context(), req)
	}
	if !ok || err != nil {
		p.nothingToApprove(w)
		return
	}
	page := approvalPage{
		Page: p.w.page("Alder Bank", phoneHost), AuthReqID: req.authReqID, ClientName: clientName(interaction),
		BindingMessage: interaction.BindingMessage, Expires: time.Until(req.expires).Round(time.Second).String(),
	}
	for _, pay := range paymentsOf(interaction.AuthorizationDetails) {
		payee, verified := payees[pay.CreditorAccount.IBAN]
		page.Payments = append(page.Payments, paymentView{
			Amount: "€" + pay.InstructedAmount.Amount, Payee: payee, PayeeVerified: verified,
			CreditorName: pay.CreditorName, IBAN: pay.CreditorAccount.IBAN, Reference: pay.RemittanceMessage,
			DebitAccount: describeAccount(p.owner.accounts[0]),
		})
	}
	for _, access := range accountAccessOf(interaction.AuthorizationDetails) {
		var view accessView
		for _, a := range access.Accounts {
			label := a.IBAN + " (not your account)"
			if acct, ok := p.owner.account(a.IBAN); ok {
				label = describeAccount(acct)
			}
			view.Accounts = append(view.Accounts, option{Value: a.IBAN, Label: label})
		}
		for _, action := range access.Actions {
			view.Actions = append(view.Actions, option{Value: action, Label: actionLabels[action]})
		}
		page.Access = append(page.Access, view)
	}
	p.w.render(w, "phone-approve", page)
}

func describeAccount(a bankAccount) string {
	return a.name + " ····" + a.iban[len(a.iban)-4:]
}

func (c customer) account(iban string) (bankAccount, bool) {
	for _, a := range c.accounts {
		if a.iban == iban {
			return a, true
		}
	}
	return bankAccount{}, false
}

// decide approves or denies a request. An approved payment is granted
// exactly as asked; an account-access request is granted for only the
// accounts and actions left ticked.
func (p *phone) decide(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.w.renderError(w, phoneHost, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	id := r.PostForm.Get("id")
	req, ok := p.w.bank.lookup(p.owner, id)
	var interaction server.BackchannelInteractionRequest
	var err error
	if ok {
		interaction, err = p.w.bank.interaction(r.Context(), req)
	}
	if !ok || err != nil {
		p.nothingToApprove(w)
		return
	}
	approve := r.PostForm.Get("decision") == "approve"
	var granted []json.RawMessage
	if approve {
		var err error
		if granted, err = grantFromForm(interaction, r.PostForm["account"], r.PostForm["action"]); err != nil {
			p.w.renderError(w, phoneHost, http.StatusBadRequest, "Nothing approved", err.Error())
			return
		}
	}
	if req, ok = p.w.bank.take(p.owner, id); !ok { // answered meanwhile
		p.nothingToApprove(w)
		return
	}
	if err := p.w.bank.decide(r.Context(), req, interaction.Scope, approve, granted); err != nil {
		p.w.renderError(w, phoneHost, http.StatusInternalServerError, "The bank couldn't record that", err.Error())
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// grantFromForm is what the customer approved: every payment as asked,
// and each account-access request narrowed to the ticked accounts and
// actions. The server checks the result is a narrowing of the request
// (RARDefinition.ValidateGrant), so a tampered form can't widen it.
func grantFromForm(interaction server.BackchannelInteractionRequest, accounts, actions []string) ([]json.RawMessage, error) {
	var granted []json.RawMessage
	for _, pay := range paymentsOf(interaction.AuthorizationDetails) {
		raw, err := extension.RARSet(paymentInitiationType, pay)
		if err != nil {
			return nil, err
		}
		granted = append(granted, raw)
	}
	for _, access := range accountAccessOf(interaction.AuthorizationDetails) {
		var narrowed accountInformation
		for _, a := range access.Accounts {
			if slices.Contains(accounts, a.IBAN) {
				narrowed.Accounts = append(narrowed.Accounts, a)
			}
		}
		for _, action := range access.Actions {
			if slices.Contains(actions, action) {
				narrowed.Actions = append(narrowed.Actions, action)
			}
		}
		if len(narrowed.Accounts) == 0 || len(narrowed.Actions) == 0 {
			return nil, errNothingTicked
		}
		raw, err := extension.RARSet(accountInformationType, narrowed)
		if err != nil {
			return nil, err
		}
		granted = append(granted, raw)
	}
	return granted, nil
}

type errorString string

func (e errorString) Error() string { return string(e) }

const errNothingTicked = errorString("tick at least one account and one thing Pocketwise may see, or deny the request")

// nothingToApprove answers for a request that isn't waiting on the
// customer any more.
func (p *phone) nothingToApprove(w http.ResponseWriter) {
	p.w.renderError(w, phoneHost, http.StatusNotFound, "Nothing to approve", "This request was already answered, or has expired.")
}
