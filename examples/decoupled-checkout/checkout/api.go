package checkout

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/serverresource"
)

// api is Alder Bank's payments and accounts APIs. They accept only
// access tokens the bank issued, bound to the key of the client that
// obtained them, and do only what the customer approved on their phone:
// the authorization_details granted with the token.
type api struct {
	w        *World
	verifier *resource.Verifier

	mu       sync.Mutex
	executed map[string]bool // payment consents already used, by token
}

// Paths the APIs serve.
const (
	paymentsPath = "/payments"
	accountsPath = "/accounts/"
)

var accountEndpoints = map[string]string{
	"balances": readBalances, "transactions": readTransactions, "standing-orders": readStandingOrders,
}

// accountEndpointOrder is accountEndpoints' keys, in the order pages
// list them.
var accountEndpointOrder = []string{"balances", "transactions", "standing-orders"}

func (w *World) newAPI() (*api, error) {
	// The APIs run in the bank's own process, so their verifier comes
	// straight from the bank's server configuration: same token format
	// and keys, same revocation and replay stores.
	verifier, err := serverresource.NewVerifier(w.bank.cfg, w.bank.deps, serverresource.Options{})
	if err != nil {
		return nil, err
	}
	a := &api{w: w, verifier: verifier, executed: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+paymentsPath, a.pay)
	mux.HandleFunc("GET "+accountsPath+"{iban}/{what}", a.readAccount)
	w.router[apiHost] = mux
	return a, nil
}

// verify checks the request's access token and DPoP proof, against the
// API's own external URL rather than anything the request says about
// itself.
func (a *api) verify(r *http.Request) (resource.AuthorizationContext, error) {
	target, err := url.Parse(a.w.URL(apiHost, r.URL.Path))
	if err != nil {
		return resource.AuthorizationContext{}, err
	}
	return a.verifier.Verify(r.Context(), resource.VerifyRequest{
		Method: r.Method, URL: target,
		Authorization: r.Header.Get("Authorization"), DPoPProofs: r.Header.Values("DPoP"),
	})
}

// forbidden is RFC 6750 §3.1's insufficient_scope: a valid token that
// doesn't cover this request.
func forbidden(w http.ResponseWriter, description string) {
	resource.NewError(resource.ErrorInsufficientScope, http.StatusForbidden, description).WriteJSON(w)
}

// grantedDetails decodes the token's authorization_details claim.
func grantedDetails(ctx resource.AuthorizationContext) []json.RawMessage {
	var details []json.RawMessage
	_ = json.Unmarshal(ctx.Claims["authorization_details"], &details)
	return details
}

func detailsOfType[T any](details []json.RawMessage, typ string) []T {
	var out []T
	for _, raw := range details {
		var head struct {
			Type string `json:"type"`
		}
		var v T
		if json.Unmarshal(raw, &head) == nil && head.Type == typ && json.Unmarshal(raw, &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// paymentOrder is what a client asks the payments API to execute.
type paymentOrder struct {
	InstructedAmount amount  `json:"instructedAmount"`
	CreditorAccount  account `json:"creditorAccount"`
}

type paymentResult struct {
	Status string `json:"status"`
	Amount string `json:"amount"`
	Payee  string `json:"payee"`
	From   string `json:"from"`
}

// pay executes a payment, only if the token carries an approved
// payment_initiation for exactly this amount and payee, and only once.
func (a *api) pay(w http.ResponseWriter, r *http.Request) {
	authz, err := a.verify(r)
	if err != nil {
		resource.WriteError(w, err)
		return
	}
	var order paymentOrder
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&order); err != nil {
		resource.NewError(resource.ErrorInvalidRequest, http.StatusBadRequest, "malformed payment order").WriteJSON(w)
		return
	}
	approved := slices.ContainsFunc(detailsOfType[paymentInitiation](grantedDetails(authz), paymentInitiationType.Type), func(p paymentInitiation) bool {
		return p.InstructedAmount == order.InstructedAmount && p.CreditorAccount == order.CreditorAccount
	})
	if !approved {
		// RFC 6750 §3: error_description is printable ASCII, so no "€".
		forbidden(w, fmt.Sprintf("the customer didn't approve paying EUR %s to %s", order.InstructedAmount.Amount, order.CreditorAccount.IBAN))
		return
	}
	a.mu.Lock()
	used := a.executed[authz.Key]
	a.executed[authz.Key] = true
	a.mu.Unlock()
	if used {
		forbidden(w, "this approval was for one payment, and it has been made")
		return
	}
	c, _ := customerByHint(authz.Subject)
	writeJSON(w, paymentResult{
		Status: "executed", Amount: "€" + order.InstructedAmount.Amount,
		Payee: payees[order.CreditorAccount.IBAN], From: describeAccount(c.accounts[0]),
	})
}

type accountResult struct {
	Account string   `json:"account"`
	Items   []string `json:"items"`
}

// readAccount answers one account read, only if the token's approved
// account_information covers both the account and the kind of read.
func (a *api) readAccount(w http.ResponseWriter, r *http.Request) {
	authz, err := a.verify(r)
	if err != nil {
		resource.WriteError(w, err)
		return
	}
	iban, action := r.PathValue("iban"), accountEndpoints[r.PathValue("what")]
	if action == "" {
		http.NotFound(w, r)
		return
	}
	approved := slices.ContainsFunc(detailsOfType[accountInformation](grantedDetails(authz), accountInformationType.Type), func(g accountInformation) bool {
		return slices.Contains(g.Actions, action) && slices.Contains(g.Accounts, account{IBAN: iban})
	})
	if !approved {
		forbidden(w, fmt.Sprintf("the customer didn't approve %s for %s", actionLabels[action], iban))
		return
	}
	c, _ := customerByHint(authz.Subject)
	acct, ok := c.account(iban)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, accountResult{Account: describeAccount(acct), Items: sampleData(acct, action)})
}

func sampleData(acct bankAccount, action string) []string {
	switch action {
	case readBalances:
		return []string{"€" + acct.balance}
	case readTransactions:
		return []string{"Harbour Coffee −€42.50", "Salary +€2,450.00", "Rent −€950.00"}
	default:
		return []string{"Rent, monthly, €950.00"}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
