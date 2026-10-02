package checkout

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
)

// api is Alder Bank's payments and accounts APIs. They accept only
// access tokens the bank issued, bound to the key of the client that
// obtained them, and do only what the customer approved on their phone:
// the authorization_details granted with the token.
type api struct {
	w        *World
	verifier *resource.Verifier

	// replay is the bank's replay store, shared by every instance of the
	// bank and its APIs: an approval is recorded there as used, so a
	// second instance refuses it too.
	replay storage.ReplayStore
	// skew is the verifier's clock-skew allowance on token expiry.
	skew time.Duration
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
	a := &api{w: w, verifier: verifier, replay: w.bank.deps.Replay, skew: w.bank.cfg.Limits.MaxClockSkew}
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
	return a.verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r, target))
}

// forbidden is RFC 6750 §3.1's insufficient_scope: a valid token that
// doesn't cover this request.
func forbidden(w http.ResponseWriter, description string) {
	resource.NewError(resource.ErrorInsufficientScope, http.StatusForbidden, description).WriteJSON(w)
}

// granted reads the details of def's type authz's token was granted.
func granted[T any](authz resource.AuthorizationContext, def extension.RARDefinition[T]) ([]extension.RARDetail[T], error) {
	values, err := extension.ParseGrantedRAR(authz.Claims[extension.AuthorizationDetailsClaim])
	if err != nil {
		return nil, err
	}
	return extension.RARGet(values, def)
}

// malformedGrant answers a token whose authorization details can't be
// read: not a grant to act on.
func malformedGrant(w http.ResponseWriter) {
	resource.NewError(resource.ErrorInvalidToken, http.StatusUnauthorized, "the token's authorization details are malformed").WriteJSON(w)
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
	// The client's next call carries a fresh DPoP nonce, when the
	// verifier issues them.
	authz.SetDPoPNonce(w.Header())
	var order paymentOrder
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&order); err != nil {
		resource.NewError(resource.ErrorInvalidRequest, http.StatusBadRequest, "malformed payment order").WriteJSON(w)
		return
	}
	payments, err := granted(authz, paymentInitiationType)
	if err != nil {
		malformedGrant(w)
		return
	}
	approved := slices.ContainsFunc(payments, func(p extension.RARDetail[paymentInitiation]) bool {
		return p.Fields.InstructedAmount == order.InstructedAmount && p.Fields.CreditorAccount == order.CreditorAccount
	})
	if !approved {
		// RFC 6750 §3: error_description is printable ASCII, so no "€".
		forbidden(w, fmt.Sprintf("the customer didn't approve paying EUR %s to %s", order.InstructedAmount.Amount, order.CreditorAccount.IBAN))
		return
	}
	if !a.useOnce(r.Context(), authz) {
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
	// The client's next call carries a fresh DPoP nonce, when the
	// verifier issues them.
	authz.SetDPoPNonce(w.Header())
	iban, action := r.PathValue("iban"), accountEndpoints[r.PathValue("what")]
	if action == "" {
		http.NotFound(w, r)
		return
	}
	reads, err := granted(authz, accountInformationType)
	if err != nil {
		malformedGrant(w)
		return
	}
	approved := slices.ContainsFunc(reads, func(g extension.RARDetail[accountInformation]) bool {
		return slices.Contains(g.Fields.Actions, action) && slices.Contains(g.Fields.Accounts, account{IBAN: iban})
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

// usedApprovalNamespace keeps this API's used approvals apart from the
// server's own records in the shared replay store.
const usedApprovalNamespace storage.ReplayNamespace = "example:decoupled-checkout:approval"

// useOnce records authz's approval as used, reporting whether this is
// its first use. The shared store does the check and the record in one
// atomic step, so two instances racing on the same approval can't both
// proceed, and a store it can't reach refuses rather than allows. The
// record lasts as long as the token can still be presented.
func (a *api) useOnce(ctx context.Context, authz resource.AuthorizationContext) bool {
	return a.replay.UseOnce(ctx, storage.ReplayUse{
		Namespace: usedApprovalNamespace,
		Digest:    sha256.Sum256([]byte(authz.Key)),
		ExpiresAt: authz.ExpiresAt.Add(a.skew),
	}) == nil
}
