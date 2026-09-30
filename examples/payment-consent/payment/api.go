package payment

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

// api is Alder Bank's payments API. It accepts only access tokens the
// bank issued, bound to the DPoP key of the client that obtained them,
// and executes only a payment the customer approved — the
// authorization_details granted with the token — and only once.
type api struct {
	w        *World
	verifier *resource.Verifier

	mu       sync.Mutex
	executed map[string]bool // approvals already used, by token
}

const paymentsPath = "/payments"

func (w *World) newAPI() (*api, error) {
	// The API runs in the bank's own process, so its verifier comes
	// straight from the bank's server configuration: same token keys,
	// same revocation and replay stores.
	verifier, err := serverresource.NewVerifier(w.bank.cfg, w.bank.deps, serverresource.Options{})
	if err != nil {
		return nil, err
	}
	a := &api{w: w, verifier: verifier, executed: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+paymentsPath, a.pay)
	w.router[apiHost] = mux
	return a, nil
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

func (a *api) pay(w http.ResponseWriter, r *http.Request) {
	// Verified against the API's own external URL, never one the
	// request describes.
	target, err := url.Parse(a.w.URL(apiHost, paymentsPath))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	authz, err := a.verifier.Verify(r.Context(), resource.VerifyRequest{
		Method: r.Method, URL: target,
		Authorization: r.Header.Get("Authorization"), DPoPProofs: r.Header.Values("DPoP"),
	})
	if err != nil {
		resource.WriteError(w, err)
		return
	}
	var order paymentOrder
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&order); err != nil {
		resource.NewError(resource.ErrorInvalidRequest, http.StatusBadRequest, "malformed payment order").WriteJSON(w)
		return
	}
	var granted []paymentInitiation
	var details []json.RawMessage
	_ = json.Unmarshal(authz.Claims["authorization_details"], &details)
	for _, raw := range details {
		var p paymentInitiation
		if json.Unmarshal(raw, &p) == nil {
			granted = append(granted, p)
		}
	}
	if !slices.ContainsFunc(granted, func(p paymentInitiation) bool {
		return p.InstructedAmount == order.InstructedAmount && p.CreditorAccount == order.CreditorAccount
	}) {
		// RFC 6750 §3: error_description is printable ASCII, so no "€".
		resource.NewError(resource.ErrorInsufficientScope, http.StatusForbidden,
			fmt.Sprintf("the customer didn't approve paying EUR %s to %s", order.InstructedAmount.Amount, order.CreditorAccount.IBAN)).WriteJSON(w)
		return
	}
	a.mu.Lock()
	used := a.executed[authz.Key]
	a.executed[authz.Key] = true
	a.mu.Unlock()
	if used {
		resource.NewError(resource.ErrorInsufficientScope, http.StatusForbidden, "this approval was for one payment, and it has been made").WriteJSON(w)
		return
	}
	c, _ := customerByName(authz.Subject)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(paymentResult{
		Status: "executed", Amount: "€" + order.InstructedAmount.Amount,
		Payee: payees[order.CreditorAccount.IBAN], From: c.account.describe(),
	})
}
