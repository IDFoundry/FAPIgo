package linked

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/serverresource"
)

const accountsPath = "/accounts"

// api is Alder Bank's account information API. It accepts only access
// tokens the bank issued, bound to the DPoP key of the client presenting
// them, and whose grant hasn't been revoked; and it shows only the
// accounts the customer chose to share (the token's account_access).
type api struct {
	w        *World
	verifier *resource.Verifier
}

func (w *World) newAPI() (*api, error) {
	// The API runs in the bank's own process, so its verifier comes
	// straight from the bank's server configuration: the same token keys,
	// clock and revocation store RevokeGrant writes to.
	verifier, err := serverresource.NewVerifier(w.bank.cfg, w.bank.deps, serverresource.Options{})
	if err != nil {
		return nil, err
	}
	a := &api{w: w, verifier: verifier}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+accountsPath, a.accounts)
	w.router[apiHost] = mux
	return a, nil
}

// accountView is one account as the API returns it.
type accountView struct {
	IBAN         string        `json:"iban"`
	Name         string        `json:"name"`
	Balance      string        `json:"balance,omitempty"`
	Transactions []transaction `json:"transactions,omitempty"`
}

func (a *api) accounts(w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse(a.w.URL(apiHost, accountsPath))
	if err != nil {
		internalError(w, err)
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
	var details []accountAccess
	_ = json.Unmarshal(authz.Claims["authorization_details"], &details)
	if len(details) == 0 {
		resource.NewError(resource.ErrorInsufficientScope, http.StatusForbidden, "the token grants no account access").WriteJSON(w)
		return
	}
	c, _ := customerByName(authz.Subject)
	out := []accountView{}
	for _, iban := range details[0].Accounts {
		acct, ok := c.account(iban)
		if !ok {
			continue
		}
		view := accountView{IBAN: iban, Name: acct.Name}
		for _, action := range details[0].Actions {
			switch action {
			case "read_balances":
				view.Balance = acct.Balance
			case "read_transactions":
				view.Transactions = acct.Transactions
			}
		}
		out = append(out, view)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
