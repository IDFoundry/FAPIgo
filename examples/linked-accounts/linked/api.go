package linked

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/idfoundry/fapigo/extension"
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
	authz, err := a.verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r, target))
	if err != nil {
		resource.WriteError(w, err)
		return
	}
	// The client's next call carries a fresh DPoP nonce, when the
	// verifier issues them.
	authz.SetDPoPNonce(w.Header())
	details, err := grantedAccess(authz)
	if err != nil {
		resource.NewError(resource.ErrorInvalidToken, http.StatusUnauthorized, "the token's authorization details are malformed").WriteJSON(w)
		return
	}
	if len(details) == 0 {
		resource.NewInsufficientScopeError(authz, "the token grants no account access").WriteJSON(w)
		return
	}
	c, _ := customerByName(authz.Subject)
	out := []accountView{}
	for _, iban := range details[0].Fields.Accounts {
		acct, ok := c.account(iban)
		if !ok {
			continue
		}
		view := accountView{IBAN: iban, Name: acct.Name}
		for _, action := range details[0].Fields.Actions {
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

// grantedAccess reads the account access authz's token was granted.
func grantedAccess(authz resource.AuthorizationContext) ([]extension.RARDetail[accountAccess], error) {
	granted, err := extension.ParseGrantedRAR(authz.Claims[extension.AuthorizationDetailsClaim])
	if err != nil {
		return nil, err
	}
	return extension.RARGet(granted, accountAccessType)
}
