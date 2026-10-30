package linked

import (
	"encoding/json"
	"net/http"

	fapi "github.com/idfoundry/fapigo"
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
	// Its ResourceURLs is the API's own external URL, which a DPoP
	// proof's htu names: the verifier builds each request's target from
	// it and the request's path, never from anything else the request
	// says about itself.
	apiURL, err := fapi.ParseEndpointURL(w.URL(apiHost, ""))
	if err != nil {
		return nil, err
	}
	// The API challenges for DPoP nonces too (RFC 9449 §9), from a
	// store of its own, in tables under a prefix of its own: a nonce the
	// bank's token endpoint handed out isn't valid here, nor the other
	// way round. (NewVerifier refuses the bank's own store.)
	verifier, err := serverresource.NewVerifier(w.bank.cfg, w.bank.deps, serverresource.Options{
		ResourceURLs:  []fapi.URL{apiURL},
		Nonces:        w.stores.api.Nonces(),
		NonceLifetime: w.bank.cfg.Limits.DPoPNonceLifetime,
	})
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
	// Verified against the API's own external URL (the verifier's
	// ResourceURLs), never one the request describes.
	authz, err := a.verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r))
	if err != nil {
		resource.WriteError(w, err)
		return
	}
	// The client's next call carries a fresh DPoP nonce, when the
	// verifier issues them.
	authz.SetDPoPNonce(w.Header())
	c, ok := customerOf(authz)
	if !ok {
		resource.NewInsufficientScopeError(authz, "the access token wasn't issued for a customer").WriteJSON(w)
		return
	}
	details, err := grantedAccess(authz)
	if err != nil {
		resource.NewError(resource.ErrorInvalidToken, http.StatusUnauthorized, "the token's authorization details are malformed").WriteJSON(w)
		return
	}
	if len(details) == 0 {
		resource.NewInsufficientScopeError(authz, "the token grants no account access").WriteJSON(w)
		return
	}
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

// customerOf is the customer authz's token was issued for. A token a
// client was issued for itself (the client credentials grant) names no
// customer, even when the client's client_id equals a customer's
// username, so EndUser, not InternalSubject alone, says whose accounts
// are read.
func customerOf(authz resource.AuthorizationContext) (customer, bool) {
	username, ok := authz.EndUser()
	if !ok {
		return customer{}, false
	}
	return customerByName(username)
}
