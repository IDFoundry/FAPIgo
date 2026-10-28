package payment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
)

// api is Alder Bank's payments API. It accepts only access tokens the
// bank issued, bound to the DPoP key of the client that obtained them,
// and executes only a payment the customer approved — the
// authorization_details granted with the token — and only once.
type api struct {
	w        *World
	verifier *resource.Verifier

	// replay is the bank's replay store, shared by every instance of the
	// bank and its APIs: an approval is recorded there as used, so a
	// second instance refuses it too.
	replay storage.ReplayStore
	// grantLifetime is how long tokens from one grant can still be
	// presented: its refresh token's lifetime (refreshing doesn't extend
	// it), the last access token's, and the verifier's clock skew.
	grantLifetime time.Duration
}

const paymentsPath = "/payments"

func (w *World) newAPI() (*api, error) {
	// The API runs in the bank's own process, so its verifier comes
	// straight from the bank's server configuration: same token keys,
	// same revocation and replay stores.
	// Its ResourceURLs is the API's own external URL, which a DPoP
	// proof's htu names: the verifier builds each request's target from
	// it and the request's path, never from anything else the request
	// says about itself.
	apiURL, err := fapi.ParseEndpointURL(w.URL(apiHost, ""))
	if err != nil {
		return nil, err
	}
	verifier, err := serverresource.NewVerifier(w.bank.cfg, w.bank.deps, serverresource.Options{ResourceURLs: []fapi.URL{apiURL}})
	if err != nil {
		return nil, err
	}
	limits := w.bank.cfg.Limits
	a := &api{w: w, verifier: verifier, replay: w.bank.deps.Replay,
		grantLifetime: limits.RefreshTokenLifetime + limits.AccessTokenLifetime + limits.MaxClockSkew}
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
	var order paymentOrder
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&order); err != nil {
		resource.NewError(resource.ErrorInvalidRequest, http.StatusBadRequest, "malformed payment order").WriteJSON(w)
		return
	}
	granted, err := grantedPayments(authz)
	if err != nil {
		resource.NewError(resource.ErrorInvalidToken, http.StatusUnauthorized, "the token's authorization details are malformed").WriteJSON(w)
		return
	}
	if !slices.ContainsFunc(granted, func(p extension.RARDetail[paymentInitiation]) bool {
		return p.Fields.InstructedAmount == order.InstructedAmount && p.Fields.CreditorAccount == order.CreditorAccount
	}) {
		// RFC 6750 §3: error_description is printable ASCII, so no "€".
		resource.NewInsufficientScopeError(authz,
			fmt.Sprintf("the customer didn't approve paying EUR %s to %s", order.InstructedAmount.Amount, order.CreditorAccount.IBAN)).WriteJSON(w)
		return
	}
	if !a.useOnce(r.Context(), authz) {
		resource.NewInsufficientScopeError(authz, "this approval was for one payment, and it has been made").WriteJSON(w)
		return
	}
	c, _ := customerByName(authz.InternalSubject)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(paymentResult{
		Status: "executed", Amount: "€" + order.InstructedAmount.Amount,
		Payee: payees[order.CreditorAccount.IBAN], From: c.account.describe(),
	})
}

// usedApprovalNamespace keeps this API's used approvals apart from the
// server's own records in the shared replay store.
const usedApprovalNamespace storage.ReplayNamespace = "example:payment-consent:approval"

// useOnce records authz's approval as used, reporting whether this is
// its first use. The approval is the grant, named by CodeGrantID, not
// the access token (authz.Key): a refresh issues a new access token
// carrying the same approval, which must not pay again. The shared store
// does the check and the record in one atomic step, so two instances
// racing on the same approval can't both proceed, and a store it can't
// reach refuses rather than allows. The record lasts as long as any
// token from the grant can still be presented. A token naming no grant
// is refused.
func (a *api) useOnce(ctx context.Context, authz resource.AuthorizationContext) bool {
	grant := authz.CodeGrantID()
	if grant == "" {
		return false
	}
	return a.replay.UseOnce(ctx, storage.ReplayUse{
		Namespace: usedApprovalNamespace,
		Digest:    sha256.Sum256([]byte(grant)),
		ExpiresAt: time.Now().Add(a.grantLifetime),
	}) == nil
}

// grantedPayments reads the payments authz's token was granted.
func grantedPayments(authz resource.AuthorizationContext) ([]extension.RARDetail[paymentInitiation], error) {
	granted, err := extension.ParseGrantedRAR(authz.Claims[extension.AuthorizationDetailsClaim])
	if err != nil {
		return nil, err
	}
	return extension.RARGet(granted, paymentInitiationType)
}
