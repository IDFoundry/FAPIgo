package payment

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
	// skew is the verifier's clock-skew allowance on token expiry.
	skew time.Duration
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
	a := &api{w: w, verifier: verifier, replay: w.bank.deps.Replay, skew: w.bank.cfg.Limits.MaxClockSkew}
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
		internalError(w, err)
		return
	}
	authz, err := a.verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r, target))
	if err != nil {
		resource.WriteError(w, err)
		return
	}
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
		resource.NewError(resource.ErrorInsufficientScope, http.StatusForbidden,
			fmt.Sprintf("the customer didn't approve paying EUR %s to %s", order.InstructedAmount.Amount, order.CreditorAccount.IBAN)).WriteJSON(w)
		return
	}
	if !a.useOnce(r.Context(), authz) {
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

// usedApprovalNamespace keeps this API's used approvals apart from the
// server's own records in the shared replay store.
const usedApprovalNamespace storage.ReplayNamespace = "example:payment-consent:approval"

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

// grantedPayments reads the payments authz's token was granted.
func grantedPayments(authz resource.AuthorizationContext) ([]extension.RARDetail[paymentInitiation], error) {
	granted, err := extension.ParseGrantedRAR(authz.Claims[extension.AuthorizationDetailsClaim])
	if err != nil {
		return nil, err
	}
	return extension.RARGet(granted, paymentInitiationType)
}
