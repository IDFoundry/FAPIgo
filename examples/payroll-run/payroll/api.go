package payroll

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/serverresource"
)

// api is Alder Bank's payroll API. It accepts only access tokens the
// bank issued, presented over a connection authenticated with the
// certificate the token is bound to, and pays only the batch the token
// grants (its authorization_details), once.
type api struct {
	w        *World
	verifier *resource.Verifier

	mu   sync.Mutex
	paid map[string]bool // grants already used, by token
}

const batchesPath = "/payroll-batches"

func (w *World) newAPI() (*api, error) {
	// The API runs in the bank's own process, so its verifier comes
	// straight from the bank's server configuration: same token keys,
	// same revocation store.
	verifier, err := serverresource.NewVerifier(w.bank.cfg, w.bank.deps, serverresource.Options{})
	if err != nil {
		return nil, err
	}
	a := &api{w: w, verifier: verifier, paid: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+batchesPath, a.submit)
	w.router[apiHost] = mux
	return a, nil
}

// batch is a payroll batch a client asks the API to pay.
type batch struct {
	DebtorAccount account  `json:"debtorAccount"`
	Reference     string   `json:"reference"`
	Payments      []salary `json:"payments"`
}

type salary struct {
	CreditorName     string  `json:"creditorName"`
	CreditorAccount  account `json:"creditorAccount"`
	InstructedAmount amount  `json:"instructedAmount"`
}

type batchResult struct {
	Status   string `json:"status"`
	Payments int    `json:"payments"`
	Total    string `json:"total"`
	From     string `json:"from"`
}

func (a *api) submit(w http.ResponseWriter, r *http.Request) {
	// Verified against the API's own external URL, never one the
	// request describes.
	target, err := url.Parse(a.w.URL(apiHost, batchesPath))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	authz, err := a.verifier.Verify(r.Context(), resource.VerifyRequest{
		Method: r.Method, URL: target, Authorization: r.Header.Get("Authorization"),
		// RFC 8705 §3: the token's cnf.x5t#S256 must be this
		// certificate's thumbprint.
		PeerCertificate: resource.PeerCertificateFromHTTP(r),
	})
	if err != nil {
		resource.WriteError(w, err)
		return
	}
	var b batch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&b); err != nil {
		resource.NewError(resource.ErrorInvalidRequest, http.StatusBadRequest, "malformed payroll batch").WriteJSON(w)
		return
	}
	var total int64
	for _, p := range b.Payments {
		c, err := cents(p.InstructedAmount.Amount)
		if err != nil || p.InstructedAmount.Currency != "EUR" {
			resource.NewError(resource.ErrorInvalidRequest, http.StatusBadRequest, "every payment must be a EUR amount like 1980.00").WriteJSON(w)
			return
		}
		total += c
	}
	if problem := withinGrant(authz.Claims["authorization_details"], b, total); problem != "" {
		// RFC 6750 §3: error_description is printable ASCII, so no "€".
		resource.NewError(resource.ErrorInsufficientScope, http.StatusForbidden, problem).WriteJSON(w)
		return
	}
	a.mu.Lock()
	used := a.paid[authz.Key]
	a.paid[authz.Key] = true
	a.mu.Unlock()
	if used {
		resource.NewError(resource.ErrorInsufficientScope, http.StatusForbidden, "this token was for one payroll batch, and it has been paid").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(batchResult{
		Status: "paid", Payments: len(b.Payments), Total: euros(total),
		From: accountHolders[b.DebtorAccount.IBAN] + " ····" + b.DebtorAccount.IBAN[len(b.DebtorAccount.IBAN)-4:],
	})
}

// withinGrant explains why b, paying total cents, isn't the batch the
// token's granted authorization_details allow; "" if it is.
func withinGrant(details json.RawMessage, b batch, total int64) string {
	var granted []payrollBatch
	_ = json.Unmarshal(details, &granted)
	if len(granted) == 0 {
		return "the token grants no payroll batch"
	}
	g := granted[0]
	limit, err := cents(g.TotalAmount.Amount)
	switch {
	case err != nil:
		return "the token's payroll grant is malformed"
	case b.DebtorAccount != g.DebtorAccount:
		return fmt.Sprintf("the token grants payments from %s, not %s", g.DebtorAccount.IBAN, b.DebtorAccount.IBAN)
	case len(b.Payments) > g.NumberOfPayments:
		return fmt.Sprintf("the token grants %d payments, not %d", g.NumberOfPayments, len(b.Payments))
	case total > limit:
		return fmt.Sprintf("the token grants EUR %s in total, not EUR %s", g.TotalAmount.Amount, decimal(total))
	}
	return ""
}
