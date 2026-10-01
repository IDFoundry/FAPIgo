package payroll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
)

// The payroll_batch Rich Authorization Requests (RFC 9396) detail type:
// permission to pay one batch of salaries from one account.

type amount struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"` // decimal string, e.g. "1980.00"
}

type account struct {
	IBAN string `json:"iban"`
}

// payrollBatch asks to pay up to NumberOfPayments salaries, together no
// more than TotalAmount, from DebtorAccount.
type payrollBatch struct {
	DebtorAccount    account `json:"debtorAccount"`
	TotalAmount      amount  `json:"totalAmount"`
	NumberOfPayments int     `json:"numberOfPayments"`
	Reference        string  `json:"reference,omitempty"`
}

var decimalAmount = regexp.MustCompile(`^[0-9]{1,7}\.[0-9]{2}$`)

var payrollBatchType = extension.RARDefinition[payrollBatch]{
	Type: "payroll_batch", MaxObjects: 1, MaxBytesPerObject: 1024,
	Validate: func(b payrollBatch) error {
		if b.TotalAmount.Currency != "EUR" || !decimalAmount.MatchString(b.TotalAmount.Amount) {
			return errors.New("totalAmount must be a EUR amount like 22840.00")
		}
		if b.DebtorAccount.IBAN == "" {
			return errors.New("debtorAccount.iban is required")
		}
		if b.NumberOfPayments < 1 || b.NumberOfPayments > 500 {
			return errors.New("numberOfPayments must be between 1 and 500")
		}
		return nil
	},
	// ValidateGrant is nil: the bank grants a batch exactly as asked, or
	// not at all.
}

func newRARRegistry() (*extension.RARRegistry, error) {
	return extension.NewRARRegistry(4096, 4, payrollBatchType)
}

// cents parses a decimal amount like "1980.00".
func cents(s string) (int64, error) {
	whole, frac, ok := strings.Cut(s, ".")
	if !ok || len(frac) != 2 {
		return 0, fmt.Errorf("malformed amount %q", s)
	}
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, err
	}
	f, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0, err
	}
	return w*100 + f, nil
}

// decimal formats cents as a decimal amount like "1980.00".
func decimal(c int64) string { return fmt.Sprintf("%d.%02d", c/100, c%100) }

// euros formats cents for a page, like "€1,980.00".
func euros(c int64) string {
	whole := strconv.FormatInt(c/100, 10)
	for i := len(whole) - 3; i > 0; i -= 3 {
		whole = whole[:i] + "," + whole[i:]
	}
	return fmt.Sprintf("€%s.%02d", whole, c%100)
}

// mandate is what an account holder has authorised a payroll provider
// to do: pay batches from Account, each no more than Limit cents.
type mandate struct {
	Account string
	Limit   int64
}

// mandates is Alder Bank's record of standing payroll mandates, by
// client: its ClientCredentialsRARPolicy. The client credentials grant
// has no end user to approve each batch, so the bank decides from what
// the account holder authorised in advance.
type mandates map[fapi.ClientID][]mandate

// Authorize implements server.RARPolicy: it grants each requested batch
// that a mandate of clientID's covers, and refuses the rest.
func (m mandates) Authorize(_ context.Context, clientID fapi.ClientID, requested []json.RawMessage) ([]json.RawMessage, error) {
	var granted []json.RawMessage
	for _, raw := range requested {
		var batch payrollBatch
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		total, err := cents(batch.TotalAmount.Amount)
		if err != nil {
			return nil, err
		}
		for _, md := range m[clientID] {
			if md.Account == batch.DebtorAccount.IBAN && total <= md.Limit {
				granted = append(granted, raw)
				break
			}
		}
	}
	return granted, nil
}
