package checkout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
)

// The two Rich Authorization Requests (RFC 9396) detail types Alder
// Bank understands. Their shapes follow RFC 9396's own examples.

// amount is a payment amount, as RFC 9396's payment_initiation example
// gives it.
type amount struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"` // decimal string, e.g. "42.50"
}

type account struct {
	IBAN string `json:"iban"`
}

// paymentInitiation asks to make one payment.
type paymentInitiation struct {
	InstructedAmount  amount  `json:"instructedAmount"`
	CreditorName      string  `json:"creditorName"`
	CreditorAccount   account `json:"creditorAccount"`
	RemittanceMessage string  `json:"remittanceInformationUnstructured,omitempty"`
}

var decimalAmount = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{2}$`)

var paymentInitiationType = extension.RARDefinition[paymentInitiation]{
	Type: "payment_initiation", MaxObjects: 1, MaxBytesPerObject: 1024,
	Validate: func(p paymentInitiation) error {
		if p.InstructedAmount.Currency != "EUR" || !decimalAmount.MatchString(p.InstructedAmount.Amount) {
			return errors.New("instructedAmount must be a EUR amount like 42.50")
		}
		if p.CreditorAccount.IBAN == "" {
			return errors.New("creditorAccount.iban is required")
		}
		return nil
	},
	// ValidateGrant is nil: a payment is approved exactly as asked, or not
	// at all. The user can't approve a different amount or payee.
}

// Actions an account_information detail may ask for.
const (
	readBalances       = "read_balances"
	readTransactions   = "read_transactions"
	readStandingOrders = "read_standing_orders"
)

var accountActions = []string{readBalances, readTransactions, readStandingOrders}

// accountInformation asks to read some of the user's accounts.
type accountInformation struct {
	Actions  []string  `json:"actions"`
	Accounts []account `json:"accounts"`
}

var accountInformationType = extension.RARDefinition[accountInformation]{
	Type: "account_information", MaxObjects: 1, MaxBytesPerObject: 2048,
	Validate: func(a accountInformation) error {
		if len(a.Actions) == 0 || len(a.Accounts) == 0 {
			return errors.New("actions and accounts are required")
		}
		for _, action := range a.Actions {
			if !slices.Contains(accountActions, action) {
				return fmt.Errorf("unknown action %q", action)
			}
		}
		return nil
	},
	// The user may approve less than was asked: fewer actions, fewer
	// accounts, but never anything that wasn't asked for.
	ValidateGrant: func(requested, granted accountInformation) error {
		if len(granted.Actions) == 0 || len(granted.Accounts) == 0 {
			return errors.New("a grant needs at least one action and one account")
		}
		for _, action := range granted.Actions {
			if !slices.Contains(requested.Actions, action) {
				return fmt.Errorf("action %q wasn't requested", action)
			}
		}
		for _, acct := range granted.Accounts {
			if !slices.Contains(requested.Accounts, acct) {
				return fmt.Errorf("account %s wasn't requested", acct.IBAN)
			}
		}
		return nil
	},
}

func newRARRegistry() (*extension.RARRegistry, error) {
	return extension.NewRARRegistry(8192, 4, paymentInitiationType, accountInformationType)
}

// entitlements is which detail types each client may ask for at all:
// Alder Bank's CIBARARPolicy, consulted before a request reaches the
// user. A merchant till may initiate payments; a budgeting app may only
// read accounts.
type entitlements map[fapi.ClientID][]string

// Authorize implements server.RARPolicy: it keeps the detail objects of
// types clientID is entitled to, and drops the rest. If none remain,
// the server refuses the request with invalid_authorization_details.
func (e entitlements) Authorize(_ context.Context, clientID fapi.ClientID, requested []json.RawMessage) ([]json.RawMessage, error) {
	var allowed []json.RawMessage
	for _, raw := range requested {
		var detail struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &detail); err != nil {
			return nil, err
		}
		if slices.Contains(e[clientID], detail.Type) {
			allowed = append(allowed, raw)
		}
	}
	return allowed, nil
}
