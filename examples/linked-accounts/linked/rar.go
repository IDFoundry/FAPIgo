package linked

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
)

// The account_access Rich Authorization Requests (RFC 9396) detail type:
// read access to named accounts.
type accountAccess struct {
	// Accounts are the IBANs the app may read. An app linking a
	// customer's accounts for the first time doesn't know them, and asks
	// with none: the customer chooses at the bank.
	Accounts []string `json:"accounts,omitempty"`
	// Actions are what it may read on them.
	Actions []string `json:"actions"`
}

var knownActions = []string{"read_balances", "read_transactions"}

var accountAccessType = extension.RARDefinition[accountAccess]{
	Type: "account_access", MaxObjects: 1, MaxBytesPerObject: 1024,
	Validate: func(a accountAccess) error {
		if len(a.Accounts) > 10 {
			return errors.New("accounts must name at most 10 accounts")
		}
		if len(a.Actions) == 0 {
			return errors.New("actions are required")
		}
		for _, action := range a.Actions {
			if !slices.Contains(knownActions, action) {
				return fmt.Errorf("unknown action %q", action)
			}
		}
		return nil
	},
	// The customer chooses which accounts to share: any of their own
	// when the app named none, otherwise some of those it named. The bank
	// offers only the customer's own accounts, and requires at least one.
	// The server also checks the bank's RAR policy against the request at
	// PAR time, before anyone has chosen, which is why a grant naming no
	// accounts passes here when the request named none either.
	ValidateGrant: func(requested, granted accountAccess) error {
		if len(granted.Accounts) == 0 && len(requested.Accounts) > 0 {
			return errors.New("no account shared")
		}
		for _, iban := range granted.Accounts {
			if len(requested.Accounts) > 0 && !slices.Contains(requested.Accounts, iban) {
				return fmt.Errorf("account %s wasn't requested", iban)
			}
		}
		if !slices.Equal(granted.Actions, requested.Actions) {
			return errors.New("actions must be granted as requested")
		}
		return nil
	},
}

func newRARRegistry() (*extension.RARRegistry, error) {
	return extension.NewRARRegistry(4096, 4, accountAccessType)
}

// accessOf is the account_access detail among values, if any.
func accessOf(values extension.RARValues) (accountAccess, bool) {
	details, _ := extension.RARGet(values, accountAccessType)
	if len(details) == 0 {
		return accountAccess{}, false
	}
	return details[0].Fields, true
}

// entitlements is which detail types each client may request: Alder
// Bank's AuthorizationCodeRARPolicy.
type entitlements map[fapi.ClientID][]string

// Authorize implements server.RARPolicy.
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
