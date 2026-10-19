package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// PromptValue is one value of an authorization request's "prompt"
// parameter (OIDC Core §3.1.2.1).
type PromptValue string

// The prompt values OIDC Core §3.1.2.1 defines. A request may carry
// others (another specification's, such as "create"); they reach
// InteractionRequest.Prompt as sent.
const (
	// PromptNone: show the end user no authentication or consent page at
	// all. If the interaction can't be concluded without one, complete it
	// with InteractionNeeded.
	PromptNone PromptValue = "none"
	// PromptLogin: authenticate the end user again, even if the
	// application already has a session for them.
	PromptLogin PromptValue = "login"
	// PromptConsent: ask the end user for consent, even if they gave it
	// before.
	PromptConsent PromptValue = "consent"
	// PromptSelectAccount: let the end user choose which of their
	// accounts to use.
	PromptSelectAccount PromptValue = "select_account"
)

// Prompt is the set of values an authorization request's "prompt"
// parameter carried, each once, in the order sent; empty when it had
// none.
type Prompt []PromptValue

// Has reports whether the request's prompt included v.
func (p Prompt) Has(v PromptValue) bool { return slices.Contains(p, v) }

// maxPromptBytes and maxPromptValues bound an authorization request's
// "prompt". OIDC Core §3.1.2.1 defines four values and other
// specifications a handful more, so a real request is a few dozen
// bytes; the bound keeps a pushed request from carrying an arbitrarily
// long list that every later step (each GET of the authorization
// endpoint, completion) would parse again.
const (
	maxPromptBytes  = 256
	maxPromptValues = 16
)

// requestedPrompt is the authorization request's "prompt" (OIDC Core
// §3.1.2.1), each value once. It refuses a prompt that isn't a string,
// one longer than maxPromptBytes or with more than maxPromptValues
// distinct values, and "none" combined with any other value, which
// §3.1.2.1 says is an error.
func requestedPrompt(params map[string]json.RawMessage) (Prompt, error) {
	raw, ok := params["prompt"]
	if !ok {
		return nil, nil
	}
	v, err := jsonStringValue(raw)
	if err != nil {
		return nil, errors.New("prompt must be a string")
	}
	if len(v) > maxPromptBytes {
		return nil, fmt.Errorf("prompt must not be longer than %d bytes", maxPromptBytes)
	}
	var p Prompt
	seen := make(map[PromptValue]struct{})
	for _, field := range strings.Fields(v) {
		value := PromptValue(field)
		if _, dup := seen[value]; dup {
			continue
		}
		if len(p) == maxPromptValues {
			return nil, fmt.Errorf("prompt must not carry more than %d values", maxPromptValues)
		}
		seen[value] = struct{}{}
		p = append(p, value)
	}
	if p.Has(PromptNone) && len(p) > 1 {
		return nil, errors.New(`prompt "none" must not be combined with another value`)
	}
	return p, nil
}
