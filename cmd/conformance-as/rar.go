package main

import (
	"context"
	"encoding/json"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
)

// sampleTransactionApprovalDetail is a generic Rich Authorization
// Requests (RFC 9396) detail type this reference server accepts, purely
// to exercise Config.RAR end-to-end (see wiring.go, authorize.go,
// backchannel.go) — a stand-in for a deployment-specific type, not
// modeled on any real third-party scheme.
type sampleTransactionApprovalDetail struct {
	Type    string   `json:"type"`
	Actions []string `json:"actions"`
	Amount  string   `json:"amount,omitempty"`
}

var sampleRARDefinition = extension.RARDefinition[sampleTransactionApprovalDetail]{
	Type: "transaction_approval", MaxObjects: 10, MaxBytesPerObject: 1024,
}

// newSampleRARRegistry builds the RARRegistry this binary always wires
// into server.Config.RAR — inert unless a request actually sends
// authorization_details, so leaving it on unconditionally (unlike -ciba/
// -userinfo-signing, which are opt-in worked examples) matches RAR being
// a first-class, always-available capability rather than a demo flag.
func newSampleRARRegistry() (*extension.RARRegistry, error) {
	return extension.NewRARRegistry(8192, 4, sampleRARDefinition)
}

// approvedAuthorizationDetails re-encodes every requested detail object
// this server recognizes as fully granted — this binary's consent/
// approval handlers stand in for a real consent UI (see consentHandler's
// own doc comment) and, like their handling of scope, don't offer
// per-object narrowing; a real deployment's own consent UI would read
// values back out the same way (extension.RARGet) and let the resource
// owner approve a subset instead of granting everything requested.
//
// requested was already validated against this exact type by the same
// RARRegistry when the request was first accepted (server/rar.go's
// parseRequestedAuthorizationDetails), so re-decoding it here and
// re-encoding the result (a plain string/[]string struct) cannot fail —
// there is no externally-reachable input that makes either step error.
func approvedAuthorizationDetails(requested extension.RARValues) []json.RawMessage {
	details, _ := extension.RARGet(requested, sampleRARDefinition)
	granted := make([]json.RawMessage, 0, len(details))
	for _, d := range details {
		encoded, _ := json.Marshal(d.Fields)
		granted = append(granted, encoded)
	}
	return granted
}

// sampleRARPolicy is this reference server's own server.RARPolicy (RFC
// 9396 §6) — a stand-in for a real deployment's client-entitlement
// policy, the same way approvedAuthorizationDetails above stands in for
// a real consent UI: it grants every requested detail object verbatim,
// with no actual per-client check. requested has already passed
// RARRegistry.Parse (a registered type, correct shape, within bounds)
// by the time this is called, so there's nothing left to reject here —
// a real deployment would consult its own client-authorization records
// instead of always returning requested unchanged.
//
// Used for all three RARPolicy roles — Dependencies.ClientCredentialsRARPolicy
// (the client_credentials grant's own entitlement check),
// Dependencies.AuthorizationCodeRARPolicy, and Dependencies.CIBARARPolicy
// (the Authorization Code and CIBA grants' own independent request-time
// gates) — see wiring.go. Every role gets the same "approve everything"
// stand-in here, matching approvedAuthorizationDetails' own scope.
type sampleRARPolicy struct{}

func (sampleRARPolicy) Authorize(_ context.Context, _ fapi.ClientID, requested []json.RawMessage) ([]json.RawMessage, error) {
	return requested, nil
}
