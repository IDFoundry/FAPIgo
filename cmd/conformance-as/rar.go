package main

import (
	"encoding/json"

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
func approvedAuthorizationDetails(requested extension.RARValues) ([]json.RawMessage, error) {
	details, err := extension.RARGet(requested, sampleRARDefinition)
	if err != nil {
		return nil, err
	}
	granted := make([]json.RawMessage, 0, len(details))
	for _, d := range details {
		encoded, err := json.Marshal(d.Fields)
		if err != nil {
			return nil, err
		}
		granted = append(granted, encoded)
	}
	return granted, nil
}
