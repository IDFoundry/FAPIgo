package server_test

import (
	"encoding/json"
	"testing"
)

// TestX5CAttesterChainMustBeASinglePath covers the shape "x5c" must
// have before any signature is checked: in order, each certificate
// named as the issuer of the one before it, with no subject or key
// repeated, except for cross-certificates of one CA at the top.
func TestX5CAttesterChainMustBeASinglePath(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	upper := newTestCert(t, "upper CA", certOptions{parent: &root, isCA: true})
	lower := newTestCert(t, "lower CA", certOptions{parent: &upper, isCA: true})
	leaf := newTestCert(t, "attester", certOptions{parent: &lower})
	upperAgain := newTestCert(t, "upper CA", certOptions{parent: &root, isCA: true, key: upper.key})
	upperThird := newTestCert(t, "upper CA", certOptions{parent: &root, isCA: true, key: upper.key})
	lowerAgain := newTestCert(t, "lower CA", certOptions{parent: &upper, isCA: true, key: lower.key})
	sharedKey := newTestCert(t, "shared-key CA", certOptions{parent: &upper, isCA: true, key: upper.key})
	leafSharedKey := newTestCert(t, "attester", certOptions{parent: &sharedKey})
	for name, tc := range map[string]struct {
		leaf   testCert
		x5c    json.RawMessage
		wantOK bool
	}{
		"in order":                          {leaf, x5cOf(leaf, lower, upper), true},
		"out of order":                      {leaf, x5cOf(leaf, upper, lower), false},
		"a step missing":                    {leaf, x5cOf(leaf, upper), false},
		"re-issued copies at the top":       {leaf, x5cOf(leaf, lower, upper, upperAgain), true},
		"three copies at the top":           {leaf, x5cOf(leaf, lower, upper, upperAgain, upperThird), false},
		"re-issued copies below the top":    {leaf, x5cOf(leaf, lower, lowerAgain, upper), false},
		"a CA repeated after another":       {leaf, x5cOf(leaf, lower, upper, lower), false},
		"two CAs with one key":              {leafSharedKey, x5cOf(leafSharedKey, sharedKey, upper), false},
		"a certificate repeated at the top": {leaf, x5cOf(leaf, lower, upper, upper), true},
	} {
		t.Run(name, func(t *testing.T) {
			checkAttesterLeaf(t, leafPolicyHarness(t, root, nil), attesterLeaf{tc.leaf, tc.x5c}, tc.wantOK)
		})
	}
}
