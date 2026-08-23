package client_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/requestobject"
)

var accountHintDef = extension.Definition[string]{
	Name:           "x_account_hint",
	Cardinality:    extension.Single,
	AllowedSources: extension.SourceRequestObject,
	MaxBytes:       64,
}

// accountBalanceDef is Cardinality: Single but not string-typed — used
// to exercise the baseline (plain-parameter) profile's rejection of a
// value shape a bare form parameter can't represent.
var accountBalanceDef = extension.Definition[int]{
	Name:        "x_account_balance",
	Cardinality: extension.Single,
	MaxBytes:    16,
}

// A string-valued extension has an unambiguous plain-parameter
// representation — the request object's JSON string and a bare form
// value round-trip identically — so it no longer requires the
// message-signing profile.
func TestBeginAuthorizationSendsStringExtensionAsPlainParameterUnderBaselineProfile(t *testing.T) {
	c, as, _ := newTestClient(t, false) // baseline, plain-parameter profile
	ctx := context.Background()

	var req client.BeginAuthorizationRequest
	req.Scope = []string{"openid"}
	if err := extension.Set(&req.Extensions, accountHintDef, "acc-1"); err != nil {
		t.Fatalf("extension.Set: %v", err)
	}

	if _, err := c.BeginAuthorization(ctx, req); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if got := as.lastPARForm.Get("x_account_hint"); got != "acc-1" {
		t.Errorf("PAR form x_account_hint = %q, want acc-1", got)
	}
}

// A non-string value (here, an int) has no lossless bare-string
// representation — a plain form parameter can't distinguish "42" the
// number from "42" the string the way the request object's native JSON
// can — so it must still be rejected under the baseline profile rather
// than silently flattened.
func TestBeginAuthorizationRejectsNonStringExtensionsUnderBaselineProfile(t *testing.T) {
	c, _, _ := newTestClient(t, false) // baseline, plain-parameter profile
	ctx := context.Background()

	var req client.BeginAuthorizationRequest
	req.Scope = []string{"openid"}
	if err := extension.Set(&req.Extensions, accountBalanceDef, 42); err != nil {
		t.Fatalf("extension.Set: %v", err)
	}

	if _, err := c.BeginAuthorization(ctx, req); err == nil {
		t.Fatalf("BeginAuthorization(non-string extension under baseline profile) = nil error, want error")
	}
}

// An extension whose wire name collides with a core authorization
// parameter must be rejected on the plain path exactly as it already is
// on the signing path, not silently let the extension value overwrite
// (or lose to) the core parameter of the same name.
func TestBeginAuthorizationRejectsExtensionCollidingWithCoreParameterUnderBaselineProfile(t *testing.T) {
	c, _, _ := newTestClient(t, false) // baseline, plain-parameter profile
	ctx := context.Background()

	stateDef := extension.Definition[string]{Name: "state", Cardinality: extension.Single, MaxBytes: 64}
	var req client.BeginAuthorizationRequest
	req.Scope = []string{"openid"}
	if err := extension.Set(&req.Extensions, stateDef, "attacker-controlled"); err != nil {
		t.Fatalf("extension.Set: %v", err)
	}

	if _, err := c.BeginAuthorization(ctx, req); err == nil {
		t.Fatalf("BeginAuthorization(extension colliding with core parameter) = nil error, want error")
	}
}

func TestBeginAuthorizationEmbedsExtensionsInSignedRequestObject(t *testing.T) {
	c, as, _ := newTestClient(t, true) // message-signing profile
	ctx := context.Background()

	var req client.BeginAuthorizationRequest
	req.Scope = []string{"openid"}
	if err := extension.Set(&req.Extensions, accountHintDef, "acc-2"); err != nil {
		t.Fatalf("extension.Set: %v", err)
	}

	if _, err := c.BeginAuthorization(ctx, req); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	requestJWT := as.lastPARForm.Get("request")
	if requestJWT == "" {
		t.Fatalf("PAR request had no signed request object")
	}
	obj, err := requestobject.Parse(requestJWT)
	if err != nil {
		t.Fatalf("parse request object: %v", err)
	}
	raw, ok := obj.Parameter("x_account_hint")
	if !ok {
		t.Fatalf("request object is missing x_account_hint")
	}
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal x_account_hint: %v", err)
	}
	if got != "acc-2" {
		t.Errorf("x_account_hint = %q, want acc-2", got)
	}
}
