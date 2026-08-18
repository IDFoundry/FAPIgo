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

func TestBeginAuthorizationRejectsExtensionsUnderBaselineProfile(t *testing.T) {
	c, _, _ := newTestClient(t, false) // baseline, plain-parameter profile
	ctx := context.Background()

	var req client.BeginAuthorizationRequest
	req.Scope = []string{"openid"}
	if err := extension.Set(&req.Extensions, accountHintDef, "acc-1"); err != nil {
		t.Fatalf("extension.Set: %v", err)
	}

	if _, err := c.BeginAuthorization(ctx, req); err == nil {
		t.Fatalf("BeginAuthorization(extensions under baseline profile) = nil error, want error")
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
