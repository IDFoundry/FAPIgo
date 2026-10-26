package resource_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

func TestAuthorizationContextGrantAccessors(t *testing.T) {
	authz := resource.AuthorizationContext{Claims: map[string]json.RawMessage{
		"grant_id": json.RawMessage(`"consent-1"`), "code_grant_id": json.RawMessage(`"cg-1"`),
	}}
	if authz.GrantID() != "consent-1" || authz.CodeGrantID() != "cg-1" {
		t.Fatalf("GrantID = %q, CodeGrantID = %q", authz.GrantID(), authz.CodeGrantID())
	}
	for name, claims := range map[string]map[string]json.RawMessage{
		"absent":     nil,
		"not string": {"grant_id": json.RawMessage(`1`), "code_grant_id": json.RawMessage(`null`)},
	} {
		authz := resource.AuthorizationContext{Claims: claims}
		if authz.GrantID() != "" || authz.CodeGrantID() != "" {
			t.Errorf("%s: GrantID = %q, CodeGrantID = %q; want both empty", name, authz.GrantID(), authz.CodeGrantID())
		}
	}
}
