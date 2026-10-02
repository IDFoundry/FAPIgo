package serverresource_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
)

// claimsSource returns everything it has, whatever it's asked for, so
// the tests see UserInfoClaims do the restricting.
type claimsSource struct {
	asked [][]string
	err   error
}

func (s *claimsSource) ResolveIdentityClaims(_ context.Context, _ string, names []string) (map[string]json.RawMessage, error) {
	s.asked = append(s.asked, names)
	return map[string]json.RawMessage{
		"email": json.RawMessage(`"sam@example.com"`),
		"name":  json.RawMessage(`"Sam Rivera"`),
		"phone": json.RawMessage(`"+44 7700 900000"`),
		"sub":   json.RawMessage(`"someone-else"`),
	}, s.err
}

func authzFor(scopes []string, requested string) resource.AuthorizationContext {
	a := resource.AuthorizationContext{Subject: "user-1", Scopes: scopes, Claims: map[string]json.RawMessage{}}
	if requested != "" {
		a.Claims[server.RequestedUserinfoClaimsKey] = json.RawMessage(requested)
	}
	return a
}

func TestUserInfoClaimsReturnsOnlyWhatWasRequested(t *testing.T) {
	source := &claimsSource{}
	claims, err := serverresource.UserInfoClaims(context.Background(), authzFor([]string{"openid"}, `["email","name"]`), source)
	if err != nil {
		t.Fatalf("UserInfoClaims: %v", err)
	}
	if len(claims) != 3 || string(claims["email"]) != `"sam@example.com"` || string(claims["name"]) != `"Sam Rivera"` {
		t.Errorf("claims = %s, want email, name and sub only", claims)
	}
	if string(claims["sub"]) != `"user-1"` {
		t.Errorf("sub = %s, want the token's subject", claims["sub"])
	}
	if len(source.asked) != 1 || len(source.asked[0]) != 2 {
		t.Errorf("source asked for %v, want [email name]", source.asked)
	}
}

func TestUserInfoClaimsWithNothingRequestedIsSubjectOnly(t *testing.T) {
	for _, requested := range []string{"", `[]`, `null`} {
		source := &claimsSource{}
		claims, err := serverresource.UserInfoClaims(context.Background(), authzFor([]string{"openid"}, requested), source)
		if err != nil || len(claims) != 1 || string(claims["sub"]) != `"user-1"` {
			t.Errorf("requested %q: claims = %s, %v; want sub alone", requested, claims, err)
		}
		if len(source.asked) != 0 {
			t.Errorf("requested %q: the source was asked for %v, want not at all", requested, source.asked)
		}
	}
}

func TestUserInfoClaimsRefuses(t *testing.T) {
	_, err := serverresource.UserInfoClaims(context.Background(), authzFor([]string{"accounts"}, `["email"]`), &claimsSource{})
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInsufficientScope || rerr.HTTPStatus() != http.StatusForbidden {
		t.Errorf("UserInfoClaims(no openid scope) = %v, want a 403 insufficient_scope", err)
	}
	if _, err := serverresource.UserInfoClaims(context.Background(), authzFor([]string{"openid"}, `"email"`), &claimsSource{}); err == nil {
		t.Error("UserInfoClaims(malformed requested claims) = nil error")
	}
	failing := errors.New("directory unavailable")
	if _, err := serverresource.UserInfoClaims(context.Background(), authzFor([]string{"openid"}, `["email"]`), &claimsSource{err: failing}); !errors.Is(err, failing) {
		t.Errorf("UserInfoClaims(source fails) = %v, want it wrapped", err)
	}
}
