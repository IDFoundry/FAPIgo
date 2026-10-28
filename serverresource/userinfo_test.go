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
	asked    [][]string
	subjects []string
	err      error
}

func (s *claimsSource) ResolveIdentityClaims(_ context.Context, subject string, names []string) (map[string]json.RawMessage, error) {
	s.asked = append(s.asked, names)
	s.subjects = append(s.subjects, subject)
	return map[string]json.RawMessage{
		"email": json.RawMessage(`"sam@example.com"`),
		"name":  json.RawMessage(`"Sam Rivera"`),
		"phone": json.RawMessage(`"+44 7700 900000"`),
		"sub":   json.RawMessage(`"someone-else"`),
		"iss":   json.RawMessage(`"https://evil.example"`),
		"code":  json.RawMessage(`"c"`),
		"state": json.RawMessage(`"s"`),
	}, s.err
}

func authzFor(scopes []string, requested string) resource.AuthorizationContext {
	a := resource.AuthorizationContext{InternalSubject: "user-1", Scopes: scopes, Claims: map[string]json.RawMessage{}}
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

// TestUserInfoClaimsDropsReservedClaims: a claim a signed UserInfo
// response may never carry — one SignUserInfoResponse sets itself, or
// code or state, which would make it pass for a JARM response — is
// dropped even when the client requested it, rather than failing
// SignUserInfoResponse.
func TestUserInfoClaimsDropsReservedClaims(t *testing.T) {
	claims, err := serverresource.UserInfoClaims(context.Background(), authzFor([]string{"openid"}, `["email","iss","code","state"]`), &claimsSource{})
	if err != nil {
		t.Fatalf("UserInfoClaims: %v", err)
	}
	for _, name := range []string{"iss", "code", "state"} {
		if _, ok := claims[name]; ok {
			t.Errorf("claims carry %q: %s", name, claims)
		}
	}
	if string(claims["email"]) != `"sam@example.com"` {
		t.Errorf("email = %s, want the source's", claims["email"])
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

// TestUserInfoClaimsForAPairwiseClient: the source is asked about the
// end user by the internal subject, and the response's sub is the one
// the client was given.
func TestUserInfoClaimsForAPairwiseClient(t *testing.T) {
	source := &claimsSource{}
	authz := authzFor([]string{"openid"}, `["email"]`)
	authz.ClientSubject = "pw:abc"
	claims, err := serverresource.UserInfoClaims(context.Background(), authz, source)
	if err != nil {
		t.Fatalf("UserInfoClaims: %v", err)
	}
	if string(claims["sub"]) != `"pw:abc"` {
		t.Errorf("sub = %s, want the client's pairwise sub", claims["sub"])
	}
	if len(source.subjects) != 1 || source.subjects[0] != "user-1" {
		t.Errorf("source asked about %v, want the internal subject", source.subjects)
	}
}

// TestUserInfoClaimsNeverAsksAboutAnEmptySubject: under
// resource.PairwiseClientSubjectsOnly a pairwise sub isn't mapped back,
// so InternalSubject is empty and the source mustn't be asked about "".
func TestUserInfoClaimsNeverAsksAboutAnEmptySubject(t *testing.T) {
	source := &claimsSource{}
	authz := authzFor([]string{"openid"}, `["email"]`)
	authz.InternalSubject, authz.ClientSubject = "", "pw:abc"
	if _, err := serverresource.UserInfoClaims(context.Background(), authz, source); err == nil {
		t.Fatal("UserInfoClaims(no internal subject) = nil error")
	}
	if len(source.subjects) != 0 {
		t.Errorf("source asked about %q, want not at all", source.subjects)
	}

	// With nothing to resolve, sub alone needs no internal subject.
	authz = authzFor([]string{"openid"}, "")
	authz.InternalSubject, authz.ClientSubject = "", "pw:abc"
	if claims, err := serverresource.UserInfoClaims(context.Background(), authz, source); err != nil || string(claims["sub"]) != `"pw:abc"` {
		t.Errorf("UserInfoClaims(nothing requested) = %s, %v; want sub alone", claims, err)
	}
}

func TestUserInfoClaimsRefusesClientCredentialsToken(t *testing.T) {
	source := &claimsSource{}
	authz := authzFor([]string{"openid"}, `["email"]`)
	authz.SubjectKind = resource.SubjectClient
	_, err := serverresource.UserInfoClaims(context.Background(), authz, source)
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInsufficientScope {
		t.Errorf("UserInfoClaims(client credentials token) = %v, want 403 insufficient_scope", err)
	}
	if len(source.subjects) != 0 {
		t.Errorf("source asked about %q, want not at all", source.subjects)
	}
}

// TestUserInfoClaimsHonoursRequestedValues: OIDC Core §5.5.1, "When the
// Claim value does not match the requested value, the Claim is not
// included in the response" — the values the token records under
// server.RequestedUserinfoClaimValuesKey.
func TestUserInfoClaimsHonoursRequestedValues(t *testing.T) {
	authz := authzFor([]string{"openid"}, `["email","name","phone"]`)
	authz.Claims[server.RequestedUserinfoClaimValuesKey] = json.RawMessage(`{"email":["other@example.com"],"name":["Sam Rivera","S. Rivera"]}`)
	claims, err := serverresource.UserInfoClaims(context.Background(), authz, &claimsSource{})
	if err != nil {
		t.Fatalf("UserInfoClaims: %v", err)
	}
	if _, ok := claims["email"]; ok {
		t.Errorf("claims carry email %s, whose value wasn't the one requested", claims["email"])
	}
	if string(claims["name"]) != `"Sam Rivera"` || string(claims["phone"]) != `"+44 7700 900000"` {
		t.Errorf("claims = %s, want name (an acceptable value) and phone (unconstrained)", claims)
	}

	authz.Claims[server.RequestedUserinfoClaimValuesKey] = json.RawMessage(`["email"]`)
	if _, err := serverresource.UserInfoClaims(context.Background(), authz, &claimsSource{}); err == nil {
		t.Error("UserInfoClaims(malformed requested claim values) = nil error")
	}
}
