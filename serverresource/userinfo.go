package serverresource

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

// UserInfoClaims builds a UserInfo response's claims (OIDC Core §5.3.2)
// for authz, the verified access token a UserInfo endpoint hosted with
// the server was called with:
//
//   - a token without the openid scope is refused, as a 403
//     insufficient_scope *resource.Error;
//   - the claims are the ones the client requested and the user approved
//     (server.RequestedUserinfoClaimsKey, carried in the token, since a
//     UserInfo call has no other link to its authorization), resolved by
//     source, which isn't asked at all when none were — never every
//     claim source knows;
//   - a claim source returns that wasn't requested is dropped, whatever
//     source does;
//   - "sub" is the token's subject.
//
// A requested-claims entry the token carries malformed is an error, not
// an empty request. An error from source is returned wrapped. Sign the
// result with server.SignUserInfoResponse when the client registered for
// signed UserInfo, or write it as JSON.
func UserInfoClaims(ctx context.Context, authz resource.AuthorizationContext, source server.IdentityClaimsSource) (map[string]json.RawMessage, error) {
	if !slices.Contains(authz.Scopes, "openid") {
		return nil, resource.NewInsufficientScopeError(authz, "the access token wasn't granted the openid scope")
	}
	var names []string
	if raw, ok := authz.Claims[server.RequestedUserinfoClaimsKey]; ok {
		if err := json.Unmarshal(raw, &names); err != nil {
			return nil, fmt.Errorf("serverresource: the access token's requested UserInfo claims are malformed: %w", err)
		}
	}
	claims := map[string]json.RawMessage{}
	if len(names) > 0 {
		resolved, err := source.ResolveIdentityClaims(ctx, authz.Subject, names)
		if err != nil {
			return nil, fmt.Errorf("serverresource: resolving UserInfo claims: %w", err)
		}
		for name, value := range resolved {
			if slices.Contains(names, name) {
				claims[name] = value
			}
		}
	}
	// A string always encodes.
	claims["sub"], _ = json.Marshal(authz.Subject)
	return claims, nil
}
