package serverresource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
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
// result with SignUserInfoResponse when the client registered for
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

// SignUserInfoResponse signs claims (and encrypts them, if the client
// registered for that) with srv.SignUserInfoResponse for the client the
// access token behind authz was issued to — its aud, its encryption
// key — resolved through clients, so the signed response can't be
// addressed to any other client.
//
// claims must carry the token's subject as "sub" (OIDC Core §5.3.2),
// as UserInfoClaims' result does; a "sub" for anyone else, or none, is
// refused, so the response can't vouch for another end user either. A
// client clients can't resolve is a 401 invalid_token *resource.Error:
// the token is for a client this server no longer knows. A signing
// failure is srv's *server.Error.
func SignUserInfoResponse(ctx context.Context, srv *server.Server, clients storage.ClientRepository, authz resource.AuthorizationContext, claims map[string]json.RawMessage) (string, error) {
	var sub string
	if raw, ok := claims["sub"]; !ok || json.Unmarshal(raw, &sub) != nil || sub != authz.Subject || sub == "" {
		return "", errors.New("serverresource: the UserInfo claims' sub isn't the access token's subject")
	}
	client, err := clients.ResolveClient(ctx, fapi.ClientID(authz.ClientID))
	if err != nil {
		return "", resource.NewError(resource.ErrorInvalidToken, http.StatusUnauthorized, "the access token's client is unknown")
	}
	signed, srvErr := srv.SignUserInfoResponse(ctx, client, claims)
	if srvErr != nil {
		return "", srvErr
	}
	return signed, nil
}
