package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// selfIssuerKeySource resolves this same process's own access-token
// signing key directly from its in-memory keyManager, rather than
// looping the resource verifier's key lookup back over HTTP to this
// binary's own /jwks endpoint. That loopback would hit this binary's
// self-signed cert with a standard net/http.Client, which — unlike the
// OIDF suite's own outbound client (see docker-compose.yml's header
// comment) — does not trust it.
type selfIssuerKeySource struct {
	keyManager *ephemeral.KeyManager
}

func (s selfIssuerKeySource) ResolveIssuerKeys(ctx context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	pub, err := s.keyManager.PublicKey(ctx, keys.AccessTokenSigning, req.Algorithm)
	if err != nil {
		return keys.IssuerKeySet{}, err
	}
	return keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: pub.KeyID, Algorithm: req.Algorithm, PublicKey: pub.PublicKey},
	}}, nil
}

// userinfoHandler serves the OIDC UserInfo endpoint (OIDC Core §5.3) —
// this conformance binary's one protected resource endpoint, using the
// same access-token verification any protected endpoint this binary
// might host would (this binary's tokens are always issued for its own
// single issuer/audience, so one Verifier config would cover any
// number of them). It also doubles as the generic protected resource
// AbstractFAPI2SPFinalServerTestModule's happy-flow test calls
// (CallProtectedResource) — the suite plan config's
// resource.resourceUrl points here — since UserInfo already has a real
// spec-defined contract to verify against (requires "openid" scope,
// must always return "sub" per OIDCC-5.3.2) rather than needing a
// separate stand-in endpoint with no contract of its own. It also
// returns whatever identity claims this binary has for the subject
// (see identity_claims.go — supporting real claim values, not just the
// plumbing, is what
// fapi2-security-profile-final-test-claims-parameter-identity-claims
// actually checks).
//
// userinfoURL is this endpoint's own fixed, externally-visible URL,
// used as the DPoP proof's expected "htu" — not read from the incoming
// request's Host header, matching how this binary's other endpoints
// (server.Endpoints) are never inferred from it either.
//
// userinfoSigning, when true (main.go's -userinfo-signing flag), signs
// the response as a JWS via srv.SignUserInfoResponse instead of
// returning plain JSON, serving Content-Type: application/jwt per OIDC
// Core §5.3.2 — the worked example proving server.Config.Algorithms.UserInfo
// actually interoperates with client.FetchUserInfo end to end.
func userinfoHandler(srv *server.Server, verifier *fapires.Verifier, userinfoURL *url.URL, identityClaims staticIdentityClaims, clients storage.ClientRepository, userinfoSigning bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dpopProof, ok := singleDPoPHeader(r)
		if !ok {
			writeResourceErrorRaw(w, http.StatusBadRequest, "invalid_request", "multiple DPoP headers are not permitted")
			return
		}
		authCtx, err := verifier.Verify(r.Context(), fapires.VerifyRequest{
			Method:          r.Method,
			URL:             userinfoURL,
			Authorization:   r.Header.Get("Authorization"),
			DPoPProof:       dpopProof,
			PeerCertificate: peerCertificate(r),
		})
		if err != nil {
			writeResourceError(w, err)
			return
		}
		hasOpenIDScope := false
		for _, scope := range authCtx.Scopes {
			if scope == "openid" {
				hasOpenIDScope = true
				break
			}
		}
		if !hasOpenIDScope {
			writeResourceErrorRaw(w, http.StatusForbidden, "insufficient_scope", "access token was not granted the openid scope")
			return
		}

		// requested_userinfo_claims (server.RequestedUserinfoClaimsKey) was
		// embedded in this access token at issuance, carrying forward the
		// authorization request's "claims" parameter — see that
		// constant's doc comment for why a UserInfo call, arriving as a
		// wholly separate later request, has no other way to know what
		// was originally requested. No entry there means nothing was
		// requested, and this endpoint must not return any identity claim
		// in that case (not "return everything this binary happens to
		// know" — that would leak data the client never asked for).
		var requestedNames []string
		if raw, ok := authCtx.Claims[server.RequestedUserinfoClaimsKey]; ok {
			_ = json.Unmarshal(raw, &requestedNames)
		}
		claims, err := identityClaims.ResolveIdentityClaims(r.Context(), authCtx.Subject, requestedNames)
		if err != nil {
			writeResourceErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to resolve identity claims")
			return
		}
		subJSON, err := json.Marshal(authCtx.Subject)
		if err != nil {
			writeResourceErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to encode subject")
			return
		}
		body := make(map[string]json.RawMessage, len(claims))
		for k, v := range claims {
			body[k] = v
		}
		body["sub"] = subJSON

		if authCtx.NextDPoPNonce != "" {
			w.Header().Set("DPoP-Nonce", authCtx.NextDPoPNonce)
		}

		if userinfoSigning {
			client, err := clients.ResolveClient(r.Context(), fapi.ClientID(authCtx.ClientID))
			if err != nil {
				writeResourceErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to resolve client")
				return
			}
			signed, srvErr := srv.SignUserInfoResponse(r.Context(), client, body)
			if srvErr != nil {
				writeResourceErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to sign userinfo response")
				return
			}
			w.Header().Set("Content-Type", "application/jwt")
			_, _ = w.Write([]byte(signed))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

func writeResourceError(w http.ResponseWriter, err error) {
	resErr, ok := err.(*fapires.Error)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Set before writeResourceErrorRaw's own WriteHeader call — a
	// header can't be added after that. Only ErrorUseDPoPNonce ever
	// carries a nonce (Error.Nonce's own doc comment), so this is a
	// no-op for every other rejection.
	if resErr.Nonce() != "" {
		w.Header().Set("DPoP-Nonce", resErr.Nonce())
	}
	writeResourceErrorRaw(w, resErr.HTTPStatus(), string(resErr.Code()), resErr.PublicDescription())
}

// writeResourceErrorRaw writes a resource-endpoint error response
// directly, for failures detected before a *fapires.Error exists (e.g.
// multiple DPoP headers, rejected before ever calling into the
// verifier).
func writeResourceErrorRaw(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("WWW-Authenticate", `DPoP error="`+code+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
