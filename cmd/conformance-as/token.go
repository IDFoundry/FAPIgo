package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/server"
)

func tokenHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form, err := server.FormRequestFromHTTP(r)
		if err != nil {
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorInvalidRequest, err.Error())
			return
		}
		grantType := formValue(form, "grant_type")
		dpopProofs := r.Header.Values("DPoP")
		peerCert := server.PeerCertificateFromHTTP(r)

		var result server.TokenResult
		switch grantType {
		case "authorization_code":
			result, err = srv.ExchangeAuthorizationCode(r.Context(), server.AuthorizationCodeExchangeRequest{HTTP: form, DPoPProofs: dpopProofs, PeerCertificate: peerCert})
		case "refresh_token":
			result, err = srv.RefreshAccessToken(r.Context(), server.RefreshTokenRequest{HTTP: form, DPoPProofs: dpopProofs, PeerCertificate: peerCert})
		case server.CIBAGrantType:
			result, err = srv.ExchangeBackchannelAuthentication(r.Context(), server.BackchannelTokenExchangeRequest{HTTP: form, DPoPProofs: dpopProofs, PeerCertificate: peerCert})
		case "client_credentials":
			result, err = srv.RequestClientCredentialsToken(r.Context(), server.ClientCredentialsTokenRequest{HTTP: form, DPoPProofs: dpopProofs, PeerCertificate: peerCert})
		default:
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorUnsupportedGrantType, "grant_type must be authorization_code, refresh_token, client_credentials, or "+server.CIBAGrantType)
			return
		}
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}

		resp := map[string]any{
			"access_token": result.AccessToken.Reveal(),
			"token_type":   result.TokenType,
			"expires_in":   int64(result.ExpiresIn / time.Second),
			"scope":        result.Scope,
		}
		if result.HasIDToken {
			resp["id_token"] = result.IDToken.Reveal()
		}
		if result.HasRefreshToken {
			resp["refresh_token"] = result.RefreshToken.Reveal()
		}
		if len(result.AuthorizationDetails) > 0 {
			resp["authorization_details"] = result.AuthorizationDetails
		}

		if result.NextDPoPNonce != "" {
			w.Header().Set("DPoP-Nonce", result.NextDPoPNonce)
		}
		// RFC 6749 §5.1 requires this on every token response — checked by
		// conformance suites, and worth doing correctly here even though
		// fapitest's own blueprint (which tests wire content, not header
		// compliance) omits it.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
