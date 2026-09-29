package main

import (
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

func tokenHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := server.TokenEndpointRequestFromHTTP(r)
		if err != nil {
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorInvalidRequest, err.Error())
			return
		}

		var result server.TokenResult
		switch req.GrantType() {
		case "authorization_code":
			result, err = srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
		case "refresh_token":
			result, err = srv.RefreshAccessToken(r.Context(), req.RefreshToken())
		case server.CIBAGrantType:
			result, err = srv.ExchangeBackchannelAuthentication(r.Context(), req.BackchannelTokenExchange())
		case "client_credentials":
			result, err = srv.RequestClientCredentialsToken(r.Context(), req.ClientCredentials())
		default:
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorUnsupportedGrantType, "grant_type must be authorization_code, refresh_token, client_credentials, or "+server.CIBAGrantType)
			return
		}
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}

		result.WriteJSON(w)
	}
}
