package main

import (
	"net/http"

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

		result.WriteJSON(w)
	}
}
