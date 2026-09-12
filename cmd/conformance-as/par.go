package main

import (
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

func parHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form, err := server.FormRequestFromHTTP(r)
		if err != nil {
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorInvalidRequest, err.Error())
			return
		}
		result, err := srv.PushAuthorizationRequest(r.Context(), server.PushAuthorizationRequest{
			HTTP:            form,
			DPoPProofs:      r.Header.Values("DPoP"),
			PeerCertificate: server.PeerCertificateFromHTTP(r),
		})
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		result.WriteJSON(w)
	}
}
