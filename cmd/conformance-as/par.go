package main

import (
	"net/http"

	"github.com/idfoundry/fapigo/internal/par"
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
			PeerCertificate: peerCertificate(r),
		})
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		body, err := par.EncodeResult(par.PushResult{RequestURI: result.RequestURI.String(), ExpiresIn: result.ExpiresIn})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if result.NextDPoPNonce != "" {
			w.Header().Set("DPoP-Nonce", result.NextDPoPNonce)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}
}
