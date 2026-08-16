package main

import (
	"net/http"

	"github.com/osanderson/go-fapi/internal/par"
	"github.com/osanderson/go-fapi/server"
)

func parHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form, err := formRequestFromHTTP(r)
		if err != nil {
			writeRawOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		dpopProof, ok := singleDPoPHeader(r)
		if !ok {
			writeRawOAuthError(w, http.StatusBadRequest, "invalid_request", "multiple DPoP headers are not permitted")
			return
		}
		result, err := srv.PushAuthorizationRequest(r.Context(), server.PushAuthorizationRequest{
			HTTP:      form,
			DPoPProof: dpopProof,
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	}
}
