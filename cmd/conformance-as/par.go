package main

import (
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

func parHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := server.PushAuthorizationRequestFromHTTP(r)
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		result, err := srv.PushAuthorizationRequest(r.Context(), req)
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		result.WriteJSON(w)
	}
}
