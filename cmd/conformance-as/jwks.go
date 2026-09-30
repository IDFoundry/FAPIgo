package main

import (
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

// jwksHandler serves this authorization server's own published keys.
func jwksHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		set, err := srv.PublicJWKS(r.Context())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		set.WriteJSON(w)
	}
}
