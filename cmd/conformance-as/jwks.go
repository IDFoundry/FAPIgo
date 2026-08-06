package main

import (
	"encoding/json"
	"net/http"

	"github.com/osanderson/go-fapi/server"
)

// jwksHandler serves this authorization server's own published keys.
// server.PublicKeySet already JSON-marshals correctly (its PublicJWK
// entries implement MarshalJSON) — no adapter struct needed here, unlike
// metadata.
func jwksHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		set, err := srv.PublicJWKS(r.Context())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}
}
