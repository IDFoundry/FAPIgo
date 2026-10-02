package payroll

import (
	"errors"
	"log"
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

// What the bank and its APIs send back when something fails. A FAPIgo
// error's Error() includes its internal cause, which is for logs: a
// response or a customer-facing page carries only its public
// description, or a fixed message. (The attack lab, protocol trace and
// logs show full errors on purpose: explaining a refusal is what they
// are for.)

// internalError answers a request that failed on this side.
func internalError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// publicMessage is what a page may say about err: a server error's public
// description, or fallback for anything else. The full error is logged.
func publicMessage(err error, fallback string) string {
	log.Printf("error shown as a page: %v", err)
	var se *server.Error
	if errors.As(err, &se) && se.PublicDescription() != "" {
		return se.PublicDescription()
	}
	return fallback
}
