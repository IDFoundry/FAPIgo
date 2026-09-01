package main

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
)

// cibaApprovePage is rendered by the manual CIBA approve/deny UI —
// auth_req_id and the operator-visible message both echo back
// low-trust input (a value read off a live suite log, or an error
// string derived from it), so this uses html/template rather than
// text/template for its automatic contextual escaping, mirroring
// consentHandler's own consentPage.
type cibaApprovePage struct {
	Token   string
	Message string
}

var cibaApproveTemplate = template.Must(template.New("ciba-approve").Parse(`<!doctype html>
<html>
<head><title>CIBA Approve/Deny</title></head>
<body>
<h1>CIBA Approve/Deny</h1>
{{if .Message}}<p><strong>{{.Message}}</strong></p>{{end}}
<form method="POST" action="/ciba-approve">
  <input type="hidden" name="token" value="{{.Token}}">
  <p><label>auth_req_id: <input type="text" name="auth_req_id" size="48" autofocus required></label></p>
  <button type="submit" name="action" value="allow">Approve</button>
  <button type="submit" name="action" value="deny">Deny</button>
</form>
</body>
</html>
`))

// validCIBAApprovalUIToken gates access to the manual CIBA approve/deny
// UI below. POST /backchannel-approve itself has no auth at all — by
// design, see backchannelHandler's own doc comment: it's meant to be
// called automatically, unauthenticated, by the local suite's own
// automated_ciba_approval_url mechanism. A page letting a human drive
// the same decision over the public internet — for a hosted
// certification run, where nothing calls that mechanism — needs its
// own gate instead. A random token in the URL is enough for a
// throwaway certification box (no real user data, no financial value),
// not real login/session infrastructure. Compared with
// subtle.ConstantTimeCompare, not ==, since it's still gating a live
// control endpoint reachable from the public internet.
func validCIBAApprovalUIToken(configured, supplied string) bool {
	if configured == "" || supplied == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(configured), []byte(supplied)) == 1
}

// cibaApproveFormHandler serves GET /ciba-approve?token=... — the
// blank approve/deny form. A wrong or missing token gets a plain 404,
// not 403, so a bad guess doesn't even confirm the route exists.
func cibaApproveFormHandler(configuredToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if !validCIBAApprovalUIToken(configuredToken, token) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = cibaApproveTemplate.Execute(w, cibaApprovePage{Token: token})
	}
}

// cibaApproveSubmitHandler serves POST /ciba-approve — reuses
// backchannelHandler.decide, the same approve/deny logic
// POST /backchannel-approve's own JSON handler calls, differing only
// in rendering an HTML result page (with a form for the next
// approval) instead of a JSON body.
func cibaApproveSubmitHandler(backchannel *backchannelHandler, configuredToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.NotFound(w, r)
			return
		}
		token := r.PostFormValue("token")
		if !validCIBAApprovalUIToken(configuredToken, token) {
			http.NotFound(w, r)
			return
		}

		authReqID := r.PostFormValue("auth_req_id")
		action := r.PostFormValue("action")

		if err := backchannel.decide(r.Context(), authReqID, action); err != nil {
			// decide's own doc comment guarantees every error it
			// returns is a *decideError — trusted directly rather than
			// defensively falling back to a generic 500 for a shape it
			// can't produce.
			de := err.(*decideError)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(de.status)
			_ = cibaApproveTemplate.Execute(w, cibaApprovePage{Token: token, Message: "Error: " + de.message})
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = cibaApproveTemplate.Execute(w, cibaApprovePage{
			Token:   token,
			Message: fmt.Sprintf("Recorded %q for auth_req_id %q.", action, authReqID),
		})
	}
}
