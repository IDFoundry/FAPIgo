// This file adds a request/response transcript to fixed-identity
// mode's own evidence output (fixed_identity.go, evidence.go) — a bare
// "DRIVER: none — completed without error" or "DRIVER: complete
// authorization: token: iss does not match expected issuer" line
// states the *outcome* but not what the client actually saw and did to
// reach it. OIDF's own RP certification submission instructions are
// explicit that evidence "must demonstrate that your application is
// detecting the error condition under test" — a bare error string
// doesn't show that on its own. OIDF's own official reference RP
// client (gitlab.com/openid/sample-openbanking-client-nodejs) logs
// exactly this level of detail itself: every PAR request/response, the
// authorization URL, the full authentication response query, and the
// specific checks it ran against the callback — this driver's own
// transcript covers the same ground generically, at the HTTP-transport
// level, rather than hand-instrumenting each call site individually.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// interactionRecorder accumulates a redacted transcript of every HTTP
// request/response pair a run actually makes against the suite —
// loggingRoundTripper is what populates one, by wrapping an
// *http.Client's own Transport; every consumer of that client
// (discovery, JWKS, PAR, the authorize redirect, token exchange, the
// resource call) then contributes to the same transcript for free,
// with no call-site-specific instrumentation needed.
type interactionRecorder struct {
	mu      sync.Mutex
	entries []string
}

func (r *interactionRecorder) log(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, fmt.Sprintf(format, args...))
}

// transcript joins every recorded entry, oldest first — "" if nothing
// was ever recorded (writeEvidence's own caller treats that as "omit
// the section", not as an empty one).
func (r *interactionRecorder) transcript() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.entries, "\n")
}

// sensitiveBodyFields are the JSON/form field names loggingRoundTripper
// redacts before recording a request or response body — actual bearer
// credentials (an access/refresh token, a client assertion or secret),
// never protocol data a reader needs to see to verify what happened:
// code, state, nonce, and an id_token's own claims are exactly what
// most of these certification tests are about, so those are recorded
// in full.
var sensitiveBodyFields = map[string]bool{
	"access_token":     true,
	"refresh_token":    true,
	"client_assertion": true,
	"client_secret":    true,
}

// loggingRoundTripper wraps next, recording a summary of every
// request/response pair into rec before returning the response
// untouched to the real caller — both bodies are read in full and
// replaced with a fresh reader over the same bytes, the same trick
// net/http/httputil.DumpRequest uses, so this is transparent to
// whatever normally consumes them.
type loggingRoundTripper struct {
	next http.RoundTripper
	rec  *interactionRecorder
}

func (t *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBody := drainAndRestore(&req.Body)
	t.rec.log("--> %s %s%s", req.Method, req.URL.String(), bodySummary(req.Header.Get("Content-Type"), reqBody))

	res, err := t.next.RoundTrip(req)
	if err != nil {
		t.rec.log("<-- error: %v", err)
		return res, err
	}

	resBody := drainAndRestore(&res.Body)
	locNote := ""
	if loc := res.Header.Get("Location"); loc != "" {
		locNote = "\n    Location: " + loc
	}
	t.rec.log("<-- %s%s%s", res.Status, locNote, bodySummary(res.Header.Get("Content-Type"), resBody))
	return res, nil
}

// drainAndRestore reads *body fully (nil-safe) and replaces it with a
// fresh reader over the same bytes.
func drainAndRestore(body *io.ReadCloser) []byte {
	if *body == nil {
		return nil
	}
	b, _ := io.ReadAll(*body)
	*body = io.NopCloser(bytes.NewReader(b))
	return b
}

// bodySummary renders body for the transcript: redacted, compact JSON
// for a JSON content type; redacted "key=value" pairs for a form
// content type; a byte count for anything else this doesn't know how
// to safely redact; "" for an empty body.
func bodySummary(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	switch {
	case strings.Contains(contentType, "json"):
		return "\n    " + redactJSON(body)
	case strings.Contains(contentType, "form-urlencoded"):
		return "\n    " + redactForm(body)
	default:
		return fmt.Sprintf("\n    (%d bytes, %s)", len(body), contentType)
	}
}

func redactJSON(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Sprintf("(%d bytes, unparsed json)", len(body))
	}
	for k := range m {
		if sensitiveBodyFields[k] {
			m[k] = "<redacted>"
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf("(%d bytes, unparsed json)", len(body))
	}
	return string(out)
}

func redactForm(body []byte) string {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return fmt.Sprintf("(%d bytes, unparsed form)", len(body))
	}
	for k := range values {
		if sensitiveBodyFields[k] {
			values.Set(k, "<redacted>")
		}
	}
	return values.Encode()
}
