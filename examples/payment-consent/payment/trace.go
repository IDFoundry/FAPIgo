package payment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// trace is the protocol record of one order: every request the shop's
// FAPIgo client made, and the authorization response it received, with
// the signed parts decoded — so the order page can show what each
// protection signs and binds.
type trace struct {
	mu    sync.Mutex
	steps []traceStep
}

type traceStep struct {
	Title, Detail string
}

func (t *trace) add(title, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.steps = append(t.steps, traceStep{Title: title, Detail: detail})
}

func (t *trace) Steps() []traceStep {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]traceStep(nil), t.steps...)
}

type traceKey struct{}

// traceOptions is what a request's context carries for the tracing
// client.
type traceOptions struct {
	trace *trace
	// tamperRequestObject changes the amount inside the pushed request
	// object after the client signed it.
	tamperRequestObject bool
}

func withTrace(ctx context.Context, opts traceOptions) context.Context {
	return context.WithValue(ctx, traceKey{}, opts)
}

// tracingClient is the shop's HTTP client: the demo network's, recording
// each request into the trace its context carries. It only forwards
// requests the FAPIgo client built, to Alder Bank's discovered
// endpoints, and the demo network's client dials the demo's own listener
// whatever host a URL names.
type tracingClient struct{ next *http.Client }

func (c tracingClient) Do(req *http.Request) (*http.Response, error) {
	opts, ok := req.Context().Value(traceKey{}).(traceOptions)
	if !ok || opts.trace == nil {
		return c.next.Do(req) //nolint:gosec // G704: see tracingClient
	}
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	title, detail := describeRequest(req, reqBody)
	if opts.tamperRequestObject && strings.HasSuffix(req.URL.Path, "/par") {
		reqBody = tamperRequestObject(reqBody)
		title += " — tampered in flight"
		detail = "The amount inside the signed request object was changed after the shop signed it:\n\n" + detail
	}
	req.Body = io.NopCloser(bytes.NewReader(reqBody))
	req.ContentLength = int64(len(reqBody))
	res, err := c.next.Do(req) //nolint:gosec // G704: see tracingClient
	if err != nil {
		// The protocol trace is shown in the browser, error included; a
		// real deployment keeps internal errors out of what users see.
		opts.trace.add(title, detail+"\n\n→ "+err.Error())
		return nil, err
	}
	resBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	_ = res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(resBody))
	opts.trace.add(title, fmt.Sprintf("%s\n\n→ %s\n%s", detail, res.Status, redactJSON(resBody)))
	return res, nil
}

// describeRequest summarizes a request the shop's client made.
func describeRequest(req *http.Request, body []byte) (string, string) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", req.Method, req.URL)
	if dpop := req.Header.Get("DPoP"); dpop != "" {
		fmt.Fprintf(&b, "DPoP proof: %s\n", decodeJWT(dpop))
	}
	if authz := req.Header.Get("Authorization"); authz != "" {
		scheme, token, _ := strings.Cut(authz, " ")
		fmt.Fprintf(&b, "Authorization: %s %s\n", scheme, shorten(token))
	}
	form, _ := url.ParseQuery(string(body))
	title := "Request"
	switch {
	case strings.HasSuffix(req.URL.Path, "/par"):
		title = "Pushed authorization request (PAR)"
	case strings.HasSuffix(req.URL.Path, "/token"):
		title = "Token request"
	case strings.HasSuffix(req.URL.Path, paymentsPath):
		title = "Payments API call"
		fmt.Fprintf(&b, "\n%s", body)
		return title, b.String()
	}
	names := make([]string, 0, len(form))
	for key := range form {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		values := form[key]
		switch key {
		case "request":
			fmt.Fprintf(&b, "request (signed request object): %s\n", decodeJWT(values[0]))
		case "client_assertion":
			fmt.Fprintf(&b, "client_assertion (private_key_jwt): %s\n", decodeJWT(values[0]))
		case "code", "code_verifier", "refresh_token":
			fmt.Fprintf(&b, "%s: %s\n", key, shorten(values[0]))
		default:
			fmt.Fprintf(&b, "%s: %s\n", key, values[0])
		}
	}
	return title, b.String()
}

// tamperRequestObject changes instructedAmount inside the form's
// request object, leaving its signature as it was.
func tamperRequestObject(body []byte) []byte {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return body
	}
	parts := strings.Split(form.Get("request"), ".")
	if len(parts) != 3 {
		return body
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return body
	}
	payload = bytes.Replace(payload, []byte(`"129.00"`), []byte(`"1.29"`), 1)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	form.Set("request", strings.Join(parts, "."))
	return []byte(form.Encode())
}

// decodeJWT shows a compact JWS's header and payload, not its signature.
func decodeJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return shorten(token)
	}
	var out []string
	for _, p := range parts[:2] {
		raw, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return shorten(token)
		}
		out = append(out, prettyJSON(raw))
	}
	return "\n  header  " + indent(out[0]) + "\n  payload " + indent(out[1]) + "\n  (signature " + shorten(parts[2]) + ")"
}

func indent(s string) string { return strings.ReplaceAll(s, "\n", "\n          ") }

// shorten keeps a secret or long value recognisable without showing it.
func shorten(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:12] + "…" + s[len(s)-6:]
}

// redactJSON pretty-prints a JSON response, shortening token values.
func redactJSON(raw []byte) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	for _, k := range []string{"access_token", "refresh_token", "id_token", "request_uri"} {
		if s, ok := m[k].(string); ok {
			m[k] = shorten(s)
		}
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	return string(out)
}

func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if json.Indent(&buf, raw, "", "  ") != nil {
		return string(raw)
	}
	return buf.String()
}
