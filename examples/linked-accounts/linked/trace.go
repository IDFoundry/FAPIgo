package linked

import (
	"bytes"
	"context"
	"crypto/rand"
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

// trace is the protocol record of Pocketwise's link and its syncs: every
// request its FAPIgo client made, with the signed parts decoded.
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

// Steps is a copy of the steps so far; nil for a nil trace.
func (t *trace) Steps() []traceStep {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]traceStep(nil), t.steps...)
}

type traceKey struct{}

func withTrace(ctx context.Context, t *trace) context.Context {
	return context.WithValue(ctx, traceKey{}, t)
}

// tracingClient is Pocketwise's HTTP client: the demo network's,
// recording each request into the trace its context carries. It only
// forwards requests the FAPIgo client built, to Alder Bank's discovered
// endpoints and its API, and the demo network's client dials the demo's
// own listener whatever host a URL names.
type tracingClient struct{ next *http.Client }

func (c tracingClient) Do(req *http.Request) (*http.Response, error) {
	t, _ := req.Context().Value(traceKey{}).(*trace)
	if t == nil {
		return c.next.Do(req) //nolint:gosec // G704: see tracingClient
	}
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	title, detail := describeRequest(req, reqBody)
	res, err := c.next.Do(req) //nolint:gosec // G704: see tracingClient
	if err != nil {
		t.add(title, detail+"\n\n→ "+err.Error())
		return nil, err
	}
	resBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	_ = res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(resBody))
	t.add(title, fmt.Sprintf("%s\n\n→ %s\n%s", detail, res.Status, describeResponse(resBody)))
	return res, nil
}

// describeRequest summarizes a request a relying party's client made.
func describeRequest(req *http.Request, body []byte) (string, string) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", req.Method, req.URL)
	if dpop := req.Header.Get("DPoP"); dpop != "" {
		fmt.Fprintf(&b, "DPoP proof: %s\n", shorten(dpop))
	}
	if authz := req.Header.Get("Authorization"); authz != "" {
		scheme, token, _ := strings.Cut(authz, " ")
		fmt.Fprintf(&b, "Authorization: %s %s\n", scheme, shorten(token))
	}
	title := "Request"
	switch {
	case strings.HasSuffix(req.URL.Path, "/par"):
		title = "Pushed authorization request (PAR)"
	case strings.HasSuffix(req.URL.Path, "/token"):
		title = "Token request"
		if strings.Contains(string(body), "grant_type=refresh_token") {
			title = "Token request: refresh"
		}
	case strings.HasSuffix(req.URL.Path, accountsPath):
		return "Account information API call", b.String()
	}
	form, _ := url.ParseQuery(string(body))
	names := make([]string, 0, len(form))
	for key := range form {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		value := form.Get(key)
		switch key {
		case "authorization_details":
			value = prettyJSON([]byte(value))
		case "client_assertion", "code", "code_verifier", "refresh_token":
			value = shorten(value)
		}
		fmt.Fprintf(&b, "%s: %s\n", key, value)
	}
	return title, b.String()
}

// describeResponse shows a response as an observer on the wire sees it:
// JSON pretty-printed, a signed JWT's header and payload decoded, and an
// encrypted one's header only.
func describeResponse(raw []byte) string {
	text := strings.TrimSpace(string(raw))
	if parts := strings.Split(text, "."); len(parts) == 3 || len(parts) == 5 {
		return describeJOSE(text)
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return text
	}
	var idToken string
	if s, ok := m["id_token"].(string); ok {
		idToken = s
		m["id_token"] = shorten(s)
	}
	for _, k := range []string{"access_token", "refresh_token", "request_uri"} {
		if s, ok := m[k].(string); ok {
			m[k] = shorten(s)
		}
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	if idToken != "" {
		return string(out) + "\n\nid_token: " + describeJOSE(idToken)
	}
	return string(out)
}

// describeJOSE shows a compact JWS's header and payload, or a JWE's
// header and nothing else: the rest is ciphertext.
func describeJOSE(token string) string {
	parts := strings.Split(token, ".")
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return shorten(token)
	}
	if len(parts) == 5 {
		return fmt.Sprintf("encrypted (JWE, %d parts)\n  header %s\n  everything else is ciphertext: only the holder of the recipient's private key can read it", len(parts), indent(prettyJSON(header)))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return shorten(token)
	}
	return fmt.Sprintf("signed (JWS)\n  header  %s\n  payload %s", indent(prettyJSON(header)), indent(prettyJSON(payload)))
}

func indent(s string) string { return strings.ReplaceAll(s, "\n", "\n          ") }

// shorten keeps a secret or long value recognisable without showing it.
func shorten(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:12] + "…" + s[len(s)-6:]
}

func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if json.Indent(&buf, raw, "", "  ") != nil {
		return string(raw)
	}
	return buf.String()
}

// randomCode is n random characters that are easy to read aloud.
func randomCode(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
