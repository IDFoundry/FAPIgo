package payroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
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

// trace is the protocol record of one run or attack: every request
// Ledgerline's FAPIgo client made, the certificate its connection
// presented, and the access token decoded — so a page can show what the
// token is bound to.
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

// tracingClient is Ledgerline's HTTP client: the demo network's,
// presenting the certificate cert returns, recording each request into
// the trace its context carries. It only forwards requests the FAPIgo
// client built, to Alder Bank's discovered endpoints and its API, and
// the demo network's client dials the demo's own listener whatever
// host a URL names.
type tracingClient struct {
	next *http.Client
	cert func() *tls.Certificate
}

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
	title, detail := describeRequest(req, reqBody, c.cert())
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

// describeRequest summarizes a request Ledgerline's client made, with
// the certificate its TLS connection presents.
func describeRequest(req *http.Request, body []byte, cert *tls.Certificate) (string, string) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", req.Method, req.URL)
	if cert == nil || cert.Leaf == nil {
		b.WriteString("TLS client certificate: none\n")
	} else {
		v := describeCertificate(cert.Leaf)
		fmt.Fprintf(&b, "TLS client certificate:\n  subject  %s\n  issuer   %s\n  serial   %s\n  x5t#S256 %s\n", v.Subject, v.Issuer, v.Serial, v.Thumbprint)
	}
	if authz := req.Header.Get("Authorization"); authz != "" {
		scheme, token, _ := strings.Cut(authz, " ")
		fmt.Fprintf(&b, "Authorization: %s %s\n", scheme, shorten(token))
	}
	if strings.HasSuffix(req.URL.Path, batchesPath) {
		fmt.Fprintf(&b, "\n%s", summarizeBatch(body))
		return "Payroll API call", b.String()
	}
	form, _ := url.ParseQuery(string(body))
	names := make([]string, 0, len(form))
	for key := range form {
		names = append(names, key)
	}
	sort.Strings(names)
	b.WriteString("\n")
	for _, key := range names {
		value := form.Get(key)
		if key == "authorization_details" {
			value = prettyJSON([]byte(value))
		}
		fmt.Fprintf(&b, "%s: %s\n", key, value)
	}
	return "Token request (client credentials)", b.String()
}

// summarizeBatch shows a payroll batch's account, total and first
// payment rather than every salary.
func summarizeBatch(body []byte) string {
	var b batch
	if json.Unmarshal(body, &b) != nil || len(b.Payments) == 0 {
		return string(body)
	}
	var total int64
	for _, p := range b.Payments {
		c, _ := cents(p.InstructedAmount.Amount)
		total += c
	}
	first := b.Payments[0]
	return fmt.Sprintf("debtorAccount: %s\nreference: %s\n%d payments, %s in total, starting:\n  %s  %s  EUR %s",
		b.DebtorAccount.IBAN, b.Reference, len(b.Payments), euros(total), first.CreditorName, first.CreditorAccount.IBAN, first.InstructedAmount.Amount)
}

// describeResponse pretty-prints a JSON response, decoding an access
// token so its cnf claim shows.
func describeResponse(raw []byte) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	token, _ := m["access_token"].(string)
	delete(m, "access_token")
	out, _ := json.MarshalIndent(m, "", "  ")
	if token == "" {
		return string(out)
	}
	return string(out) + "\n\naccess_token " + shorten(token) + ", decoded:\n" + prettyJSON(jwtPayload(token))
}

// jwtPayload is a compact JWS's payload, unverified.
func jwtPayload(token string) []byte {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	return raw
}

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

func randomCode(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
