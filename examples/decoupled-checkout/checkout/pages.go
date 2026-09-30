package checkout

import (
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/idfoundry/fapigo/examples/internal/demokit"
)

// Page is what every page's layout needs.
type Page struct {
	Title, Color, Console string
	// Refresh reloads the page every two seconds, while it's waiting on
	// something.
	Refresh bool
}

var hostColors = map[string]string{
	bankHost: "#0f766e", phoneHost: "#0f766e", apiHost: "#0f766e",
	tillHost: "#9a3412", pocketwiseHost: "#7c3aed", consoleHost: "#334155",
}

func (w *World) page(title, host string) Page {
	return Page{Title: title, Color: hostColors[host], Console: w.URL(consoleHost, "/")}
}

type phoneHomePage struct {
	Page
	Owner         string
	Notifications []notificationView
}

type approvalPage struct {
	Page
	AuthReqID, ClientName, BindingMessage, Expires string
	Payments                                       []paymentView
	Access                                         []accessView
}

type tillOrderPage struct {
	Page
	Order *order
}

type pocketwiseLinkPage struct {
	Page
	Link *link
}

type consolePage struct {
	Page
	Till, Phone, Pocketwise string
	Tour                    []tourStep
	Log                     []demokit.FetchEntry
}

type errorPage struct {
	Page
	Heading, Detail string
}

const layout = `{{define "top"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
{{if .Refresh}}<meta http-equiv="refresh" content="2">{{end}}
<title>{{.Title}}</title>
<style>
:root { --accent: {{.Color}}; --ink: #1f2937; --muted: #6b7280; --line: #e5e7eb; --bg: #f8fafc; --ok: #047857; --bad: #b91c1c; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--ink); background: var(--bg); }
header { background: var(--accent); color: #fff; padding: 12px 18px; display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
header h1 { margin: 0; font-size: 18px; font-weight: 600; }
header a { color: #fff; opacity: .85; font-size: 12px; }
main { max-width: 1200px; margin: 0 auto; padding: 18px 14px 40px; }
h2 { font-size: 15px; margin: 22px 0 8px; }
.card { background: #fff; border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; }
.muted { color: var(--muted); font-size: 13px; }
.pill { display: inline-block; border-radius: 999px; padding: 1px 9px; font-size: 12px; font-weight: 600; }
.ok { background: #d1fae5; color: var(--ok); } .bad { background: #fee2e2; color: var(--bad); } .off { background: #f3f4f6; color: var(--muted); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
pre { background: #0f172a; color: #e2e8f0; padding: 10px; border-radius: 8px; overflow-x: auto; font-size: 12px; white-space: pre-wrap; word-break: break-word; }
button, .button { background: var(--accent); color: #fff; border: 0; border-radius: 7px; padding: 8px 14px; font: inherit; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }
button.secondary { background: #fff; color: var(--ink); border: 1px solid var(--line); }
button.attack { background: #fff; color: var(--bad); border: 1px solid #fecaca; }
input[type=text] { font: inherit; padding: 6px 8px; border: 1px solid var(--line); border-radius: 6px; }
.error { color: var(--bad); font-size: 13px; word-break: break-word; }
.big { font-size: 28px; font-weight: 700; }
.verified { border-left: 4px solid var(--ok); }
.unverified { border-left: 4px solid #f59e0b; background: #fffbeb; }
label.row { display: flex; gap: 8px; align-items: center; padding: 3px 0; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 8px; }
.actions form { margin: 0; }
.devices { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.devices iframe { width: 100%; height: 640px; border: 1px solid var(--line); border-radius: 14px; background: #fff; }
.devices .label { font-size: 12px; color: var(--muted); margin: 0 0 4px 4px; }
@media (max-width: 900px) { .devices { grid-template-columns: 1fr; } }
ol.tour { padding-left: 20px; } ol.tour li { margin-bottom: 10px; }
code { font-size: 12px; word-break: break-all; }
</style></head><body>
<header><h1>{{.Title}}</h1><a href="{{.Console}}" target="_top">demo console</a></header>
<main>{{end}}
{{define "bottom"}}</main></body></html>{{end}}`

var pageTemplates = map[string]string{
	"console": `{{template "top" .}}
<p class="muted">Alder Bank's customer approves, on their phone, a payment or account access that was started on another device — Harbour Coffee's till, or the Pocketwise app — using CIBA. The phone shows exactly what's being approved, from the request's structured authorization details, and the bank's APIs then allow exactly that. Everything runs in this one process, each party at its own host. The customer is <strong>sam</strong>.</p>
<div class="devices">
<div><p class="label">Harbour Coffee till — {{.Till}}</p><iframe src="{{.Till}}" title="Harbour Coffee till"></iframe></div>
<div><p class="label">Sam's phone — {{.Phone}}</p><iframe src="{{.Phone}}" title="Sam's phone"></iframe></div>
<div><p class="label">Pocketwise app — {{.Pocketwise}}</p><iframe src="{{.Pocketwise}}" title="Pocketwise"></iframe></div>
</div>
<h2>Start here</h2>
<ol class="tour">{{range .Tour}}<li class="card"><strong>{{.Title}}</strong><p>{{.Do}}</p><p class="muted">{{.Notice}}</p></li>{{end}}</ol>
<h2>Traffic between the parties</h2>
<div class="card"><p class="muted">Every request one party made to another, newest first. <a href="/">Refresh</a></p>
<table><tr><th>When</th><th>From</th><th>Request</th><th>Result</th></tr>
{{range .Log}}<tr><td class="muted">{{.Time.Format "15:04:05"}}</td><td>{{.From}}</td><td><code>{{.Method}} {{.URL}}</code></td><td>{{if .Err}}<span class="error">{{.Err}}</span>{{else}}{{.Status}}{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted">Nothing yet — start a checkout.</td></tr>{{end}}
</table></div>
{{template "bottom" .}}`,

	"phone-home": `{{template "top" .}}
<p class="muted">{{.Owner}}'s phone. This screen checks for new requests every two seconds.</p>
{{range .Notifications}}<a href="/request?id={{.AuthReqID}}" style="text-decoration:none;color:inherit"><div class="card">
<strong>{{.ClientName}}</strong> <span class="muted">· {{.Age}} ago</span><br>{{.Summary}}<br><span class="button" style="margin-top:8px">Review</span></div></a>
{{else}}<div class="card muted">No requests waiting.</div>{{end}}
{{template "bottom" .}}`,

	"phone-approve": `{{template "top" .}}
<form method="post" action="/decide"><input type="hidden" name="id" value="{{.AuthReqID}}">
<p><strong>{{.ClientName}}</strong> is asking you to approve:</p>
{{range .Payments}}<div class="card verified">
<p class="muted">Payment — checked by Alder Bank</p>
<p class="big">{{.Amount}}</p>
<p>to <strong>{{if .PayeeVerified}}{{.Payee}}{{else}}an account we can't confirm{{end}}</strong> {{if .PayeeVerified}}<span class="pill ok">name matches account</span>{{else}}<span class="pill bad">unknown payee</span>{{end}}<br><span class="muted">{{.IBAN}}</span></p>
<p>from your <strong>{{.DebitAccount}}</strong> account</p>
</div>
<div class="card unverified"><p class="muted">Written by {{$.ClientName}} — not checked by Alder Bank</p>
<p>Payee name: {{.CreditorName}}<br>Reference: {{.Reference}}</p></div>{{end}}
{{range .Access}}<div class="card verified">
<p class="muted">Read access — untick anything you'd rather not share</p>
<h2>Accounts</h2>{{range .Accounts}}<label class="row"><input type="checkbox" name="account" value="{{.Value}}" checked> {{.Label}}</label>{{end}}
<h2>What they may see</h2>{{range .Actions}}<label class="row"><input type="checkbox" name="action" value="{{.Value}}" checked> {{.Label}}</label>{{end}}
</div>{{end}}
{{if .BindingMessage}}<div class="card unverified"><p class="muted">Message from {{.ClientName}} — the device you're using should show the same</p><p><strong>{{.BindingMessage}}</strong></p></div>{{end}}
<p class="actions"><button name="decision" value="approve">Approve</button> <button class="secondary" name="decision" value="deny">Deny</button></p>
<p class="muted">Expires in {{.Expires}}.</p>
</form>
{{template "bottom" .}}`,

	"till-home": `{{template "top" .}}
<div class="card"><p>1 × flat white, 1 × cinnamon bun, beans to go</p><p class="big">€42.50</p>
<form method="post" action="/pay">
<p><label>Alder Bank customer <input type="text" name="customer" value="sam"></label></p>
<p class="actions"><button name="scenario" value="coffee">Pay with Alder Bank</button></p>
<p class="muted">Attack: <button class="attack" name="scenario" value="misleading">Ask for €500 while calling it a refund</button></p>
</form></div>
{{template "bottom" .}}`,

	"till-order": `{{template "top" .}}
{{with .Order}}
{{if eq .Status "waiting"}}<div class="card"><p class="big">€{{.Amount}}</p><p>Approve this on your phone. Check it shows:</p><p><strong>{{.Message}}</strong></p><p class="muted">Waiting for Alder Bank… (polling)</p></div>{{end}}
{{if eq .Status "approved"}}<div class="card"><p><span class="pill ok">approved</span></p>
{{with .Payment}}{{if .OK}}<p><strong>Paid.</strong></p>{{else}}<p class="error">The payment was refused.</p>{{end}}<pre>{{.Body}}</pre>{{end}}
<p class="muted">Authorization details the bank granted:</p><pre>{{.Granted}}</pre></div>
<div class="card" id="attempts"><strong>Now try to misuse these tokens</strong>
<form method="post" action="/attack" class="actions"><input type="hidden" name="id" value="{{.ID}}">
<button class="attack" name="kind" value="overcharge">Charge €420 instead</button>
<button class="attack" name="kind" value="again">Charge again</button>
<button class="attack" name="kind" value="stolen">Use the token from another device</button>
<button class="attack" name="kind" value="reuse">Reuse the auth_req_id</button></form>
{{range .Attempts}}<p>{{if .Refused}}<span class="pill ok">refused</span>{{else}}<span class="pill bad">allowed</span>{{end}} {{.Title}}</p><pre>{{.Result}}</pre>{{end}}
</div>{{end}}
{{if eq .Status "denied"}}<div class="card"><span class="pill bad">declined</span><p class="error">{{.Problem}}</p></div>{{end}}
{{if eq .Status "expired"}}<div class="card"><span class="pill off">expired</span><p>Nobody answered in time.</p></div>{{end}}
{{if eq .Status "failed"}}<div class="card"><span class="pill bad">failed</span><p class="error">{{.Problem}}</p></div>{{end}}
{{end}}
<p><a class="button secondary" href="/">New order</a></p>
{{template "bottom" .}}`,

	"pocketwise-home": `{{template "top" .}}
<div class="card"><p>See all your money in one place. Link your Alder Bank accounts — you'll approve it on your phone.</p>
<form method="post" action="/link">
<p><label>Alder Bank customer <input type="text" name="customer" value="sam"></label></p>
<p class="actions"><button name="scenario" value="accounts">Link Alder Bank</button></p>
<p class="muted">Attack: <button class="attack" name="scenario" value="payment">Ask for a €9.99 payment too</button></p>
</form></div>
{{template "bottom" .}}`,

	"pocketwise-link": `{{template "top" .}}
{{with .Link}}
{{if eq .Status "waiting"}}<div class="card"><p>Approve linking on your phone.</p><p class="muted">Waiting for Alder Bank to notify us — Pocketwise doesn't poll.</p></div>{{end}}
{{if eq .Status "linked"}}<div class="card"><p><span class="pill ok">linked</span> <span class="muted">notified {{.Pinged.Format "15:04:05"}}</span></p>
<table><tr><th>Account</th><th>Read</th><th>Result</th></tr>
{{range .Readings}}<tr><td>{{.Account}}</td><td>{{.What}}</td><td>{{if .OK}}<span class="pill ok">allowed</span>{{else}}<span class="pill bad">refused</span>{{end}}<pre>{{.Result}}</pre></td></tr>{{end}}</table>
<p class="muted">Authorization details the bank granted:</p><pre>{{.Granted}}</pre></div>{{end}}
{{if eq .Status "denied"}}<div class="card"><span class="pill bad">declined</span><p class="error">{{.Problem}}</p></div>{{end}}
{{if eq .Status "expired"}}<div class="card"><span class="pill off">expired</span></div>{{end}}
{{if eq .Status "failed"}}<div class="card"><span class="pill bad">refused</span><p class="error">{{.Problem}}</p></div>{{end}}
{{end}}
<p><a class="button secondary" href="/">Start again</a></p>
{{template "bottom" .}}`,

	"error": `{{template "top" .}}
<div class="card"><h2>{{.Heading}}</h2><p class="error">{{.Detail}}</p><p><a href="/">Back</a></p></div>
{{template "bottom" .}}`,
}

var templates = func() map[string]*template.Template {
	out := make(map[string]*template.Template, len(pageTemplates))
	for name, body := range pageTemplates {
		out[name] = template.Must(template.Must(template.New(name).Parse(layout)).Parse(body))
	}
	return out
}()

func (w *World) render(rw http.ResponseWriter, name string, data any) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates[name].ExecuteTemplate(rw, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// renderError shows detail, often an internal error's text, to the
// browser: useful in a demo for seeing why something was refused, but a
// real service should log it instead.
func (w *World) renderError(rw http.ResponseWriter, host string, status int, heading, detail string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	data := errorPage{Page: w.page("Something went wrong", host), Heading: heading, Detail: strings.TrimSpace(detail)}
	if err := templates["error"].ExecuteTemplate(rw, "error", data); err != nil {
		log.Printf("render error page: %v", err)
	}
}
