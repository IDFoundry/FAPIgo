package payment

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
	// Refresh reloads the page every two seconds.
	Refresh bool
}

var hostColors = map[string]string{
	shopHost: "#1d4ed8", bankHost: "#0f766e", apiHost: "#0f766e", consoleHost: "#334155",
}

func (w *World) page(title, host string) Page {
	return Page{Title: title, Color: hostColors[host], Console: w.URL(consoleHost, "/")}
}

type consentPage struct {
	Page
	// Interaction is interactioncookie\'s tag for this page\'s form.
	Interaction         string
	ClientName, Problem string
	Payments            []consentView
}

type orderPage struct {
	Page
	Order *order
	Trace []traceStep
}

type consolePage struct {
	Page
	Shop string
	Tour []tourStep
	Log  []demokit.FetchEntry
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
main { max-width: 900px; margin: 0 auto; padding: 18px 14px 40px; }
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
ol.tour { padding-left: 20px; } ol.tour li { margin-bottom: 10px; }
details.step { margin: 6px 0; } details.step summary { cursor: pointer; font-weight: 600; }
code { font-size: 12px; word-break: break-all; }
</style></head><body>
<header><h1>{{.Title}}</h1><a href="{{.Console}}" target="_top">demo console</a></header>
<main>{{end}}
{{define "bottom"}}</main></body></html>{{end}}`

var pageTemplates = map[string]string{
	"console": `{{template "top" .}}
<p class="muted">Northgate Outfitters, a web shop, takes payment by bank from an Alder Bank customer through the FAPI 2.0 Message Signing redirect flow: a signed request object pushed to the bank (PAR), a consent screen describing the payment from its Rich Authorization Request, a signed authorization response (JARM) and a DPoP-bound access token. The attack lab tries to break each of those. Everything runs in this one process, each party at its own host. Sign in at the bank as <strong>sam</strong>, PIN <strong>2468</strong>.</p>
<p><a class="button" href="{{.Shop}}">Open the shop</a></p>
<h2>Start here</h2>
<ol class="tour">{{range .Tour}}<li class="card"><strong>{{.Title}}</strong><p>{{.Do}}</p><p class="muted">{{.Notice}}</p></li>{{end}}</ol>
<h2>Traffic between the parties</h2>
<div class="card"><p class="muted">Every request one party made to another, newest first. <a href="/">Refresh</a></p>
<table><tr><th>When</th><th>From</th><th>Request</th><th>Result</th></tr>
{{range .Log}}<tr><td class="muted">{{.Time.Format "15:04:05"}}</td><td>{{.From}}</td><td><code>{{.Method}} {{.URL}}</code></td><td>{{if .Err}}<span class="error">{{.Err}}</span>{{else}}{{.Status}}{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted">Nothing yet — open the shop.</td></tr>{{end}}
</table></div>
{{template "bottom" .}}`,

	"shop-home": `{{template "top" .}}
<div class="card"><p><strong>Storm shell rain jacket</strong>, size M</p><p class="big">€129.00</p>
<form method="post" action="/pay"><input type="hidden" name="scenario" value="normal"><button>Pay by bank with Alder Bank</button></form></div>
<h2>Attack lab: before the payment</h2>
<div class="card">
<form method="post" action="/pay" class="actions"><input type="hidden" name="scenario" value="tamper"><button class="attack">Change the amount in the signed request</button> <span class="muted">after the shop signed it, on its way to the bank</span></form>
<form method="post" action="/pay" class="actions"><input type="hidden" name="scenario" value="redirect"><button class="attack">Send the result to another redirect URI</button> <span class="muted">one the bank never registered for the shop</span></form>
<form method="post" action="/direct" class="actions"><button class="attack">Skip PAR</button> <span class="muted">send the payment request straight to the authorization endpoint</span></form>
<form method="post" action="/inject" class="actions"><button class="attack">Inject an attacker's authorization response</button> <span class="muted">approved on the attacker's own device</span></form>
</div>
{{template "bottom" .}}`,

	"consent": `{{template "top" .}}
<form method="post" action="/authorize"><input type="hidden" name="interaction" value="{{.Interaction}}">
<p><strong>{{.ClientName}}</strong> asks you to approve a payment:</p>
{{range .Payments}}<div class="card verified">
<p class="muted">Payment — checked by Alder Bank</p>
<p class="big">{{.Amount}}</p>
<p>to <strong>{{if .PayeeVerified}}{{.Payee}}{{else}}an account we can't confirm{{end}}</strong> {{if .PayeeVerified}}<span class="pill ok">name matches account</span>{{else}}<span class="pill bad">unknown payee</span>{{end}}<br><span class="muted">{{.IBAN}}</span></p>
</div>
<div class="card unverified"><p class="muted">Written by {{$.ClientName}} — not checked by Alder Bank</p>
<p>Payee name: {{.CreditorName}}<br>Reference: {{.Reference}}</p></div>{{end}}
<div class="card"><h2>Sign in to approve</h2>
{{if .Problem}}<p class="error">{{.Problem}}</p>{{end}}
<p><label>Username <input type="text" name="username" value="sam" autocomplete="off"></label></p>
<p><label>PIN <input type="text" name="pin" value="" autocomplete="off" placeholder="2468"></label></p>
<p class="actions"><button name="decision" value="approve">Approve payment</button> <button class="secondary" name="decision" value="deny">Cancel</button></p></div>
</form>
{{template "bottom" .}}`,

	"shop-order": `{{template "top" .}}
{{with .Order}}
{{if eq .Status "paid"}}<div class="card"><p><span class="pill ok">paid</span></p>
{{with .Payment}}{{if .OK}}<p><strong>Thank you — your payment went through.</strong></p>{{else}}<p class="error">The payment was refused.</p>{{end}}<pre>{{.Body}}</pre>{{end}}</div>
<div class="card" id="attempts"><h2>Attack lab: after the payment</h2>
<form method="post" action="/attack" class="actions"><input type="hidden" name="id" value="{{.ID}}">
<button class="attack" name="kind" value="overcharge">Charge €1,290.00</button>
<button class="attack" name="kind" value="again">Charge again</button>
<button class="attack" name="kind" value="stolen">Use the token from another device</button>
<button class="attack" name="kind" value="reuse">Redeem the code again</button>
<button class="attack" name="kind" value="replay">Replay the response</button>
<button class="attack" name="kind" value="forged">Forge the response</button></form>
{{range .Attempts}}<p>{{if .Refused}}<span class="pill ok">refused</span>{{else}}<span class="pill bad">allowed</span>{{end}} {{.Title}}</p><pre>{{.Result}}</pre>{{end}}
</div>{{end}}
{{if eq .Status "redirected"}}{{if .Injected}}<div class="card"><p>You have a checkout in progress. Instead of approving it, open the attacker's authorization response in this browser:</p>
<p><a class="button attack" href="{{.Injected}}">Open the attacker's response</a></p></div>{{else}}<div class="card"><p>Waiting for Alder Bank.</p></div>{{end}}{{end}}
{{if eq .Status "declined"}}<div class="card"><span class="pill bad">declined</span><p class="error">{{.Problem}}</p></div>{{end}}
{{if eq .Status "failed"}}<div class="card">{{if eq .Scenario "normal"}}<span class="pill bad">failed</span>{{else}}<span class="pill ok">refused</span>{{end}}<p class="error">{{.Problem}}</p></div>{{end}}
{{end}}
<h2>Protocol trace</h2>
<div class="card">{{range .Trace}}<details class="step"><summary>{{.Title}}</summary><pre>{{.Detail}}</pre></details>{{else}}<p class="muted">Nothing yet.</p>{{end}}</div>
<p><a class="button secondary" href="/">Back to the shop</a></p>
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
