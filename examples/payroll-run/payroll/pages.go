package payroll

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
}

var hostColors = map[string]string{
	ledgerlineHost: "#7c3aed", bankHost: "#0f766e", apiHost: "#0f766e", consoleHost: "#334155",
}

func (w *World) page(title, host string) Page {
	return Page{Title: title, Color: hostColors[host], Console: w.URL(consoleHost, "/")}
}

type ledgerlinePage struct {
	Page
	Certificate  certificateView
	Total, Limit string
	Staff        []staffRow
	Attempts     []attempt
	Rotation     *rotation
}

type runPage struct {
	Page
	Run   runView
	Trace []traceStep
}

type consolePage struct {
	Page
	Ledgerline string
	Tour       []tourStep
	Log        []demokit.FetchEntry
}

type errorPage struct {
	Page
	Heading, Detail string
}

const layout = `{{define "top"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
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
.ok { background: #d1fae5; color: var(--ok); } .bad { background: #fee2e2; color: var(--bad); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
td.num { text-align: right; white-space: nowrap; }
dl.cert { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; margin: 0; font-size: 13px; }
dl.cert dt { color: var(--muted); } dl.cert dd { margin: 0; word-break: break-all; }
pre { background: #0f172a; color: #e2e8f0; padding: 10px; border-radius: 8px; overflow-x: auto; font-size: 12px; white-space: pre-wrap; word-break: break-word; }
button, .button { background: var(--accent); color: #fff; border: 0; border-radius: 7px; padding: 8px 14px; font: inherit; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }
button.secondary, .button.secondary { background: #fff; color: var(--ink); border: 1px solid var(--line); }
button.attack { background: #fff; color: var(--bad); border: 1px solid #fecaca; text-align: left; }
.error { color: var(--bad); font-size: 13px; word-break: break-word; }
.big { font-size: 28px; font-weight: 700; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 8px; }
.actions form { margin: 0; }
ol.tour { padding-left: 20px; } ol.tour li { margin-bottom: 10px; }
details.step { margin: 6px 0; } details.step summary { cursor: pointer; font-weight: 600; }
details.wide summary { cursor: pointer; }
code { font-size: 12px; word-break: break-all; }
</style></head><body>
<header><h1>{{.Title}}</h1><a href="{{.Console}}" target="_top">demo console</a></header>
<main>{{end}}
{{define "bottom"}}</main></body></html>{{end}}
{{define "cert"}}<dl class="cert"><dt>Subject</dt><dd>{{.Subject}}</dd><dt>Issuer</dt><dd>{{.Issuer}}</dd><dt>Serial</dt><dd>{{.Serial}}</dd><dt>x5t#S256</dt><dd><code>{{.Thumbprint}}</code></dd><dt>Expires</dt><dd>{{.Expires}}</dd>{{with .Chain}}<dt>Chain</dt><dd>{{.}}</dd>{{end}}</dl>{{end}}
{{define "attempt"}}<div class="card"><p>{{if .Refused}}<span class="pill ok">refused</span>{{else}}<span class="pill bad">allowed</span>{{end}} {{.Title}}</p><pre>{{.Result}}</pre>
{{range .Trace}}<details class="step"><summary>{{.Title}}</summary><pre>{{.Detail}}</pre></details>{{end}}</div>{{end}}`

var pageTemplates = map[string]string{
	"console": `{{template "top" .}}
<p class="muted">Ledgerline, a payroll provider, pays Harbour Coffee's staff from Harbour Coffee's account at Alder Bank — server to server, with no one signing in. Ledgerline authenticates with a TLS client certificate from Alder Bank's client CA (mutual TLS, RFC 8705), gets an access token bound to that certificate through the client credentials grant, and may pay only the batch Harbour Coffee's standing mandate allows (a Rich Authorization Request). The attack lab tries to get around each of those. Everything runs in this one process, each party at its own host.</p>
<p><a class="button" href="{{.Ledgerline}}">Open Ledgerline</a></p>
<h2>Start here</h2>
<ol class="tour">{{range .Tour}}<li class="card"><strong>{{.Title}}</strong><p>{{.Do}}</p><p class="muted">{{.Notice}}</p></li>{{end}}</ol>
<h2>Traffic between the parties</h2>
<div class="card"><p class="muted">Every request one party made to another, newest first. <a href="/">Refresh</a></p>
<table><tr><th>When</th><th>From</th><th>Request</th><th>Result</th></tr>
{{range .Log}}<tr><td class="muted">{{.Time.Format "15:04:05"}}</td><td>{{.From}}</td><td><code>{{.Method}} {{.URL}}</code></td><td>{{if .Err}}<span class="error">{{.Err}}</span>{{else}}{{.Status}}{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted">Nothing yet — open Ledgerline.</td></tr>{{end}}
</table></div>
{{template "bottom" .}}`,

	"ledgerline-home": `{{template "top" .}}
<div class="card"><p class="muted">Harbour Coffee — October payroll, paid from its Alder Bank account</p>
<p class="big">{{.Total}}</p><p>{{len .Staff}} salaries. Harbour Coffee's mandate lets Ledgerline pay up to {{.Limit}} per batch from this account.</p>
<form method="post" action="/run"><button>Run payroll</button></form>
<details class="wide"><summary class="muted">The staff list</summary><table><tr><th>Name</th><th>Account</th><th>Pay</th></tr>
{{range .Staff}}<tr><td>{{.Name}}</td><td><code>{{.IBAN}}</code></td><td class="num">{{.Pay}}</td></tr>{{end}}</table></details></div>
<h2>Ledgerline's certificate</h2>
<div class="card">{{template "cert" .Certificate}}<p class="muted">Alder Bank registered Ledgerline by this subject, issued by its client CA under its root CA. Ledgerline presents the certificate on every connection to the bank's mTLS hosts; its key never leaves Ledgerline.</p></div>
<h2 id="attempts">Attack lab: at the token endpoint</h2>
<div class="card">
{{range attackTitles}}<form method="post" action="/attack" class="actions"><input type="hidden" name="kind" value="{{.Kind}}"><button class="attack">{{.Title}}</button></form>{{end}}
</div>
{{range .Attempts}}{{template "attempt" .}}{{end}}
<h2 id="rotation">Rotate the certificate</h2>
<div class="card"><p>The bank's CA issues Ledgerline a new certificate with the same subject. Ledgerline gets a token with the old one first, then switches.</p>
<form method="post" action="/rotate"><button class="secondary">Rotate Ledgerline's certificate</button></form></div>
{{with .Rotation}}<div class="card"><table><tr><th></th><th>Old certificate</th><th>New certificate</th></tr>
<tr><td class="muted">Serial</td><td>{{.Old.Serial}}</td><td>{{.New.Serial}}</td></tr>
<tr><td class="muted">x5t#S256</td><td><code>{{.Old.Thumbprint}}</code></td><td><code>{{.New.Thumbprint}}</code></td></tr>
<tr><td class="muted">Subject</td><td colspan="2">{{.New.Subject}}</td></tr></table></div>
{{range .Steps}}{{template "attempt" .}}{{end}}{{end}}
{{template "bottom" .}}`,

	"ledgerline-run": `{{template "top" .}}
{{with .Run}}
{{if eq .Status "paid"}}<div class="card"><p><span class="pill ok">paid</span></p>{{with .Payment}}<pre>{{.Body}}</pre>{{end}}
{{with .BoundTo}}<p class="muted">The token was bound to the certificate Ledgerline presented:</p>{{template "cert" .}}{{end}}</div>
<h2 id="attempts">Attack lab: after the run</h2>
<div class="card"><form method="post" action="/run/attack" class="actions"><input type="hidden" name="id" value="{{.ID}}">
<button class="attack" name="kind" value="stolen">Use the token without Ledgerline's certificate</button>
<button class="attack" name="kind" value="stolen-copperfield">Use the token with Copperfield's certificate</button>
<button class="attack" name="kind" value="overspend">Add €5,000.00 to the batch</button>
<button class="attack" name="kind" value="again">Pay the batch again</button></form></div>
{{range .Attempts}}{{template "attempt" .}}{{end}}
{{else}}<div class="card"><span class="pill bad">failed</span><p class="error">{{.Problem}}</p>{{with .Payment}}<pre>{{.Body}}</pre>{{end}}</div>{{end}}
{{end}}
<h2>Protocol trace</h2>
<div class="card">{{range .Trace}}<details class="step"><summary>{{.Title}}</summary><pre>{{.Detail}}</pre></details>{{else}}<p class="muted">Nothing yet.</p>{{end}}</div>
<p><a class="button secondary" href="/">Back to Ledgerline</a></p>
{{template "bottom" .}}`,

	"error": `{{template "top" .}}
<div class="card"><h2>{{.Heading}}</h2><p class="error">{{.Detail}}</p><p><a href="/">Back</a></p></div>
{{template "bottom" .}}`,
}

// attackOrder is the order the token endpoint attacks are listed in.
var attackOrder = []string{"no-cert", "self-signed", "impostor", "expired", "revoked", "retired-ca", "copperfield", "other-account", "over-limit"}

var templates = func() map[string]*template.Template {
	funcs := template.FuncMap{"attackTitles": func() []struct{ Kind, Title string } {
		out := make([]struct{ Kind, Title string }, len(attackOrder))
		for i, kind := range attackOrder {
			out[i].Kind, out[i].Title = kind, tokenAttacks[kind].title
		}
		return out
	}}
	out := make(map[string]*template.Template, len(pageTemplates))
	for name, body := range pageTemplates {
		out[name] = template.Must(template.Must(template.New(name).Funcs(funcs).Parse(layout)).Parse(body))
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
