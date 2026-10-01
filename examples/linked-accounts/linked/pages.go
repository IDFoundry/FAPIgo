package linked

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
	pocketwiseHost: "#7c3aed", bankHost: "#0f766e", apiHost: "#0f766e", consoleHost: "#334155",
}

func (w *World) page(title, host string) Page {
	return Page{Title: title, Color: hostColors[host], Console: w.URL(consoleHost, "/")}
}

type consentPage struct {
	Page
	ClientName, Problem, Actions, Until string
	Accounts                            []bankAccount
}

type connectionView struct {
	GrantID, App, ApprovedAt, Until string
	Accounts                        []string
	Revoked, Expired                bool
}

type connectedAppsPage struct {
	Page
	Connections []connectionView
}

type pocketwisePage struct {
	Page
	Linked   bool
	LinkedAt string
	Accounts []accountView
	Log      []syncEntry
	Attempts []attempt
	Trace    []traceStep
}

type consolePage struct {
	Page
	Pocketwise, ConnectedApps string
	DaysAhead                 int
	Tour                      []tourStep
	Log                       []demokit.FetchEntry
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
<p class="muted">Pocketwise, a budgeting app, links an Alder Bank customer's accounts for 90 days. The customer approves once; after that Pocketwise syncs on its own, redeeming its refresh token for a fresh DPoP-bound access token, with nobody signing in. The customer can withdraw Pocketwise's access at any time from the bank's Connected apps page, and the consent runs out after 90 days. The attack lab tries to misuse the long-lived access. Everything runs in this one process, each party at its own host. Sign in at the bank as <strong>sam</strong>, PIN <strong>2468</strong>.</p>
<p class="actions"><a class="button" href="{{.Pocketwise}}">Open Pocketwise</a> <a class="button secondary" href="{{.ConnectedApps}}">Alder Bank: Connected apps</a></p>
<div class="card"><h2>Demo clock</h2><p>{{if .DaysAhead}}Running <strong>{{.DaysAhead}} days</strong> ahead of real time.{{else}}Running at real time.{{end}} The bank, its API and Pocketwise all read this clock.</p>
<form method="post" action="/clock" class="actions"><button class="secondary" name="days" value="1">+1 day</button> <button class="secondary" name="days" value="30">+30 days</button> <button class="secondary" name="days" value="91">+91 days</button></form></div>
<h2>Start here</h2>
<ol class="tour">{{range .Tour}}<li class="card"><strong>{{.Title}}</strong><p>{{.Do}}</p><p class="muted">{{.Notice}}</p></li>{{end}}</ol>
<h2>Traffic between the parties</h2>
<div class="card"><p class="muted">Every request one party made to another, newest first. <a href="/">Refresh</a></p>
<table><tr><th>When</th><th>From</th><th>Request</th><th>Result</th></tr>
{{range .Log}}<tr><td class="muted">{{.Time.Format "15:04:05"}}</td><td>{{.From}}</td><td><code>{{.Method}} {{.URL}}</code></td><td>{{if .Err}}<span class="error">{{.Err}}</span>{{else}}{{.Status}}{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted">Nothing yet — open Pocketwise.</td></tr>{{end}}
</table></div>
{{template "bottom" .}}`,

	"pocketwise": `{{template "top" .}}
{{if .Linked}}<div class="card"><p><span class="pill ok">linked</span> to Alder Bank since {{.LinkedAt}}</p>
<table><tr><th>Account</th><th>Balance</th><th>Latest</th></tr>{{range .Accounts}}<tr><td>{{.Name}}<br><span class="muted">{{.IBAN}}</span></td><td>{{.Balance}}</td><td>{{with index .Transactions 0}}{{.Date}} {{.Description}} {{.Amount}}{{end}}</td></tr>{{end}}</table>
<form method="post" action="/sync" class="actions"><button>Sync now</button></form>
<form method="post" action="/rotate-key" class="actions"><button class="secondary">Rotate Pocketwise's DPoP key</button></form></div>
<div class="card" id="attempts"><h2>Attack lab</h2>
<form method="post" action="/attack" class="actions">
<button class="attack" name="kind" value="thriftly">Redeem the refresh token as Thriftly</button>
<button class="attack" name="kind" value="no-client-auth">Redeem the refresh token without client authentication</button>
<button class="attack" name="kind" value="widen">Refresh asking for more scope</button>
<button class="attack" name="kind" value="other-key">Use the access token with another app's DPoP key</button></form>
{{range .Attempts}}<p>{{if .Refused}}<span class="pill ok">refused</span>{{else}}<span class="pill bad">allowed</span>{{end}} {{.Title}}</p><pre>{{.Result}}</pre>{{end}}</div>
{{else}}<div class="card"><p>See all your accounts in one place. Link your Alder Bank accounts once; Pocketwise keeps them up to date for 90 days.</p>
<form method="post" action="/link"><button>Link Alder Bank accounts</button></form></div>{{end}}
<h2>Sync log</h2>
<div class="card"><table><tr><th>When (demo clock)</th><th>What</th><th>Result</th></tr>{{range .Log}}<tr><td class="muted">{{.When}}</td><td>{{.What}}</td><td>{{if .OK}}<span class="pill ok">ok</span>{{else}}<span class="pill bad">failed</span>{{end}} {{.Result}}</td></tr>{{else}}<tr><td colspan="3" class="muted">Nothing yet.</td></tr>{{end}}</table></div>
<h2>Protocol trace</h2>
<div class="card">{{range .Trace}}<details class="step"><summary>{{.Title}}</summary><pre>{{.Detail}}</pre></details>{{else}}<p class="muted">Nothing yet.</p>{{end}}</div>
{{template "bottom" .}}`,

	"consent": `{{template "top" .}}
<form method="post" action="/authorize">
<p><strong>{{.ClientName}}</strong> asks to read your accounts — {{.Actions}} — until <strong>{{.Until}}</strong>, without asking you again.</p>
<div class="card"><h2>Which accounts?</h2>
{{range .Accounts}}<label class="row"><input type="checkbox" name="account" value="{{.IBAN}}" checked> {{.Name}} <span class="muted">{{.IBAN}}</span></label>{{end}}
<p class="muted">You can withdraw access at any time from Connected apps.</p></div>
<div class="card"><h2>Sign in</h2>
{{if .Problem}}<p class="error">{{.Problem}}</p>{{end}}
<p><label>Username <input type="text" name="username" value="sam" autocomplete="off"></label></p>
<p><label>PIN <input type="text" name="pin" value="" autocomplete="off" placeholder="2468"></label></p>
<p class="actions"><button name="decision" value="approve">Share accounts</button> <button class="secondary" name="decision" value="deny">Cancel</button></p></div>
</form>
{{template "bottom" .}}`,

	"connected-apps": `{{template "top" .}}
<p class="muted">Signed in as Sam Rivera. These apps can read your accounts without asking you again.</p>
{{range .Connections}}<div class="card"><p><strong>{{.App}}</strong> {{if .Revoked}}<span class="pill bad">revoked</span>{{else if .Expired}}<span class="pill bad">expired</span>{{else}}<span class="pill ok">active</span>{{end}}</p>
<p class="muted">Approved {{.ApprovedAt}}, until {{.Until}} · grant ID <code>{{.GrantID}}</code></p>
<p>{{range .Accounts}}{{.}}<br>{{end}}</p>
{{if not (or .Revoked .Expired)}}<form method="post" action="/connected-apps"><input type="hidden" name="grant_id" value="{{.GrantID}}"><button class="attack">Revoke access</button></form>{{end}}</div>
{{else}}<div class="card"><p class="muted">No apps connected yet.</p></div>{{end}}
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
