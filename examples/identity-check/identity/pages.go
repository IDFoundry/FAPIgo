package identity

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
	fernwayHost: "#047857", brightlineHost: "#b45309", bankHost: "#0f766e", consoleHost: "#334155",
}

func (w *World) page(title, host string) Page {
	return Page{Title: title, Color: hostColors[host], Console: w.URL(consoleHost, "/")}
}

type consentPage struct {
	Page
	ClientName, Problem string
	Claims              []claimView
	StrongRequested     bool
	MaxAge, Remembered  string
}

type rpHomePage struct {
	Page
	Purpose  string
	Requests []string
}

type rpCheckPage struct {
	Page
	Check     *check
	Trace     []traceStep
	AttackLab bool
}

type consolePage struct {
	Page
	Fernway, Brightline string
	Tour                []tourStep
	Log                 []demokit.FetchEntry
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
<p class="muted">Fernway, a fintech, opens a savings account for an Alder Bank customer and has to verify who they are. Instead of a photo-ID upload, the customer signs in at Alder Bank, acting as an OpenID Provider. Fernway asks for exactly the identity claims it needs and for a strong, recent sign-in; the customer sees each claim and can withhold any of them; the ID token and UserInfo response come back signed by the bank and encrypted to Fernway. Brightline Rentals, a letting agent, asks for less. The attack lab tries to get around each protection. Everything runs in this one process, each party at its own host. Sign in at the bank as <strong>sam</strong>, PIN <strong>2468</strong>.</p>
<p class="actions"><a class="button" href="{{.Fernway}}">Open Fernway</a> <a class="button secondary" href="{{.Brightline}}">Open Brightline Rentals</a></p>
<h2>Start here</h2>
<ol class="tour">{{range .Tour}}<li class="card"><strong>{{.Title}}</strong><p>{{.Do}}</p><p class="muted">{{.Notice}}</p></li>{{end}}</ol>
<h2>Traffic between the parties</h2>
<div class="card"><p class="muted">Every request one party made to another, newest first. <a href="/">Refresh</a></p>
<table><tr><th>When</th><th>From</th><th>Request</th><th>Result</th></tr>
{{range .Log}}<tr><td class="muted">{{.Time.Format "15:04:05"}}</td><td>{{.From}}</td><td><code>{{.Method}} {{.URL}}</code></td><td>{{if .Err}}<span class="error">{{.Err}}</span>{{else}}{{.Status}}{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted">Nothing yet — open Fernway.</td></tr>{{end}}
</table></div>
{{template "bottom" .}}`,

	"rp-home": `{{template "top" .}}
<div class="card"><p>{{.Purpose}}</p>
<p class="muted">What we ask Alder Bank for:</p><ul>{{range .Requests}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="/start"><input type="hidden" name="scenario" value="normal"><button>Verify with Alder Bank</button></form></div>
{{template "bottom" .}}`,

	"rp-check": `{{template "top" .}}
{{with .Check}}
{{if eq .Status "verified"}}<div class="card"><p><span class="pill ok">verified</span> Alder Bank confirmed who you are.</p>
<table><tr><th>Claim</th><th>Value</th><th>From</th></tr>{{range .Claims}}<tr><td>{{.Label}}</td><td>{{.Value}}</td><td class="muted">{{.Source}}</td></tr>{{end}}</table>
<p class="muted">Signed in at {{.AuthTime}} · acr {{.ACR}}</p></div>
{{if $.AttackLab}}<div class="card" id="attempts"><h2>Attack lab</h2>
<form method="post" action="/attack" class="actions"><input type="hidden" name="id" value="{{.ID}}">
<button class="attack" name="kind" value="withheld">Ask UserInfo again for withheld claims</button>
<button class="attack" name="kind" value="eavesdrop">Read the claims off the wire</button>
<button class="attack" name="kind" value="swap-alex">Swap in Alex's ID token</button>
<button class="attack" name="kind" value="swap-brightline">Swap in Brightline's ID token</button>
<button class="attack" name="kind" value="other-userinfo">Swap in Alex's UserInfo response</button>
<button class="attack" name="kind" value="tamper-userinfo">Tamper with the UserInfo response</button>
<button class="attack" name="kind" value="stolen">Use the access token from another device</button></form>
{{range .Attempts}}<p>{{if .Refused}}<span class="pill ok">refused</span>{{else}}<span class="pill bad">allowed</span>{{end}} {{.Title}}</p><pre>{{.Result}}</pre>{{end}}
</div>{{end}}{{end}}
{{if eq .Status "redirected"}}<div class="card"><p>Waiting for Alder Bank.</p></div>{{end}}
{{if eq .Status "refused"}}<div class="card"><span class="pill bad">not verified</span><p class="error">{{.Problem}}</p></div>{{end}}
{{end}}
<h2>Protocol trace</h2>
<div class="card">{{range .Trace}}<details class="step"><summary>{{.Title}}</summary><pre>{{.Detail}}</pre></details>{{else}}<p class="muted">Nothing yet.</p>{{end}}</div>
<p><a class="button secondary" href="/">Start again</a></p>
{{template "bottom" .}}`,

	"consent": `{{template "top" .}}
<form method="post" action="/authorize">
<p><strong>{{.ClientName}}</strong> asks Alder Bank to confirm who you are.</p>
<div class="card"><h2>What it asks for</h2>
<p class="muted">Untick anything you'd rather not share. Alder Bank sends only what you leave ticked, from its own records.</p>
{{range .Claims}}<label class="row"><input type="checkbox" name="claim" value="{{.Name}}" checked> {{.Label}} <span class="muted">({{.Where}})</span></label>{{end}}</div>
<div class="card"><h2>Sign in</h2>
{{if .StrongRequested}}<p class="muted">{{.ClientName}} asks for a sign-in approved in the Alder Bank app{{if .MaxAge}}, made within the last {{.MaxAge}}{{end}}.</p>{{end}}
{{if .Problem}}<p class="error">{{.Problem}}</p>{{end}}
<p><label>Username <input type="text" name="username" value="sam" autocomplete="off"></label></p>
<p><label>PIN <input type="text" name="pin" value="" autocomplete="off" placeholder="2468"></label></p>
<label class="row"><input type="radio" name="method" value="app" checked> PIN, then approve in the Alder Bank app</label>
<label class="row"><input type="radio" name="method" value="pin"> PIN only</label>
<label class="row"><input type="radio" name="method" value="remembered"> Use my earlier sign-in (with the app, at {{.Remembered}}) — no PIN needed</label>
<p class="actions"><button name="decision" value="approve">Share and continue</button> <button class="secondary" name="decision" value="deny">Cancel</button></p></div>
</form>
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
