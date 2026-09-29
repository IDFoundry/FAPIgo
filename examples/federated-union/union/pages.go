package union

import (
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/idfoundry/fapigo/examples/federated-union/internal/demonet"
)

// Page is what every page's layout needs.
type Page struct {
	Title, Country, Color, Console string
	// ActiveScenes are the titles of the console scenes that are on, so
	// every page can say its behaviour is altered.
	ActiveScenes []string
}

func (w *World) page(title string, c country) Page {
	color := c.color
	if color == "" {
		color = "#4f46e5"
	}
	return Page{Title: title, Country: c.name, Color: color, Console: w.URL(consoleHost, "/"), ActiveScenes: w.activeScenes()}
}

type consolePage struct {
	Page
	Entities []entityRow
	Tour     []tourStep
	Log      []demonet.FetchEntry
}

type entityPage struct {
	Page
	Entity     entityRow
	Statements []statementView
}

type resolvePage struct {
	Page
	View     resolveView
	Entities []entityRow
	Anchors  []anchorOption
}

type servicePage struct {
	Page
	Providers []providerStatus
	Requested []string
}

type consentPage struct {
	Page
	Provider, Client, ClientName string
	Scope                        []string
	Citizens                     []citizen
	Claims                       []claimRow
}

// Citizen fields for the consent template, which can't reach
// unexported fields.
func (c citizen) Sub() string  { return c.sub }
func (c citizen) Name() string { return c.given + " " + c.family }

type welcomePage struct {
	Page
	Provider, ProviderCountry, Subject, Issuer string
	Claims                                     []sharedClaim
	CrossBorder                                bool
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
header { background: var(--accent); color: #fff; padding: 14px 24px; display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
header h1 { margin: 0; font-size: 19px; font-weight: 600; }
header a { color: #fff; opacity: .85; font-size: 13px; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }
h2 { font-size: 16px; margin: 28px 0 10px; }
.card { background: #fff; border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; margin-bottom: 14px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; }
.muted { color: var(--muted); font-size: 13px; }
.pill { display: inline-block; border-radius: 999px; padding: 1px 9px; font-size: 12px; font-weight: 600; }
.ok { background: #d1fae5; color: var(--ok); } .bad { background: #fee2e2; color: var(--bad); } .off { background: #f3f4f6; color: var(--muted); }
.dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
pre { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; max-height: 420px; }
button, .button { background: var(--accent); color: #fff; border: 0; border-radius: 7px; padding: 8px 14px; font: inherit; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }
button.secondary { background: #fff; color: var(--ink); border: 1px solid var(--line); }
button:disabled { opacity: .45; cursor: not-allowed; }
.chain { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.chain .node { border: 1px solid var(--line); border-radius: 8px; padding: 6px 10px; background: #fff; font-size: 13px; }
.chain .arrow { color: var(--muted); }
.error { color: var(--bad); font-size: 13px; word-break: break-word; }
label.row { display: flex; gap: 8px; align-items: center; padding: 4px 0; }
code { font-size: 12px; word-break: break-all; }
.scenes-on { background: #fef3c7; color: #92400e; padding: 8px 24px; font-size: 13px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.scenes-on form { margin: 0; } .scenes-on button { padding: 3px 10px; font-size: 12px; }
ol.tour { list-style: none; padding: 0; margin: 0; counter-reset: step; }
ol.tour > li { counter-increment: step; position: relative; padding-left: 44px; }
ol.tour > li::before { content: counter(step); position: absolute; left: 14px; top: 16px; width: 22px; height: 22px; border-radius: 50%; background: var(--accent); color: #fff; font-size: 12px; font-weight: 700; text-align: center; line-height: 22px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 8px; }
.actions form { margin: 0; }
</style></head><body>
<header><h1>{{.Title}}</h1><span>{{if .Country}}{{.Country}} · {{end}}<a href="{{.Console}}">Meridian Union console</a></span></header>
{{if .ActiveScenes}}<div class="scenes-on"><span><strong>Scene on:</strong> {{range $i, $s := .ActiveScenes}}{{if $i}}; {{end}}{{$s}}{{end}}. Sign-ins behave differently until it's off.</span>
<form method="post" action="{{.Console}}scene/reset"><button class="secondary">Turn every scene off</button></form></div>{{end}}
<main>{{end}}
{{define "bottom"}}</main></body></html>{{end}}`

var pageTemplates = map[string]string{
	"console": `{{template "top" .}}
<p class="muted">Three countries — Northland, Southport and Eastmark — run their own identity federations and have joined the Meridian Union, so a service in one country can accept a citizen of another without either registering with the other. Everything below runs in this one process, each entity at its own host.</p>

<h2>Start here</h2>
<ol class="tour">{{range .Tour}}<li class="card"{{with .Scene}} id="{{.Key}}"{{end}}>
<strong>{{.Title}}</strong>{{with .Scene}} {{if .On}}<span class="pill bad">scene on</span>{{else}}<span class="pill off">scene off</span>{{end}}{{end}}
<p>{{.Do}}</p>
<p class="muted">{{.Notice}}</p>
<div class="actions">{{with .Scene}}<form method="post" action="/scene"><input type="hidden" name="scene" value="{{.Key}}">{{if .On}}<input type="hidden" name="on" value="false"><button class="secondary">Turn scene off</button>{{else}}<input type="hidden" name="on" value="true"><button>Turn scene on</button>{{end}}</form>{{end}}
{{range .Links}}<a class="button" href="{{.Href}}">{{.Text}}</a>{{end}}</div>
{{with .Scene}}<p class="muted"><em>{{.Description}}</em></p>{{end}}
</li>{{end}}</ol>

<h2>Members</h2>
<div class="card"><table><tr><th>Entity</th><th>Role</th><th>Country</th><th></th></tr>
{{range .Entities}}<tr><td><span class="dot" style="background:{{.Color}}"></span><strong>{{.Name}}</strong><br><code>{{.ID}}</code></td><td>{{.Role}}</td><td>{{.Country}}</td>
<td><a href="/entity?id={{.ID}}">statements</a> · <a href="/resolve?subject={{.ID}}&via=union">trust chain</a>{{if .Page}} · <a href="{{.Page}}">open</a>{{end}}</td></tr>{{end}}
</table></div>

<h2>Recent federation traffic</h2>
<div class="card"><p class="muted">Every request one entity made to another: Entity Configurations, Subordinate Statements, keys. Newest first.</p>
<table><tr><th>When</th><th>From</th><th>Request</th><th>Result</th></tr>
{{range .Log}}<tr><td class="muted">{{.Time.Format "15:04:05"}}</td><td>{{.From}}</td><td><code>{{.Method}} {{.URL}}</code></td><td>{{if .Err}}<span class="error">{{.Err}}</span>{{else}}{{.Status}}{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted">Nothing yet — open a service.</td></tr>{{end}}
</table></div>
{{template "bottom" .}}`,

	"entity": `{{template "top" .}}
<p><strong>{{.Entity.Name}}</strong> — {{.Entity.Role}}{{if .Entity.Country}}, {{.Entity.Country}}{{end}}<br><code>{{.Entity.ID}}</code></p>
<p class="muted">Payloads decoded for reading; their signatures are checked when a Trust Chain is resolved.</p>
{{range .Statements}}<h2>{{.Title}}</h2>{{if .Error}}<p class="error">{{.Error}}</p>{{else}}<pre>{{.JSON}}</pre>{{end}}{{end}}
{{template "bottom" .}}`,

	"resolve": `{{template "top" .}}
<form method="get" action="/resolve" class="card">
<label>Entity <select name="subject">{{range .Entities}}<option value="{{.ID}}" {{if eq .ID $.View.Subject}}selected{{end}}>{{.Name}}</option>{{end}}</select></label>
<label>trusting <select name="via">{{range .Anchors}}<option value="{{.Key}}" {{if eq .Key $.View.Via}}selected{{end}}>{{.Name}}</option>{{end}}</select></label>
<button>Resolve</button></form>
{{with .View}}
{{if .Error}}<div class="card"><span class="pill bad">not trusted</span><p class="error">{{.Error}}</p></div>{{else}}
<h2>Trust Chain, trusting {{.ViaName}}</h2>
<div class="card chain">{{range $i, $n := .Chain}}{{if $i}}<span class="arrow">→</span>{{end}}<span class="node"><span class="dot" style="background:{{$n.Color}}"></span>{{$n.Name}}<br><span class="muted">{{$n.Role}}</span></span>{{end}}</div>
<p class="muted">Valid until {{.ExpiresAt.Format "2006-01-02 15:04 MST"}} — the earliest expiry of any statement in the chain.</p>
{{if .Marks}}<h2>Trust Marks</h2><div class="card"><table><tr><th>Type</th><th>Result</th></tr>{{range .Marks}}<tr><td><code>{{.Type}}</code></td><td>{{if .OK}}<span class="pill ok">accredited</span> issued by {{.Issuer}}{{else}}<span class="pill bad">rejected</span> <span class="error">{{.Status}}</span>{{end}}</td></tr>{{end}}</table></div>{{end}}
{{end}}
<div class="grid">
<div><h2>Metadata as the entity declares it</h2>{{range .Declared}}<p class="muted">{{.Type}}</p><pre>{{.JSON}}</pre>{{end}}</div>
{{if not .Error}}<div><h2>Metadata after every superior's policy</h2>{{range .Resolved}}<p class="muted">{{.Type}}</p><pre>{{.JSON}}</pre>{{end}}</div>{{end}}
</div>
{{end}}
{{template "bottom" .}}`,

	"service": `{{template "top" .}}
<p>Sign in with your national identity. This service has never registered with any of these providers: it finds each one through the Meridian Union federation, and they recognise this service the same way.</p>
<p class="muted">Only providers accredited by the Union at a high level of assurance are accepted. This service will ask for: {{range $i, $c := .Requested}}{{if $i}}, {{end}}{{$c}}{{end}}.</p>
<div class="grid">{{range .Providers}}<div class="card">
<span class="dot" style="background:{{.Color}}"></span><strong>{{.Name}}</strong> <span class="muted">{{.Country}}</span>
<p>{{if .Reachable}}<span class="pill ok">trusted</span>{{else}}<span class="pill bad">not trusted</span>{{end}}
{{if .LoAHigh}}<span class="pill ok">high assurance</span>{{else if .Reachable}}<span class="pill bad">assurance not accredited</span>{{end}}</p>
{{if .Reachable}}<p class="muted">Chain: {{range $i, $n := .Chain}}{{if $i}} → {{end}}{{$n}}{{end}}</p>{{else}}<p class="error">{{.Problem}}</p>{{end}}
{{if and .Reachable (not .LoAHigh)}}<p class="error">{{.LoAProblem}}</p>{{end}}
<form method="get" action="/login"><input type="hidden" name="provider" value="{{.ID}}"><button {{if not (and .Reachable .LoAHigh)}}disabled{{end}}>Sign in with {{.Name}}</button></form>
</div>{{end}}</div>
{{template "bottom" .}}`,

	"consent": `{{template "top" .}}
<div class="card">
<p><strong>{{.ClientName}}</strong> wants you to sign in with {{.Provider}}.</p>
<p class="muted"><code>{{.Client}}</code> — registered automatically through its Trust Chain, with no onboarding beforehand.</p>
<form method="post" action="/authorize">
<h2>Who are you?</h2>
{{range $i, $c := .Citizens}}<label class="row"><input type="radio" name="citizen" value="{{$c.Sub}}" {{if eq $i 0}}checked{{end}}> {{$c.Name}} <span class="muted">({{$c.Sub}})</span></label>{{end}}
{{if .Claims}}<h2>What may {{.ClientName}} see?</h2>
<p class="muted">Untick anything you'd rather not share. Only what you leave ticked leaves {{.Provider}}.</p>
{{range .Claims}}<label class="row"><input type="checkbox" name="claim" value="{{.Name}}" checked> {{.Label}}</label>{{end}}{{end}}
<p><button name="decision" value="approve">Sign in</button> <button class="secondary" name="decision" value="deny">Cancel</button></p>
</form></div>
{{template "bottom" .}}`,

	"welcome": `{{template "top" .}}
<div class="card">
<p><span class="pill ok">signed in</span> {{if .CrossBorder}}<span class="pill ok">cross-border</span>{{end}}</p>
<p>Signed in with <strong>{{.Provider}}</strong> ({{.ProviderCountry}}) as <code>{{.Subject}}</code>.</p>
<table><tr><th>Asked for</th><th>Received</th></tr>
{{range .Claims}}<tr><td>{{.Label}}</td><td>{{if .Shared}}{{.Value}}{{else}}<span class="muted">not shared</span>{{end}}</td></tr>{{end}}</table>
<p class="muted">From an ID token issued by <code>{{.Issuer}}</code>, over PAR, a signed request object, PKCE and a DPoP-bound access token.</p>
<p><a class="button" href="/">Back</a></p></div>
{{template "bottom" .}}`,

	"error": `{{template "top" .}}
<div class="card"><h2>{{.Heading}}</h2><p class="error">{{.Detail}}</p><p><a href="javascript:history.back()">Back</a></p></div>
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
// real service or identity provider should log it instead.
func (w *World) renderError(rw http.ResponseWriter, status int, heading, detail string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	if err := templates["error"].ExecuteTemplate(rw, "error", errorPage{Page: w.page("Meridian Union", country{}), Heading: heading, Detail: strings.TrimSpace(detail)}); err != nil {
		log.Printf("render error page: %v", err)
	}
}
