package main

import "html/template"

// localErrorPage is rendered by writeLocalHTMLError/writeLocalHTMLErrorRaw
// for any browser-facing failure the authorize/decision endpoints hit.
type localErrorPage struct {
	Code        string
	Description string
}

var localErrorTemplate = template.Must(template.New("local-error").Parse(`<!doctype html>
<html>
<head><title>Authorization Error</title></head>
<body>
<h1>Authorization Error</h1>
<p><strong>{{.Code}}</strong></p>
<p>{{.Description}}</p>
</body>
</html>
`))

// consentPage is rendered by GET /authorize for an interaction requiring
// login/consent. Client ID, scope names and the login hint all come from
// the pushed authorization request — client-controlled, low-trust input
// — so this uses html/template rather than text/template for its
// automatic contextual escaping.
type consentPage struct {
	Handle    string
	ClientID  string
	Scopes    []string
	LoginHint string
	Subject   string
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html>
<head><title>Authorize {{.ClientID}}</title></head>
<body>
<h1>Authorize Access</h1>
<p>Client <strong>{{.ClientID}}</strong> is requesting access.</p>
{{if .LoginHint}}<p>The client suggested logging in as: {{.LoginHint}}</p>{{end}}
<form method="POST" action="/authorize/decision">
  <input type="hidden" name="handle" value="{{.Handle}}">
  <p><label>Subject: <input type="text" name="subject" value="{{.Subject}}"></label></p>
  <fieldset>
    <legend>Requested scopes</legend>
    {{range .Scopes}}
    <label><input type="checkbox" name="scope" value="{{.}}" checked> {{.}}</label><br>
    {{end}}
  </fieldset>
  <button type="submit" name="decision" value="approve">Approve</button>
  <button type="submit" name="decision" value="deny">Deny</button>
</form>
</body>
</html>
`))
