package union

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/federation"
)

// console is the Union operator's view: every entity, the scene
// switches, a Trust Chain inspector and the log of what the entities
// fetch from one another.
type console struct {
	w *World
	// resolvers by trust anchor: the Union, or one country's authority.
	resolvers map[string]*federation.Resolver
}

func (w *World) newConsole() (*console, error) {
	c := &console{w: w, resolvers: map[string]*federation.Resolver{}}
	r, err := w.resolverFor(consoleHost, w.union)
	if err != nil {
		return nil, err
	}
	c.resolvers["union"] = r
	for key, ta := range w.authorities {
		if c.resolvers[key], err = w.resolverFor(consoleHost, ta); err != nil {
			return nil, err
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", c.home)
	mux.HandleFunc("POST /scene", c.scene)
	mux.HandleFunc("POST /scene/reset", c.resetScenes)
	mux.HandleFunc("GET /entity", c.entityPage)
	mux.HandleFunc("GET /resolve", c.resolve)
	// Scene switches accept POSTs from the demo's own pages (every page
	// carries a reset button) but not from any other site.
	protect := http.NewCrossOriginProtection()
	for _, host := range Hosts() {
		if err := protect.AddTrustedOrigin(w.URL(host, "")); err != nil {
			return nil, err
		}
	}
	w.router[consoleHost] = protect.Handler(mux)
	return c, nil
}

// entityRow is one entity in the console's list.
type entityRow struct {
	ID, Host, Name, Role, Country, Color string
	Page                                 string // its own page, for services
}

func (c *console) rows() []entityRow {
	var rows []entityRow
	for _, e := range c.w.sortedEntities() {
		country := countryByKey(e.country)
		row := entityRow{ID: e.id, Host: e.host, Name: e.name, Role: e.role, Country: country.name, Color: country.color}
		if e.role == "service" {
			row.Page = e.id + "/"
		}
		rows = append(rows, row)
	}
	return rows
}

// sceneRow is one console switch.
type sceneRow struct {
	Key, Title, Description string
	On                      bool
}

func (c *console) sceneRows() []sceneRow {
	var rows []sceneRow
	for _, s := range c.w.sceneList() {
		rows = append(rows, sceneRow{Key: s.key, Title: s.title, Description: s.description, On: s.flag.Load()})
	}
	return rows
}

func (c *console) home(w http.ResponseWriter, _ *http.Request) {
	c.w.render(w, "console", consolePage{
		Page: c.w.page("Meridian Union console", country{}), Entities: c.rows(), Tour: c.tour(),
		Log: c.w.net.Log().Recent(40),
	})
}

// scene turns one scene on or off.
func (c *console) scene(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	back := "/"
	for _, s := range c.w.sceneList() {
		if s.key == r.PostForm.Get("scene") {
			s.flag.Store(r.PostForm.Get("on") == "true")
			back = "/#" + s.key // back to the tour step
		}
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// resetScenes turns every scene off.
func (c *console) resetScenes(w http.ResponseWriter, r *http.Request) {
	for _, s := range c.w.sceneList() {
		s.flag.Store(false)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// statementView is one decoded Entity Statement.
type statementView struct {
	Title, JSON, Error string
}

func (c *console) entityPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var e *entity
	for _, candidate := range c.w.entities {
		if candidate.id == id {
			e = candidate
		}
	}
	if e == nil {
		c.w.renderError(w, http.StatusNotFound, "Unknown entity", id)
		return
	}
	views := []statementView{decodeStatement("Entity Configuration", func() (string, error) { return e.EntityConfiguration(r.Context()) })}
	if e.subordinates != nil {
		for sub := range e.subordinates() {
			views = append(views, decodeStatement("Subordinate Statement about "+c.w.displayName(sub), func() (string, error) {
				token, _, err := e.SubordinateStatement(sub)
				return token, err
			}))
		}
	}
	country := countryByKey(e.country)
	c.w.render(w, "entity", entityPage{Page: c.w.page(e.name, country), Entity: entityRow{ID: e.id, Name: e.name, Role: e.role, Country: country.name}, Statements: views})
}

// decodeStatement shows a signed statement's payload. Display only: the
// signature isn't checked here — resolution does that.
func decodeStatement(title string, sign func() (string, error)) statementView {
	token, err := sign()
	if err != nil {
		return statementView{Title: title, Error: err.Error()}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return statementView{Title: title, Error: "not a compact JWS"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return statementView{Title: title, Error: err.Error()}
	}
	return statementView{Title: title, JSON: prettyJSON(payload)}
}

func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// resolveView is the Trust Chain inspector's result.
type resolveView struct {
	Subject, SubjectName, Via, ViaName string
	Chain                              []entityRow
	ExpiresAt                          time.Time
	Declared, Resolved                 []metadataView
	Marks                              []markView
	Error                              string
}

type metadataView struct {
	Type, JSON string
}

type markView struct {
	Type, Issuer, Status string
	OK                   bool
}

func (c *console) resolve(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	via := r.URL.Query().Get("via")
	if via == "" {
		via = "union"
	}
	resolver, ok := c.resolvers[via]
	if !ok {
		c.w.renderError(w, http.StatusBadRequest, "Unknown trust anchor", via)
		return
	}
	view := resolveView{Subject: subject, SubjectName: c.w.displayName(subject), Via: via, ViaName: c.viaName(via)}
	view.Declared = c.declaredMetadata(r.Context(), subject)

	if resolved, err := resolver.Resolve(r.Context(), subject); err != nil {
		view.Error = err.Error()
	} else {
		c.describeResolved(r.Context(), resolver, subject, resolved, &view)
	}
	country := country{}
	if e := c.w.entityByID(subject); e != nil {
		country = countryByKey(e.country)
	}
	c.w.render(w, "resolve", resolvePage{Page: c.w.page("Trust Chain of "+view.SubjectName, country), View: view, Entities: c.rows(), Anchors: c.anchorOptions()})
}

// describeResolved fills view with resolved's Trust Chain, resolved
// metadata and Trust Marks, each mark verified against the Union's
// accreditation.
func (c *console) describeResolved(ctx context.Context, resolver *federation.Resolver, subject string, resolved federation.ResolvedEntity, view *resolveView) {
	view.ExpiresAt = resolved.ExpiresAt
	for _, id := range resolved.Chain {
		row := entityRow{ID: id, Name: c.w.displayName(id)}
		if e := c.w.entityByID(id); e != nil {
			country := countryByKey(e.country)
			row.Role, row.Country, row.Color = e.role, country.name, country.color
		}
		view.Chain = append(view.Chain, row)
	}
	for _, t := range sortedKeys(resolved.Metadata) {
		view.Resolved = append(view.Resolved, metadataView{Type: t, JSON: prettyJSON(resolved.Metadata[t])})
	}
	for _, mark := range resolved.TrustMarks {
		mv := markView{Type: mark.TrustMarkType}
		if claims, err := resolver.VerifyTrustMark(ctx, subject, mark, federation.RequireFederationAccreditation); err != nil {
			mv.Status = err.Error()
		} else {
			mv.OK, mv.Issuer, mv.Status = true, c.w.displayName(claims.Issuer), "accredited by the Union"
		}
		view.Marks = append(view.Marks, mv)
	}
}

// declaredMetadata is the subject's own metadata as it declares it,
// before any superior's policy — for comparison with the resolved form.
func (c *console) declaredMetadata(ctx context.Context, subject string) []metadataView {
	e := c.w.entityByID(subject)
	if e == nil {
		return nil
	}
	token, err := e.EntityConfiguration(ctx)
	if err != nil {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		Metadata map[string]json.RawMessage `json:"metadata"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	var out []metadataView
	for _, t := range sortedKeys(claims.Metadata) {
		out = append(out, metadataView{Type: t, JSON: prettyJSON(claims.Metadata[t])})
	}
	return out
}

type anchorOption struct{ Key, Name string }

func (c *console) anchorOptions() []anchorOption {
	opts := []anchorOption{{Key: "union", Name: "Meridian Union"}}
	for _, ct := range countries {
		opts = append(opts, anchorOption{Key: ct.key, Name: ct.name + " Federation Authority"})
	}
	return opts
}

func (c *console) viaName(via string) string {
	for _, o := range c.anchorOptions() {
		if o.Key == via {
			return o.Name
		}
	}
	return via
}

func (w *World) entityByID(id string) *entity {
	for _, e := range w.entities {
		if e.id == id {
			return e
		}
	}
	return nil
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
