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
	mux.HandleFunc("GET /entity", c.entityPage)
	mux.HandleFunc("GET /resolve", c.resolve)
	w.router[consoleHost] = mux
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
	s := &c.w.scenes
	return []sceneRow{
		{Key: "suspend", Title: "Suspend Eastmark", On: s.SuspendEastmark.Load(),
			Description: "The Union stops vouching for Eastmark's authority. Cross-border sign-ins with EastID fail; Eastmark's own services, which also trust their national authority directly, keep working."},
		{Key: "forge", Title: "EastID forges its assurance mark", On: s.ForgeEastmarkMark.Load(),
			Description: "EastID publishes a level-of-assurance Trust Mark it signed itself. It verifies as a signature — EastID is a federation member — but the Union doesn't accredit EastID to issue it, so services refuse it."},
		{Key: "compromise", Title: "Eastmark's authority is compromised", On: s.CompromiseEastmark.Load(),
			Description: "Eastmark's authority vouches for an impostor at bank.northland.localhost. The Union's naming constraints confine Eastmark to *.eastmark.localhost, so the impostor fails to resolve through the Union."},
	}
}

func (c *console) home(w http.ResponseWriter, _ *http.Request) {
	var services []entityRow
	for _, rp := range c.w.services {
		country := rp.country
		services = append(services, entityRow{ID: rp.entity.id, Name: rp.entity.name, Country: country.name, Color: country.color, Page: rp.entity.id + "/"})
	}
	c.w.render(w, "console", consolePage{
		Page: c.w.page("Meridian Union console", country{}), Entities: c.rows(), Scenes: c.sceneRows(),
		Services: services, Log: c.w.net.Log().Recent(40), Impostor: c.w.impostor.id,
	})
}

func (c *console) scene(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	on := r.PostForm.Get("on") == "true"
	switch r.PostForm.Get("scene") {
	case "suspend":
		c.w.scenes.SuspendEastmark.Store(on)
	case "forge":
		c.w.scenes.ForgeEastmarkMark.Store(on)
	case "compromise":
		c.w.scenes.CompromiseEastmark.Store(on)
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

	resolved, err := resolver.Resolve(r.Context(), subject)
	if err != nil {
		view.Error = err.Error()
	} else {
		view.ExpiresAt = resolved.ExpiresAt
		for _, id := range resolved.Chain {
			e := c.w.entityByID(id)
			row := entityRow{ID: id, Name: c.w.displayName(id)}
			if e != nil {
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
			claims, err := resolver.VerifyTrustMark(r.Context(), subject, mark, federation.RequireFederationAccreditation)
			if err != nil {
				mv.Status = err.Error()
			} else {
				mv.OK, mv.Issuer, mv.Status = true, c.w.displayName(claims.Issuer), "accredited by the Union"
			}
			view.Marks = append(view.Marks, mv)
		}
	}
	country := country{}
	if e := c.w.entityByID(subject); e != nil {
		country = countryByKey(e.country)
	}
	c.w.render(w, "resolve", resolvePage{Page: c.w.page("Trust Chain of "+view.SubjectName, country), View: view, Entities: c.rows(), Anchors: c.anchorOptions()})
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
