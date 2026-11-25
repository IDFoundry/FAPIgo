package federation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/storage"
)

// This file fuzzes Resolver.Resolve and AutomaticClientRepository over
// small federation graphs decoded from the fuzzer's bytes, and checks
// them against gfGraph's oracle: a deliberately small, top-down reading
// of OpenID Federation 1.0 that enumerates every Trust Chain the graph
// has and decides each one on its own, rather than searching the way
// Resolve does.
//
// A graph has six entities: the leaf (0), three Intermediates (1–3) and
// two Trust Anchor candidates (4, always configured, and 5, configured
// or not, so it can also act as an Intermediate). Each entity's
// authority_hints, each Subordinate Statement's presence, keys,
// constraints and openid_relying_party metadata_policy, and the leaf's
// openid_relying_party metadata are drawn from a fixed vocabulary, so
// the fuzzer explores structure rather than JSON syntax.
//
// The oracle models, for a chain leaf=e0, e1, …, ek=Trust Anchor:
//
//   - discovery: e(j+1) is among e(j)'s authority_hints, entities are
//     distinct, e1…e(k-1) are not configured Trust Anchors (Resolve ends
//     a chain at the first configured Trust Anchor it reaches) and k is
//     at most Limits.MaxPathLength;
//   - statements: every e(j+1) publishes a federation_fetch_endpoint and
//     a Subordinate Statement about e(j) naming e(j)'s own key, and the
//     Trust Anchor's configuration validates against its configured key;
//   - constraints (§6.2): max_path_length bounds the Intermediates
//     between the issuer and the leaf, naming_constraints (exact hosts
//     only) apply to every entity below the issuer, and
//     allowed_entity_types removes the leaf's other Entity Types before
//     any policy;
//   - metadata (§3.1.1, §6.1): the leaf's Immediate Superior's metadata
//     replaces the leaf's token_endpoint_auth_method, then the policies
//     are merged from the Trust Anchor down (one_of: intersection, empty
//     is an error; value: equal; subset_of: intersection; superset_of:
//     union; essential: or), combinations checked (value within one_of,
//     superset_of within subset_of) and applied in §6.1.4.2's order.
//
// It deliberately does not model a policy combination error once
// allowed_entity_types has removed the leaf's openid_relying_party
// metadata (whether that error still invalidates the chain is left to
// the implementation), nor a search the bounded budget may cut short
// (Limits.MaxPathLength × MaxAuthorityHints superiors): there, only
// Resolve's other properties are checked. Expiry, Trust Marks,
// metadata_policy_crit and non-standard operators are out of its scope.

const (
	gfEntities          = 6
	gfLeaf              = 0
	gfAnchorA           = 4
	gfAnchorB           = 5
	gfMaxAuthorityHints = 8
	gfRPType            = "openid_relying_party"
)

var (
	gfMethods = []string{"private_key_jwt", "tls_client_auth"}
	gfGrants  = []string{"authorization_code", "client_credentials", "refresh_token"}
	gfAlgs    = []string{"ES256", "PS256"}
	// gfMethodChoice and gfAlgChoice map two bits to a value, "" for none.
	gfMethodChoice = []string{"", "private_key_jwt", "tls_client_auth", ""}
	gfAlgChoice    = []string{"", "ES256", "PS256", ""}
)

// gfPolicy is one Subordinate Statement's openid_relying_party
// metadata_policy, or a chain's merged one. A nil slice is an absent
// operator; "" an absent value.
type gfPolicy struct {
	methodOneOf     []string
	methodValue     string
	methodEssential bool
	grantSubset     []string
	grantSuperset   []string
	grantEssential  bool
	algOneOf        []string
}

// gfEdge is the Subordinate Statement a superior issues about one
// subject.
type gfEdge struct {
	missing  bool // not served at all
	wrongKey bool // names a key the subject doesn't hold
	// maxPathLength is the max_path_length constraint, -1 for none.
	maxPathLength int
	naming        *intfed.NamingConstraints
	allowedTypes  []string // nil: no allowed_entity_types constraint
	policy        gfPolicy
	// override is the token_endpoint_auth_method the statement's own
	// metadata sets for the leaf, "" for none. Only statements about the
	// leaf carry one.
	override string
}

// gfRP is the leaf's openid_relying_party metadata parameters the
// vocabulary covers; nil slices and "" are absent parameters.
type gfRP struct {
	method  string
	methods []string // token_endpoint_auth_methods_supported
	grants  []string
	alg     string
	algs    []string // token_endpoint_auth_signing_alg_values_supported
}

type gfGraph struct {
	maxPathLength  int
	anchors        [gfEntities]bool
	wrongAnchorKey [gfEntities]bool
	noFetch        [gfEntities]bool
	hints          [gfEntities][]int
	edges          map[[2]int]gfEdge // keyed {superior, subject}
	leaf           gfRP
}

// gfBytes reads the fuzzer's input a byte at a time, zero once spent.
type gfBytes struct {
	b []byte
	i int
}

func (s *gfBytes) next() byte {
	if s.i >= len(s.b) {
		return 0
	}
	s.i++
	return s.b[s.i-1]
}

// decodeGFGraph decodes data: a flags byte, a fetch-endpoint byte, one
// authority_hints byte per entity, two bytes of leaf metadata, then
// five bytes per authority hint (see decodeGFEdge), in entity then hint
// order.
func decodeGFGraph(data []byte) gfGraph {
	src := &gfBytes{b: data}
	g := gfGraph{edges: map[[2]int]gfEdge{}}
	flags := src.next()
	g.maxPathLength = 1 + int(flags&7)%5
	g.anchors[gfAnchorA] = true
	g.anchors[gfAnchorB] = flags&0x08 != 0
	g.wrongAnchorKey[gfAnchorA] = flags&0x30 == 0x30
	g.wrongAnchorKey[gfAnchorB] = flags&0xc0 == 0xc0
	fetch := src.next()
	for e := range gfEntities {
		g.noFetch[e] = fetch&0x80 != 0 && fetch&(1<<e) != 0
	}
	for e := range gfEntities {
		g.hints[e] = decodeGFHints(e, src.next())
	}
	g.leaf = decodeGFLeaf(src.next(), src.next())
	for e := range gfEntities {
		for _, sup := range g.hints[e] {
			g.edges[[2]int{sup, e}] = decodeGFEdge(src, e == gfLeaf)
		}
	}
	return g
}

// decodeGFHints: bit i names entity i (never e itself); bit 6 reverses
// the order.
func decodeGFHints(e int, b byte) []int {
	var hints []int
	for i := range gfEntities {
		if i != e && b&(1<<i) != 0 {
			hints = append(hints, i)
		}
	}
	if b&0x40 != 0 {
		slices.Reverse(hints)
	}
	return hints
}

// gfPick is the members of vocab mask's bits select, never nil.
func gfPick(vocab []string, mask byte) []string {
	out := []string{}
	for i, v := range vocab {
		if mask&(1<<i) != 0 {
			out = append(out, v)
		}
	}
	return out
}

// gfPickIf is gfPick when present, nil otherwise.
func gfPickIf(present bool, vocab []string, mask byte) []string {
	if !present {
		return nil
	}
	return gfPick(vocab, mask)
}

func decodeGFLeaf(b0, b1 byte) gfRP {
	return gfRP{
		method:  []string{"", "private_key_jwt", "tls_client_auth", "client_secret_basic"}[b0&3],
		methods: gfPickIf(b0>>2&3 != 0, gfMethods, b0>>2&3),
		grants:  gfPickIf(b0&0x80 != 0, gfGrants, b0>>4&7),
		alg:     gfAlgChoice[b1&3],
		algs:    gfPickIf(b1>>2&3 != 0, gfAlgs, b1>>2&3),
	}
}

// decodeGFEdge reads five bytes: kind and constraints, then the policy
// on token_endpoint_auth_method, on grant_types, on
// token_endpoint_auth_signing_alg (with the metadata override), and the
// entity a naming constraint names.
func decodeGFEdge(src *gfBytes, aboutLeaf bool) gfEdge {
	b0, b1, b2, b3, b4 := src.next(), src.next(), src.next(), src.next(), src.next()
	e := gfEdge{missing: b0&3 == 2, wrongKey: b0&3 == 3, maxPathLength: int(b0>>2&3) - 1}
	host := gfHost(int(b4) % gfEntities)
	switch b0 >> 4 & 3 {
	case 1:
		e.naming = &intfed.NamingConstraints{Permitted: []string{host}}
	case 2:
		e.naming = &intfed.NamingConstraints{Excluded: []string{host}}
	case 3:
		e.naming = &intfed.NamingConstraints{Permitted: []string{}}
	}
	e.allowedTypes = [][]string{nil, {gfRPType}, {"openid_provider"}, {}}[b0>>6]
	e.policy = gfPolicy{
		methodOneOf:     gfPickIf(b1&3 != 0, gfMethods, b1&3),
		methodValue:     gfMethodChoice[b1>>2&3],
		methodEssential: b1&0x10 != 0,
		grantSubset:     gfPickIf(b2&0x08 != 0, gfGrants, b2&7),
		grantSuperset:   gfPickIf(b2>>4&7 != 0, gfGrants, b2>>4&7),
		grantEssential:  b2&0x80 != 0,
		algOneOf:        gfPickIf(b3&3 != 0, gfAlgs, b3&3),
	}
	if aboutLeaf {
		e.override = gfMethodChoice[b3>>2&3]
	}
	return e
}

func gfHost(e int) string { return fmt.Sprintf("127.0.0.%d", e+1) }

func gfEntityID(e int) string { return "https://" + gfHost(e) }

// --- the oracle ---

// gfOutcome is the oracle's verdict on one chain.
type gfOutcome struct {
	valid      bool
	unmodelled bool
	why        string
	merged     gfPolicy
	rp         *gfRP // resolved openid_relying_party metadata; nil if removed
}

// chains is every chain the graph's authority_hints make discoverable
// (see the file comment), each starting at the leaf.
func (g gfGraph) chains() [][]int {
	var out [][]int
	var walk func(path []int)
	walk = func(path []int) {
		if len(path) > g.maxPathLength {
			return
		}
		for _, h := range g.hints[path[len(path)-1]] {
			if slices.Contains(path, h) {
				continue
			}
			next := append(slices.Clone(path), h)
			if g.anchors[h] {
				out = append(out, next)
			} else {
				walk(next)
			}
		}
	}
	walk([]int{gfLeaf})
	return out
}

// searchSize is how many superiors a search trying every discoverable
// path, without ever stopping early, would try: an upper bound on what
// Resolve tries, so a graph within its budget is decided in full.
func (g gfGraph) searchSize() int {
	var count func(path []int) int
	count = func(path []int) int {
		if len(path) > g.maxPathLength {
			return 0
		}
		n := 0
		for _, h := range g.hints[path[len(path)-1]] {
			if slices.Contains(path, h) {
				continue
			}
			n++
			if !g.anchors[h] {
				n += count(append(slices.Clone(path), h))
			}
		}
		return n
	}
	return count([]int{gfLeaf})
}

// discoverable reports whether chain has the shape chains produces.
func (g gfGraph) discoverable(chain []int) bool {
	k := len(chain) - 1
	if k < 1 || k > g.maxPathLength || chain[0] != gfLeaf || !g.anchors[chain[k]] {
		return false
	}
	for j := 1; j <= k; j++ {
		if !slices.Contains(g.hints[chain[j-1]], chain[j]) || slices.Contains(chain[:j], chain[j]) || j < k && g.anchors[chain[j]] {
			return false
		}
	}
	return true
}

func (g gfGraph) edge(chain []int, j int) gfEdge { return g.edges[[2]int{chain[j+1], chain[j]}] }

// evaluate decides chain, a discoverable one.
func (g gfGraph) evaluate(chain []int) gfOutcome {
	if why := g.statementFault(chain); why != "" {
		return gfOutcome{why: why}
	}
	if why := g.constraintFault(chain); why != "" {
		return gfOutcome{why: why}
	}
	merged, why := g.mergedPolicy(chain)
	if why != "" {
		return gfOutcome{why: why}
	}
	rp := g.declaredRP(chain)
	if why := merged.combinationFault(); why != "" {
		return gfOutcome{unmodelled: rp == nil, why: why, merged: merged}
	}
	if rp == nil {
		return gfOutcome{valid: true, merged: merged}
	}
	resolved, why := merged.apply(*rp)
	if why != "" {
		return gfOutcome{why: why, merged: merged}
	}
	return gfOutcome{valid: true, merged: merged, rp: &resolved}
}

func (g gfGraph) statementFault(chain []int) string {
	k := len(chain) - 1
	for j := range k {
		e := g.edge(chain, j)
		switch {
		case g.noFetch[chain[j+1]]:
			return fmt.Sprintf("entity %d has no fetch endpoint", chain[j+1])
		case e.missing:
			return fmt.Sprintf("no statement %d→%d", chain[j+1], chain[j])
		case e.wrongKey:
			return fmt.Sprintf("statement %d→%d names the wrong key", chain[j+1], chain[j])
		}
	}
	if g.wrongAnchorKey[chain[k]] {
		return fmt.Sprintf("trust anchor %d is configured with the wrong key", chain[k])
	}
	return ""
}

func (g gfGraph) constraintFault(chain []int) string {
	for j := range len(chain) - 1 {
		e := g.edge(chain, j)
		if e.maxPathLength >= 0 && j > e.maxPathLength {
			return fmt.Sprintf("statement %d→%d: %d intermediates exceed max_path_length %d", chain[j+1], chain[j], j, e.maxPathLength)
		}
		if e.naming == nil {
			continue
		}
		for _, below := range chain[:j+1] {
			if !gfNamePermitted(*e.naming, gfHost(below)) {
				return fmt.Sprintf("statement %d→%d: naming_constraints refuse entity %d", chain[j+1], chain[j], below)
			}
		}
	}
	return ""
}

func gfNamePermitted(nc intfed.NamingConstraints, host string) bool {
	if slices.Contains(nc.Excluded, host) {
		return false
	}
	return nc.Permitted == nil || slices.Contains(nc.Permitted, host)
}

// mergedPolicy merges chain's policies from the Trust Anchor's
// statement down (§6.1.4.1).
func (g gfGraph) mergedPolicy(chain []int) (gfPolicy, string) {
	var merged gfPolicy
	for j := len(chain) - 2; j >= 0; j-- {
		var why string
		if merged, why = merged.merge(g.edge(chain, j).policy); why != "" {
			return gfPolicy{}, fmt.Sprintf("statement %d→%d: %s", chain[j+1], chain[j], why)
		}
	}
	return merged, ""
}

// declaredRP is the leaf's openid_relying_party metadata after its
// Immediate Superior's metadata (§3.1.1) and the chain's
// allowed_entity_types (§6.2.3), nil if a constraint removes it.
func (g gfGraph) declaredRP(chain []int) *gfRP {
	for j := range len(chain) - 1 {
		if types := g.edge(chain, j).allowedTypes; types != nil && !slices.Contains(types, gfRPType) {
			return nil
		}
	}
	rp := g.leaf
	if o := g.edge(chain, 0).override; o != "" {
		rp.method = o
	}
	return &rp
}

func (p gfPolicy) merge(next gfPolicy) (gfPolicy, string) {
	out := gfPolicy{
		methodEssential: p.methodEssential || next.methodEssential,
		grantSubset:     gfIntersect(p.grantSubset, next.grantSubset),
		grantSuperset:   gfUnion(p.grantSuperset, next.grantSuperset),
		grantEssential:  p.grantEssential || next.grantEssential,
	}
	var ok bool
	if out.methodOneOf, ok = gfMergeOneOf(p.methodOneOf, next.methodOneOf); !ok {
		return gfPolicy{}, "token_endpoint_auth_method one_of values share nothing"
	}
	if out.algOneOf, ok = gfMergeOneOf(p.algOneOf, next.algOneOf); !ok {
		return gfPolicy{}, "token_endpoint_auth_signing_alg one_of values share nothing"
	}
	out.methodValue = cmpOr(p.methodValue, next.methodValue)
	if p.methodValue != "" && next.methodValue != "" && p.methodValue != next.methodValue {
		return gfPolicy{}, "token_endpoint_auth_method values differ"
	}
	return out, ""
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// gfMergeOneOf intersects two one_of operands; false when both are
// present and share nothing.
func gfMergeOneOf(a, b []string) ([]string, bool) {
	out := gfIntersect(a, b)
	return out, out == nil || len(out) > 0
}

// gfIntersect is a ∩ b, either nil (absent) leaving the other.
func gfIntersect(a, b []string) []string {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := []string{}
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// gfUnion is a ∪ b, nil only if both are.
func gfUnion(a, b []string) []string {
	if a == nil && b == nil {
		return nil
	}
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func gfSubset(sub, super []string) bool {
	for _, v := range sub {
		if !slices.Contains(super, v) {
			return false
		}
	}
	return true
}

func (p gfPolicy) combinationFault() string {
	if p.methodValue != "" && p.methodOneOf != nil && !slices.Contains(p.methodOneOf, p.methodValue) {
		return "token_endpoint_auth_method value outside one_of"
	}
	if p.grantSuperset != nil && p.grantSubset != nil && !gfSubset(p.grantSuperset, p.grantSubset) {
		return "grant_types superset_of outside subset_of"
	}
	return ""
}

// apply applies p to rp in §6.1.4.2's order: value, one_of, subset_of,
// superset_of, essential.
func (p gfPolicy) apply(rp gfRP) (gfRP, string) {
	if p.methodValue != "" {
		rp.method = p.methodValue
	}
	if p.methodOneOf != nil && rp.method != "" && !slices.Contains(p.methodOneOf, rp.method) {
		return gfRP{}, "token_endpoint_auth_method outside one_of"
	}
	if p.methodEssential && rp.method == "" {
		return gfRP{}, "essential token_endpoint_auth_method absent"
	}
	if p.algOneOf != nil && rp.alg != "" && !slices.Contains(p.algOneOf, rp.alg) {
		return gfRP{}, "token_endpoint_auth_signing_alg outside one_of"
	}
	if rp.grants != nil && p.grantSubset != nil {
		rp.grants = gfIntersect(rp.grants, p.grantSubset)
	}
	if rp.grants != nil && p.grantSuperset != nil && !gfSubset(p.grantSuperset, rp.grants) {
		return gfRP{}, "grant_types lacks a superset_of value"
	}
	if p.grantEssential && rp.grants == nil {
		return gfRP{}, "essential grant_types absent"
	}
	return rp, ""
}

// permitsMethod reports whether the merged policy p lets
// token_endpoint_auth_method be method.
func (p gfPolicy) permitsMethod(method string) bool {
	if p.methodValue != "" && method != p.methodValue {
		return false
	}
	return p.methodOneOf == nil || slices.Contains(p.methodOneOf, method)
}

// --- serving the graph ---

// gfKeys is every key a graph uses, generated once per fuzz target.
type gfKeys struct {
	keys     [gfEntities]*ecdsa.PrivateKey
	jwks     [gfEntities]json.RawMessage
	stranger json.RawMessage // a key no entity holds
	rpJWKS   json.RawMessage
	now      time.Time
}

func newGFKeys(tb testing.TB) *gfKeys {
	tb.Helper()
	k := &gfKeys{now: time.Now()}
	for e := range gfEntities {
		k.keys[e] = gfKey(tb)
		k.jwks[e] = gfJWKS(tb, gfKeyID(e), k.keys[e])
	}
	k.stranger = gfJWKS(tb, "stranger", gfKey(tb))
	k.rpJWKS = gfJWKS(tb, "rp-oidc", gfKey(tb))
	return k
}

func gfKeyID(e int) string { return fmt.Sprintf("e%d", e) }

func gfKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	return key
}

func gfJWKS(tb testing.TB, kid string, key *ecdsa.PrivateKey) json.RawMessage {
	tb.Helper()
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		tb.Fatalf("jose.NewJWK: %v", err)
	}
	raw, err := jwk.WithKeyID(kid).MarshalJSON()
	if err != nil {
		tb.Fatalf("marshal jwk: %v", err)
	}
	set, err := json.Marshal(map[string][]json.RawMessage{"keys": {raw}})
	if err != nil {
		tb.Fatalf("marshal jwk set: %v", err)
	}
	return set
}

// gfServer serves a graph's statements in memory, as an
// http.RoundTripper, counting every request.
type gfServer struct {
	configs      map[string]string            // entity id → Entity Configuration
	subordinates map[string]map[string]string // superior id → subject id → statement
	requests     atomic.Int64
}

func (s *gfServer) RoundTrip(r *http.Request) (*http.Response, error) {
	s.requests.Add(1)
	base := "https://" + r.URL.Host
	token, ok := "", false
	switch r.URL.Path {
	case "/.well-known/openid-federation":
		token, ok = s.configs[base]
	case "/fetch":
		token, ok = s.subordinates[base][r.URL.Query().Get("sub")]
	}
	// A response with no TLS state reads as plain http to fapihttp,
	// which refuses it for an https URL.
	res := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r, TLS: &tls.ConnectionState{HandshakeComplete: true}}
	if !ok {
		res.StatusCode, token = http.StatusNotFound, `{"error":"not_found"}`
		res.Header.Set("Content-Type", "application/json")
	} else {
		res.Header.Set("Content-Type", federation.EntityStatementContentType)
	}
	res.Body = io.NopCloser(strings.NewReader(token))
	return res, nil
}

// serve signs g's statements. Subordinate Statements are signed
// unchecked, so one may carry a policy combination a conformant issuer
// wouldn't.
func (k *gfKeys) serve(tb testing.TB, g gfGraph) *gfServer {
	tb.Helper()
	s := &gfServer{configs: map[string]string{}, subordinates: map[string]map[string]string{}}
	for e := range gfEntities {
		s.configs[gfEntityID(e)] = k.entityConfiguration(tb, g, e)
	}
	for key, edge := range g.edges {
		if edge.missing {
			continue
		}
		sup := gfEntityID(key[0])
		if s.subordinates[sup] == nil {
			s.subordinates[sup] = map[string]string{}
		}
		s.subordinates[sup][gfEntityID(key[1])] = k.subordinateStatement(tb, key[0], key[1], edge)
	}
	return s
}

func (k *gfKeys) entityConfiguration(tb testing.TB, g gfGraph, e int) string {
	tb.Helper()
	var hints []string
	for _, h := range g.hints[e] {
		hints = append(hints, gfEntityID(h))
	}
	metadata := map[string]json.RawMessage{}
	switch {
	case e == gfLeaf:
		metadata[gfRPType] = k.leafMetadata(tb, g.leaf)
	case !g.noFetch[e]:
		metadata["federation_entity"] = gfJSON(tb, map[string]string{"federation_fetch_endpoint": gfEntityID(e) + "/fetch"})
	}
	token, err := intfed.Create(intfed.CreateParams{
		Signer: k.keys[e], Algorithm: fapi.ES256, KeyID: gfKeyID(e),
		Issuer: gfEntityID(e), Subject: gfEntityID(e), Now: k.now, Lifetime: time.Hour,
		JWKS: k.jwks[e], AuthorityHints: hints, Metadata: metadata,
	})
	if err != nil {
		tb.Fatalf("entity configuration %d: %v", e, err)
	}
	return token
}

func (k *gfKeys) leafMetadata(tb testing.TB, rp gfRP) json.RawMessage {
	tb.Helper()
	md := map[string]any{
		"redirect_uris":              []string{"https://rp.example.org/cb"},
		"jwks":                       k.rpJWKS,
		"tls_client_auth_subject_dn": "CN=rp.example.org",
	}
	gfSetString(md, "token_endpoint_auth_method", rp.method)
	gfSetString(md, "token_endpoint_auth_signing_alg", rp.alg)
	gfSetList(md, "token_endpoint_auth_methods_supported", rp.methods)
	gfSetList(md, "grant_types", rp.grants)
	gfSetList(md, "token_endpoint_auth_signing_alg_values_supported", rp.algs)
	return gfJSON(tb, md)
}

func gfSetString(m map[string]any, name, v string) {
	if v != "" {
		m[name] = v
	}
}

func gfSetList(m map[string]any, name string, v []string) {
	if v != nil {
		m[name] = v
	}
}

func gfJSON(tb testing.TB, v any) json.RawMessage {
	tb.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}
	return raw
}

func (k *gfKeys) subordinateStatement(tb testing.TB, sup, sub int, e gfEdge) string {
	tb.Helper()
	p := intfed.CreateParams{
		Signer: k.keys[sup], Algorithm: fapi.ES256, KeyID: gfKeyID(sup),
		Issuer: gfEntityID(sup), Subject: gfEntityID(sub), Now: k.now, Lifetime: time.Hour,
		JWKS: k.jwks[sub], MetadataPolicy: e.policy.wire(tb),
	}
	if e.wrongKey {
		p.JWKS = k.stranger
	}
	if e.override != "" {
		p.Metadata = map[string]json.RawMessage{gfRPType: gfJSON(tb, map[string]string{"token_endpoint_auth_method": e.override})}
	}
	if e.maxPathLength >= 0 || e.naming != nil || e.allowedTypes != nil {
		p.Constraints = &intfed.Constraints{
			MaxPathLength: max(e.maxPathLength, 0), HasMaxPathLength: e.maxPathLength >= 0,
			NamingConstraints: e.naming, AllowedEntityTypes: e.allowedTypes,
		}
	}
	token, err := intfed.CreateUncheckedForTesting(p)
	if err != nil {
		tb.Fatalf("subordinate statement %d→%d: %v", sup, sub, err)
	}
	return token
}

// wire is p as a metadata_policy claim, nil when it has no operator.
func (p gfPolicy) wire(tb testing.TB) intfed.MetadataPolicy {
	tb.Helper()
	params := map[string]intfed.PolicyOperators{}
	add := func(param, op string, v any) {
		if params[param] == nil {
			params[param] = intfed.PolicyOperators{}
		}
		params[param][op] = gfJSON(tb, v)
	}
	if p.methodOneOf != nil {
		add("token_endpoint_auth_method", "one_of", p.methodOneOf)
	}
	if p.methodValue != "" {
		add("token_endpoint_auth_method", "value", p.methodValue)
	}
	if p.methodEssential {
		add("token_endpoint_auth_method", "essential", true)
	}
	if p.grantSubset != nil {
		add("grant_types", "subset_of", p.grantSubset)
	}
	if p.grantSuperset != nil {
		add("grant_types", "superset_of", p.grantSuperset)
	}
	if p.grantEssential {
		add("grant_types", "essential", true)
	}
	if p.algOneOf != nil {
		add("token_endpoint_auth_signing_alg", "one_of", p.algOneOf)
	}
	if len(params) == 0 {
		return nil
	}
	return intfed.MetadataPolicy{gfRPType: params}
}

// resolver builds a Resolver over s, trusting g's configured anchors,
// and the fetcher it uses.
func (k *gfKeys) resolver(tb testing.TB, g gfGraph, s *gfServer) (*federation.Resolver, *fapihttp.Client) {
	tb.Helper()
	fetcher, err := fapihttp.New(&http.Client{Transport: s}, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, AllowLoopbackHosts: true,
	})
	if err != nil {
		tb.Fatalf("fapihttp.New: %v", err)
	}
	var anchors []federation.TrustAnchor
	for e := range gfEntities {
		if !g.anchors[e] {
			continue
		}
		jwks := k.jwks[e]
		if g.wrongAnchorKey[e] {
			jwks = k.stranger
		}
		anchors = append(anchors, federation.TrustAnchor{EntityID: gfEntityID(e), JWKS: jwks})
	}
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: anchors,
		Limits: federation.Limits{
			MaxPathLength: g.maxPathLength, MaxAuthorityHints: gfMaxAuthorityHints,
			MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second,
		},
	}, federation.Dependencies{HTTP: fetcher, Clock: fixedClock{now: k.now}})
	if err != nil {
		tb.Fatalf("NewResolver: %v", err)
	}
	return r, fetcher
}

// --- checks ---

// gfChainIndices is chain's entities, or false if one isn't in the
// graph.
func gfChainIndices(chain []string) ([]int, bool) {
	out := make([]int, 0, len(chain))
	for _, id := range chain {
		i := -1
		for e := range gfEntities {
			if gfEntityID(e) == id {
				i = e
			}
		}
		if i < 0 {
			return nil, false
		}
		out = append(out, i)
	}
	return out, true
}

// checkFetchBound fails t if Resolve made more requests than
// Limits.MaxAuthorityHints documents: 2 × MaxPathLength ×
// MaxAuthorityHints + 1 per Resolve call.
func checkFetchBound(t *testing.T, g gfGraph, s *gfServer, calls int) {
	t.Helper()
	if n, bound := s.requests.Load(), int64(calls*(2*g.maxPathLength*gfMaxAuthorityHints+1)); n > bound {
		t.Fatalf("%d fetches for %d resolutions, more than the documented bound %d", n, calls, bound)
	}
}

// checkResolveAgainstOracle fails t unless Resolve's answer agrees with
// the oracle: a chain it returns is discoverable, valid and resolved to
// the oracle's metadata, and it refuses only a graph with no valid
// chain (when its search budget can't bind).
func checkResolveAgainstOracle(t *testing.T, g gfGraph, res federation.ResolvedEntity, err error) {
	t.Helper()
	if err != nil {
		checkRefusalAgreed(t, g, err)
		return
	}
	chain, ok := gfChainIndices(res.Chain)
	if !ok || !g.discoverable(chain) || res.EntityID != gfEntityID(gfLeaf) || res.TrustAnchor != res.Chain[len(res.Chain)-1] {
		t.Fatalf("Resolve returned chain %v (trust anchor %s), not one the graph's authority hints make", res.Chain, res.TrustAnchor)
	}
	o := g.evaluate(chain)
	if o.unmodelled {
		return
	}
	if !o.valid {
		t.Fatalf("Resolve accepted chain %v, which the oracle refuses: %s", chain, o.why)
	}
	checkResolvedRP(t, chain, o.rp, res.Metadata)
}

func checkRefusalAgreed(t *testing.T, g gfGraph, err error) {
	t.Helper()
	if g.searchSize() > g.maxPathLength*gfMaxAuthorityHints {
		return // the budget may legitimately cut the search short
	}
	for _, chain := range g.chains() {
		if o := g.evaluate(chain); o.valid && !o.unmodelled {
			t.Fatalf("Resolve refused, but the oracle accepts chain %v: %v", chain, err)
		}
	}
}

// gfResolvedRP is the vocabulary's parameters as Resolve returned them.
type gfResolvedRP struct {
	Method  string   `json:"token_endpoint_auth_method"`
	Methods []string `json:"token_endpoint_auth_methods_supported"`
	Grants  []string `json:"grant_types"`
	Alg     string   `json:"token_endpoint_auth_signing_alg"`
	Algs    []string `json:"token_endpoint_auth_signing_alg_values_supported"`
}

func checkResolvedRP(t *testing.T, chain []int, want *gfRP, metadata map[string]json.RawMessage) {
	t.Helper()
	raw, present := metadata[gfRPType]
	if want == nil || !present {
		if (want == nil) != !present {
			t.Fatalf("chain %v: openid_relying_party present = %v, oracle wants %v", chain, present, want != nil)
		}
		return
	}
	var got gfResolvedRP
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("chain %v: resolved openid_relying_party: %v", chain, err)
	}
	if got.Method != want.method || got.Alg != want.alg ||
		!gfSameSet(got.Methods, want.methods) || !gfSameSet(got.Grants, want.grants) || !gfSameSet(got.Algs, want.algs) {
		t.Fatalf("chain %v: resolved %s, oracle wants %+v", chain, raw, *want)
	}
}

// gfSameSet reports whether a and b are both absent, or both present
// with the same members.
func gfSameSet(a, b []string) bool {
	return (a == nil) == (b == nil) && gfSubset(a, b) && gfSubset(b, a)
}

// checkClientWithinPolicy fails t if client, registered from res, holds
// a value merged — the chain's merged policy — forbids: an
// authentication method outside token_endpoint_auth_method's
// value/one_of, an assertion algorithm outside
// token_endpoint_auth_signing_alg's one_of, or client_credentials
// outside grant_types' subset_of or its resolved value.
func checkClientWithinPolicy(t *testing.T, merged gfPolicy, client storage.RegisteredClient, res federation.ResolvedEntity) {
	t.Helper()
	methods := append(client.ClientAuthMethods(), client.ClientAuthMethod())
	for _, m := range methods {
		if !merged.permitsMethod(m.String()) {
			t.Fatalf("registered method %v, which the merged policy %+v forbids", m, merged)
		}
	}
	if slices.Contains(methods, storage.ClientAuthMethodPrivateKeyJWT) && merged.algOneOf != nil {
		for _, alg := range client.ClientAssertionAlgorithms() {
			if !slices.Contains(merged.algOneOf, alg.String()) {
				t.Fatalf("registered assertion algorithm %v outside one_of %v", alg, merged.algOneOf)
			}
		}
	}
	if !client.AllowsClientCredentialsGrant() {
		return
	}
	var rp gfResolvedRP
	_ = json.Unmarshal(res.Metadata[gfRPType], &rp)
	if !slices.Contains(rp.Grants, "client_credentials") || merged.grantSubset != nil && !slices.Contains(merged.grantSubset, "client_credentials") {
		t.Fatalf("client_credentials registered, though resolved grant_types %v / subset_of %v don't allow it", rp.Grants, merged.grantSubset)
	}
}

// --- fuzz targets ---

// gfSeeds are hand-built graphs, in decodeGFGraph's encoding.
func gfSeeds() [][]byte {
	return [][]byte{
		// leaf → 1 → A, no policy: trusted.
		{0x04, 0x00, 0x02, 0x10, 0, 0, 0, 0, 0xB1, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// The same, A's statement restricting the method to
		// private_key_jwt and grants to authorization_code and
		// client_credentials, essential.
		{0x04, 0x00, 0x02, 0x10, 0, 0, 0, 0, 0xB1, 0x01, 0, 0, 0, 0, 0, 0, 0x11, 0x8B, 0x01, 0},
		// leaf → {1, 2}; 1 → B (not configured, a dead end), 2 → A.
		{0x04, 0x00, 0x06, 0x20, 0x10, 0, 0, 0, 0xB1, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// leaf → 1 → 2 → A, A's statement about 2 with max_path_length 1.
		{0x04, 0x00, 0x02, 0x04, 0x10, 0, 0, 0, 0xB1, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0, 0, 0, 0},
		// leaf → 1 → A, A allowing only openid_provider.
		{0x04, 0x00, 0x02, 0x10, 0, 0, 0, 0, 0xB1, 0x01, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0},
		// Both methods as choices, A's one_of allowing tls_client_auth only.
		{0x04, 0x00, 0x02, 0x10, 0, 0, 0, 0, 0x0C, 0x0C, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x02, 0},
		// The same choices, A's one_of allowing private_key_jwt and PS256
		// only.
		{0x04, 0x00, 0x02, 0x10, 0, 0, 0, 0, 0x0C, 0x0C, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02, 0},
		// 1's statement about the leaf excluding the leaf's host.
		{0x04, 0x00, 0x02, 0x10, 0, 0, 0, 0, 0xB1, 0x01, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// A configured with the wrong key; B configured too, also reachable.
		{0x3C, 0x00, 0x02, 0x30, 0, 0, 0, 0, 0xB1, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// Conflicting values across the chain, and an override.
		{0x04, 0x00, 0x02, 0x10, 0, 0, 0, 0, 0xB1, 0x01, 0, 0x04, 0, 0x08, 0, 0, 0x08, 0, 0, 0},
	}
}

func gfResolve(t *testing.T, keys *gfKeys, data []byte) (gfGraph, *gfServer, *federation.Resolver, *fapihttp.Client) {
	t.Helper()
	g := decodeGFGraph(data)
	s := keys.serve(t, g)
	r, fetcher := keys.resolver(t, g, s)
	return g, s, r, fetcher
}

// FuzzResolveFederationGraph checks Resolver.Resolve over decoded
// federation graphs against the oracle described at the top of this
// file, and that it stays within its documented fetch bound.
func FuzzResolveFederationGraph(f *testing.F) {
	for _, seed := range gfSeeds() {
		f.Add(seed)
	}
	keys := newGFKeys(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		g, s, r, _ := gfResolve(t, keys, data)
		res, err := r.Resolve(context.Background(), gfEntityID(gfLeaf))
		checkFetchBound(t, g, s, 1)
		checkResolveAgainstOracle(t, g, res, err)
	})
}

// FuzzAutomaticRegistrationFederationGraph registers the leaf of each
// decoded graph through AutomaticClientRepository, whose Trust Chains
// carry policies on token_endpoint_auth_method,
// token_endpoint_auth_signing_alg and grant_types (so its choiceLimits
// are not empty), and checks that it registers only an entity Resolve
// trusts, and never with a value the chain's merged policy — the
// oracle's — forbids, however the leaf declares its choices.
func FuzzAutomaticRegistrationFederationGraph(f *testing.F) {
	for _, seed := range gfSeeds() {
		f.Add(seed)
	}
	keys := newGFKeys(f)
	cfg := federation.AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, MaxCacheAge: time.Hour, AllowsClientCredentialsGrant: true,
		ClientAssertionAlgorithms: []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256},
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		g, s, r, fetcher := gfResolve(t, keys, data)
		repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, r, fetcher, cfg, fixedClock{now: keys.now})
		if err != nil {
			t.Fatalf("NewAutomaticClientRepository: %v", err)
		}
		client, regErr := repo.ResolveClient(context.Background(), fapi.ClientID(gfEntityID(gfLeaf)))
		res, resErr := r.Resolve(context.Background(), gfEntityID(gfLeaf))
		checkFetchBound(t, g, s, 2)
		if regErr != nil {
			return
		}
		if resErr != nil {
			t.Fatalf("registered %s, which Resolve refuses: %v", client.ID(), resErr)
		}
		if !client.AutomaticFederationRegistration() {
			t.Fatal("registered client lacks the federation marker")
		}
		chain, _ := gfChainIndices(res.Chain)
		merged, why := g.mergedPolicy(chain)
		if why != "" {
			t.Fatalf("registered over chain %v, whose policies the oracle can't merge: %s", chain, why)
		}
		checkClientWithinPolicy(t, merged, client, res)
	})
}
