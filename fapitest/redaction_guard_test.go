package fapitest_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unsafe"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/rendertest"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// This file is the reflection guard over the exported API: every
// exported struct type of the packages below is either in guardedTypes,
// whose renderings TestRedactionGuardRenderings checks, or in
// exemptTypes, with a reason. A new type fails
// TestRedactionGuardCoversEveryExportedType until it is classified.
//
// TestRedactionGuardRenderings fills each string a guarded type holds,
// exported or not, with a sentinel of its own (a fapi.Secret with
// NewSecret of one, a fapi.URL with one as its code, a json.RawMessage
// with one quoted): in the fields of this module's structs, down to
// maxFillDepth levels, where a field, a pointer, a slice's first element
// and a string-keyed map's one entry each count as one. It leaves an
// interface field nil, and a struct of another module or the standard
// library zero. It renders the value through the rendering matrix's
// sweep (rendertest.LeaksOf: the value, a pointer to it, an exported and
// an unexported field, under fmt's v, s, q, x, X, d, p and w verbs with
// no flag, "+" and "#", and the matrix's other printers, slog handlers
// and encoders) and records, for each sentinel that printed, the field
// path it sat at and the classes of rendering that printed it: log (a
// value's own methods: fmt's v, s, q, x and X, log/slog, the templates),
// fallback (fmt's reflection fallback) and encoding (encoding/json, xml
// and gob). The record must match testdata/redaction.golden, which go
// test -run TestRedactionGuard -update rewrites: a field or type that
// starts printing shows up in review as a change to it. A value held in
// a fapi.Secret must print in no class at all, except a handle's or a
// request_uri's wire value through its String.

var updateGolden = flag.Bool("update", false, "rewrite testdata/redaction.golden from the renderings")

const guardGolden = "testdata/redaction.golden"

// guardedPackages are the directories, from this one, whose exported
// types the guard covers.
var guardedPackages = []string{"..", "../client", "../client/sessioncookie", "../server", "../server/interactioncookie", "../resource", "../storage", "../storage/memstore", "../extension", "."}

// guardedTypes are the exported struct types whose renderings the guard
// checks.
var guardedTypes = map[string]reflect.Type{
	"fapi.Secret":                                           reflect.TypeFor[fapi.Secret](),
	"fapi.URL":                                              reflect.TypeFor[fapi.URL](),
	"client.AuthorizationCallback":                          reflect.TypeFor[client.AuthorizationCallback](),
	"client.AuthorizationSession":                           reflect.TypeFor[client.AuthorizationSession](),
	"client.BackchannelAuthenticationApproved":              reflect.TypeFor[client.BackchannelAuthenticationApproved](),
	"client.BackchannelAuthenticationDenied":                reflect.TypeFor[client.BackchannelAuthenticationDenied](),
	"client.BackchannelAuthenticationExpired":               reflect.TypeFor[client.BackchannelAuthenticationExpired](),
	"client.BackchannelAuthenticationPending":               reflect.TypeFor[client.BackchannelAuthenticationPending](),
	"client.BackchannelAuthenticationSession":               reflect.TypeFor[client.BackchannelAuthenticationSession](),
	"client.BackchannelNotification":                        reflect.TypeFor[client.BackchannelNotification](),
	"client.BeginAuthorizationRequest":                      reflect.TypeFor[client.BeginAuthorizationRequest](),
	"client.BeginBackchannelAuthenticationRequest":          reflect.TypeFor[client.BeginBackchannelAuthenticationRequest](),
	"client.CallbackDenied":                                 reflect.TypeFor[client.CallbackDenied](),
	"client.CallbackSuccess":                                reflect.TypeFor[client.CallbackSuccess](),
	"client.ClientCredentialsTokenRequest":                  reflect.TypeFor[client.ClientCredentialsTokenRequest](),
	"client.ClientCredentialsTokenResult":                   reflect.TypeFor[client.ClientCredentialsTokenResult](),
	"client.CompletionDenied":                               reflect.TypeFor[client.CompletionDenied](),
	"client.CompletionSuccess":                              reflect.TypeFor[client.CompletionSuccess](),
	"client.Error":                                          reflect.TypeFor[client.Error](),
	"client.IDTokenClaims":                                  reflect.TypeFor[client.IDTokenClaims](),
	"client.RefreshTokenRequest":                            reflect.TypeFor[client.RefreshTokenRequest](),
	"client.RequestedClaims":                                reflect.TypeFor[client.RequestedClaims](),
	"client.ResourceClient":                                 reflect.TypeFor[client.ResourceClient](),
	"client.ServerErrorResponse":                            reflect.TypeFor[client.ServerErrorResponse](),
	"client.SessionHandle":                                  reflect.TypeFor[client.SessionHandle](),
	"client.TokenSet":                                       reflect.TypeFor[client.TokenSet](),
	"client.UserInfo":                                       reflect.TypeFor[client.UserInfo](),
	"client.ValidatedAuthorizationResponse":                 reflect.TypeFor[client.ValidatedAuthorizationResponse](),
	"extension.Definition":                                  reflect.TypeFor[extension.Definition[string]](),
	"extension.RARDefinition":                               reflect.TypeFor[extension.RARDefinition[string]](),
	"extension.RARDetail":                                   reflect.TypeFor[extension.RARDetail[string]](),
	"extension.RARValues":                                   reflect.TypeFor[extension.RARValues](),
	"extension.Values":                                      reflect.TypeFor[extension.Values](),
	"resource.AccessTokenAssurance":                         reflect.TypeFor[resource.AccessTokenAssurance](),
	"resource.AuthorizationContext":                         reflect.TypeFor[resource.AuthorizationContext](),
	"resource.Error":                                        reflect.TypeFor[resource.Error](),
	"resource.ResolveAccessTokenRequest":                    reflect.TypeFor[resource.ResolveAccessTokenRequest](),
	"resource.ResolvedAccessToken":                          reflect.TypeFor[resource.ResolvedAccessToken](),
	"resource.VerifyRequest":                                reflect.TypeFor[resource.VerifyRequest](),
	"server.AccessTokenAssurance":                           reflect.TypeFor[server.AccessTokenAssurance](),
	"server.AccessTokenParams":                              reflect.TypeFor[server.AccessTokenParams](),
	"server.AttestedClient":                                 reflect.TypeFor[server.AttestedClient](),
	"server.AttestedClientAuthenticationRequest":            reflect.TypeFor[server.AttestedClientAuthenticationRequest](),
	"server.AuditEvent":                                     reflect.TypeFor[server.AuditEvent](),
	"server.AuthReqID":                                      reflect.TypeFor[server.AuthReqID](),
	"server.AuthenticatedSubject":                           reflect.TypeFor[server.AuthenticatedSubject](),
	"server.AuthenticationContext":                          reflect.TypeFor[server.AuthenticationContext](),
	"server.AuthenticationHints":                            reflect.TypeFor[server.AuthenticationHints](),
	"server.AuthorizationCodeExchangeRequest":               reflect.TypeFor[server.AuthorizationCodeExchangeRequest](),
	"server.AuthorizationLocalError":                        reflect.TypeFor[server.AuthorizationLocalError](),
	"server.AuthorizationRedirect":                          reflect.TypeFor[server.AuthorizationRedirect](),
	"server.BackchannelAuthenticationHandle":                reflect.TypeFor[server.BackchannelAuthenticationHandle](),
	"server.BackchannelAuthenticationHints":                 reflect.TypeFor[server.BackchannelAuthenticationHints](),
	"server.BackchannelAuthenticationLocalError":            reflect.TypeFor[server.BackchannelAuthenticationLocalError](),
	"server.BackchannelInteractionRequest":                  reflect.TypeFor[server.BackchannelInteractionRequest](),
	"server.BackchannelInteractionRequired":                 reflect.TypeFor[server.BackchannelInteractionRequired](),
	"server.BackchannelNotification":                        reflect.TypeFor[server.BackchannelNotification](),
	"server.BackchannelTokenExchangeRequest":                reflect.TypeFor[server.BackchannelTokenExchangeRequest](),
	"server.BeginAuthorizationRequest":                      reflect.TypeFor[server.BeginAuthorizationRequest](),
	"server.BeginBackchannelAuthenticationRequest":          reflect.TypeFor[server.BeginBackchannelAuthenticationRequest](),
	"server.ClientCredentialsTokenRequest":                  reflect.TypeFor[server.ClientCredentialsTokenRequest](),
	"server.CompleteAuthorizationRequest":                   reflect.TypeFor[server.CompleteAuthorizationRequest](),
	"server.CompleteBackchannelAuthenticationRequest":       reflect.TypeFor[server.CompleteBackchannelAuthenticationRequest](),
	"server.DPoPProofBinding":                               reflect.TypeFor[server.DPoPProofBinding](),
	"server.Error":                                          reflect.TypeFor[server.Error](),
	"server.FormParameter":                                  reflect.TypeFor[server.FormParameter](),
	"server.FormRequest":                                    reflect.TypeFor[server.FormRequest](),
	"server.GrantedAuthorization":                           reflect.TypeFor[server.GrantedAuthorization](),
	"server.InteractionHandle":                              reflect.TypeFor[server.InteractionHandle](),
	"server.InteractionRequest":                             reflect.TypeFor[server.InteractionRequest](),
	"server.InteractionRequired":                            reflect.TypeFor[server.InteractionRequired](),
	"server.IssueAccessTokenRequest":                        reflect.TypeFor[server.IssueAccessTokenRequest](),
	"server.IssueRefreshTokenRequest":                       reflect.TypeFor[server.IssueRefreshTokenRequest](),
	"server.ListedGrant":                                    reflect.TypeFor[server.ListedGrant](),
	"server.LocalErrorResponse":                             reflect.TypeFor[server.LocalErrorResponse](),
	"server.PendingBackchannelInteraction":                  reflect.TypeFor[server.PendingBackchannelInteraction](),
	"server.PushAuthorizationRequest":                       reflect.TypeFor[server.PushAuthorizationRequest](),
	"server.PushAuthorizationResult":                        reflect.TypeFor[server.PushAuthorizationResult](),
	"server.RedirectResponse":                               reflect.TypeFor[server.RedirectResponse](),
	"server.RefreshTokenRequest":                            reflect.TypeFor[server.RefreshTokenRequest](),
	"server.RequestURI":                                     reflect.TypeFor[server.RequestURI](),
	"server.RequestedClaims":                                reflect.TypeFor[server.RequestedClaims](),
	"server.SubjectID":                                      reflect.TypeFor[server.SubjectID](),
	"server.TokenBinding":                                   reflect.TypeFor[server.TokenBinding](),
	"server.TokenEndpointRequest":                           reflect.TypeFor[server.TokenEndpointRequest](),
	"server.TokenResult":                                    reflect.TypeFor[server.TokenResult](),
	"server.TokenRevocationRequest":                         reflect.TypeFor[server.TokenRevocationRequest](),
	"server.TokenRevocationResult":                          reflect.TypeFor[server.TokenRevocationResult](),
	"server.VerifiedClientAttestation":                      reflect.TypeFor[server.VerifiedClientAttestation](),
	"storage.AccessTokenLookup":                             reflect.TypeFor[storage.AccessTokenLookup](),
	"storage.AuthorizationCodeAlreadyRedeemedError":         reflect.TypeFor[storage.AuthorizationCodeAlreadyRedeemedError](),
	"storage.AuthorizationCodeRedemption":                   reflect.TypeFor[storage.AuthorizationCodeRedemption](),
	"storage.BackchannelAuthenticationAlreadyRedeemedError": reflect.TypeFor[storage.BackchannelAuthenticationAlreadyRedeemedError](),
	"storage.BackchannelAuthenticationExpiredError":         reflect.TypeFor[storage.BackchannelAuthenticationExpiredError](),
	"storage.BackchannelAuthenticationSlowDownError":        reflect.TypeFor[storage.BackchannelAuthenticationSlowDownError](),
	"storage.BackchannelInboxEntry":                         reflect.TypeFor[storage.BackchannelInboxEntry](),
	"storage.BackchannelInboxListing":                       reflect.TypeFor[storage.BackchannelInboxListing](),
	"storage.BeginAuthorizationTransaction":                 reflect.TypeFor[storage.BeginAuthorizationTransaction](),
	"storage.ClientDisplay":                                 reflect.TypeFor[storage.ClientDisplay](),
	"storage.CompleteAuthorizationTransaction":              reflect.TypeFor[storage.CompleteAuthorizationTransaction](),
	"storage.CompletedInteraction":                          reflect.TypeFor[storage.CompletedInteraction](),
	"storage.ConsumedSession":                               reflect.TypeFor[storage.ConsumedSession](),
	"storage.DecideBackchannelAuthentication":               reflect.TypeFor[storage.DecideBackchannelAuthentication](),
	"storage.DecidedBackchannelAuthentication":              reflect.TypeFor[storage.DecidedBackchannelAuthentication](),
	"storage.GrantEntry":                                    reflect.TypeFor[storage.GrantEntry](),
	"storage.GrantListing":                                  reflect.TypeFor[storage.GrantListing](),
	"storage.LookedUpAccessToken":                           reflect.TypeFor[storage.LookedUpAccessToken](),
	"storage.LookedUpBackchannelAuthentication":             reflect.TypeFor[storage.LookedUpBackchannelAuthentication](),
	"storage.LookupAuthorizationTransaction":                reflect.TypeFor[storage.LookupAuthorizationTransaction](),
	"storage.LookupPushedRequestTransaction":                reflect.TypeFor[storage.LookupPushedRequestTransaction](),
	"storage.NewAccessToken":                                reflect.TypeFor[storage.NewAccessToken](),
	"storage.NewAuthorizationCode":                          reflect.TypeFor[storage.NewAuthorizationCode](),
	"storage.NewBackchannelAuthentication":                  reflect.TypeFor[storage.NewBackchannelAuthentication](),
	"storage.NewBackchannelInboxEntry":                      reflect.TypeFor[storage.NewBackchannelInboxEntry](),
	"storage.NewGrantEntry":                                 reflect.TypeFor[storage.NewGrantEntry](),
	"storage.NewPARRecord":                                  reflect.TypeFor[storage.NewPARRecord](),
	"storage.NewRefreshToken":                               reflect.TypeFor[storage.NewRefreshToken](),
	"storage.NewSession":                                    reflect.TypeFor[storage.NewSession](),
	"storage.NonceIssuance":                                 reflect.TypeFor[storage.NonceIssuance](),
	"storage.NonceLookup":                                   reflect.TypeFor[storage.NonceLookup](),
	"storage.NonceRecord":                                   reflect.TypeFor[storage.NonceRecord](),
	"storage.PairwiseSubjectKey":                            reflect.TypeFor[storage.PairwiseSubjectKey](),
	"storage.PendingInteraction":                            reflect.TypeFor[storage.PendingInteraction](),
	"storage.PendingPushedRequest":                          reflect.TypeFor[storage.PendingPushedRequest](),
	"storage.PollBackchannelAuthentication":                 reflect.TypeFor[storage.PollBackchannelAuthentication](),
	"storage.PolledBackchannelAuthentication":               reflect.TypeFor[storage.PolledBackchannelAuthentication](),
	"storage.PushedAuthorizationRequest":                    reflect.TypeFor[storage.PushedAuthorizationRequest](),
	"storage.RedeemedAuthorizationCode":                     reflect.TypeFor[storage.RedeemedAuthorizationCode](),
	"storage.RedeemedRefreshToken":                          reflect.TypeFor[storage.RedeemedRefreshToken](),
	"storage.RefreshTokenRedemption":                        reflect.TypeFor[storage.RefreshTokenRedemption](),
	"storage.RegisteredClient":                              reflect.TypeFor[storage.RegisteredClient](),
	"storage.ReplayUse":                                     reflect.TypeFor[storage.ReplayUse](),
	"storage.SessionConsumption":                            reflect.TypeFor[storage.SessionConsumption](),
}

// The reasons a type is exempt from the guard.
const (
	configuration = "configuration: set once at startup, from the deployment's own values, never a request's"
	engine        = "an engine: it holds keys behind interfaces, dependencies and stores' records, never a value a flow hands to its caller"
)

// exemptTypes are the exported struct types the guard doesn't fill.
var exemptTypes = map[string]string{
	"client.Algorithms": configuration, "client.Config": configuration, "client.Dependencies": configuration,
	"client.Endpoints": configuration, "client.FederationConfig": configuration, "client.Limits": configuration,
	"client.MTLSEndpoints": configuration, "sessioncookie.Options": configuration, "fapitest.Config": configuration,
	"resource.Config": configuration, "resource.Dependencies": configuration, "resource.Limits": configuration,
	"server.AlgorithmPolicy": configuration, "server.AutomaticRegistrationConfig": configuration, "server.Config": configuration,
	"server.Dependencies": configuration, "server.Endpoints": configuration, "server.FederationConfig": configuration,
	"server.Limits": configuration, "server.MTLSEndpointAliases": configuration, "server.MTLSEndpoints": configuration,
	"server.SubjectConfig": configuration, "interactioncookie.Options": configuration, "storage.RegisteredClientConfig": configuration,
	"client.BackchannelSessionSealer": engine, "client.Client": engine, "client.DiscoveredMetadata": engine,
	"client.InMemoryDPoPNonceCache": engine, "client.SystemClock": engine, "client.TokenSetSealer": engine,
	"sessioncookie.Cookie": engine, "extension.RARRegistry": engine, "extension.Registry": engine,
	"fapitest.AutoApprove": engine, "fapitest.Harness": engine, "resource.JWTAccessTokens": engine,
	"resource.NoDPoPNonces": engine, "resource.NoRevocation": engine, "resource.NoRevocationUntilExpiry": engine,
	"resource.OpaqueAccessTokens": engine, "resource.SystemClock": engine, "resource.Verifier": engine,
	"server.AllowRequestedAuthorizationDetails": engine, "server.AnyAttesterLeaf": engine, "server.AttesterAnchor": engine,
	"server.BackchannelNotifierCapabilities": engine, "server.ClientCertificateCRLs": engine, "server.ClientCertificateChainVerifiedUpstream": engine,
	"server.ClientCertificateRevocationCheck": engine, "server.DefaultAttesterLeafPolicy": engine, "server.JWTAccessTokens": engine,
	"server.Metadata": engine, "server.NoBackchannelNotifications": engine, "server.NoClientAttestationStatusCheck": engine,
	"server.NoClientCertificateChainTrust": engine, "server.NoClientCertificateRevocationCheck": engine, "server.NoDPoPNonces": engine,
	"server.NoPKIClientAuthentication": engine, "server.NoRevocation": engine, "server.OpaqueAccessTokens": engine,
	"server.RegisteredAttesterKeys": engine, "server.Server": engine, "server.StaticAttesterTrustAnchors": engine,
	"server.SystemClock": engine, "server.TrustedClientCAs": engine, "server.X5CAttesterChain": engine,
	"interactioncookie.Cookie": engine, "storage.Capabilities": engine, "memstore.AccessTokenStore": engine,
	"memstore.BackchannelAuthenticationStore": engine, "memstore.BackchannelInbox": engine, "memstore.ClientRepository": engine,
	"memstore.GrantRegistry": engine, "memstore.GrantStore": engine, "memstore.NonceStore": engine,
	"memstore.PairwiseSubjectStore": engine, "memstore.ReplayStore": engine, "memstore.RevocationStore": engine,
	"memstore.SessionStore": engine, "memstore.TransactionStore": engine,
}

// TestRedactionGuardCoversEveryExportedType parses the guarded packages
// and fails for an exported struct type neither guarded nor exempt, and
// for a table entry that names no exported type.
func TestRedactionGuardCoversEveryExportedType(t *testing.T) {
	declared := map[string]bool{}
	for _, dir := range guardedPackages {
		for name, isStruct := range exportedTypes(t, dir) {
			declared[name] = true
			if isStruct && !classified(name) {
				t.Errorf("%s is neither guarded nor exempt: add it to guardedTypes, or to exemptTypes with a reason", name)
			}
		}
	}
	for _, name := range append(slices.Collect(maps.Keys(guardedTypes)), slices.Collect(maps.Keys(exemptTypes))...) {
		if !declared[name] {
			t.Errorf("the guard's tables name %s, which no guarded package declares", name)
		}
	}
}

// classified reports whether the guard either checks name or exempts it.
func classified(name string) bool {
	_, guarded := guardedTypes[name]
	_, exempt := exemptTypes[name]
	return guarded || exempt
}

// exportedTypes is the exported types declared in dir's non-test files,
// by package-qualified name, and whether each is a struct.
func exportedTypes(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range typeSpecs(file) {
			if spec.Name.IsExported() {
				_, isStruct := spec.Type.(*ast.StructType)
				out[file.Name.Name+"."+spec.Name.Name] = isStruct && !spec.Assign.IsValid()
			}
		}
	}
	return out
}

func typeSpecs(file *ast.File) []*ast.TypeSpec {
	var specs []*ast.TypeSpec
	for _, decl := range file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
			for _, spec := range gd.Specs {
				specs = append(specs, spec.(*ast.TypeSpec))
			}
		}
	}
	return specs
}

// handleTypes are the types whose String is their wire value, which fmt
// prints by design: the handles, and a request_uri.
var handleTypes = []string{"client.SessionHandle", "server.InteractionHandle", "server.BackchannelAuthenticationHandle", "server.AuthReqID", "server.RequestURI"}

// TestRedactionGuardRenderings renders every guarded type, filled with
// sentinels, and checks what prints against testdata/redaction.golden.
func TestRedactionGuardRenderings(t *testing.T) {
	var got []string
	for _, name := range sortedNames(guardedTypes) {
		got = append(got, guardType(t, name, guardedTypes[name])...)
	}
	if *updateGolden {
		writeGolden(t, got)
		return
	}
	want := readGolden(t)
	for _, line := range got {
		if !slices.Contains(want, line) {
			t.Errorf("a rendering changed: %s is not in %s (if it is right, run go test -run TestRedactionGuard -update and review the diff)", line, guardGolden)
		}
	}
	for _, line := range want {
		if !slices.Contains(got, line) {
			t.Errorf("a rendering changed: %s no longer happens (if that is right, run go test -run TestRedactionGuard -update)", line)
		}
	}
}

func sortedNames(m map[string]reflect.Type) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// guardType fills a value of t with sentinels, renders it, and returns
// a golden line for each field path that printed, with the classes that
// printed it; it fails for a value held in a fapi.Secret that printed
// other than through a handle's String.
func guardType(t *testing.T, name string, typ reflect.Type) (lines []string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: rendering panicked: %v", name, r)
		}
	}()
	v := reflect.New(typ).Elem()
	f := newFiller()
	f.fill(v, name, 0)
	if len(f.sentinels) == 0 {
		return nil
	}
	classes := map[string][]string{}
	for _, l := range rendertest.LeaksOf(v, f.sentinels) {
		path := f.paths[l.Secret]
		if f.secret[l.Secret] && (l.Class != rendertest.Logging || !isHandleValue(path)) {
			t.Errorf("%s: %s, held in a fapi.Secret, printed: %v", name, path, l)
		}
		if !slices.Contains(classes[path], string(l.Class)) {
			classes[path] = append(classes[path], string(l.Class))
		}
	}
	for path, cs := range classes {
		slices.Sort(cs)
		lines = append(lines, path+" "+strings.Join(cs, ","))
	}
	slices.Sort(lines)
	return lines
}

// isHandleValue reports whether path is a handle's own value, which its
// String prints.
func isHandleValue(path string) bool {
	return slices.ContainsFunc(handleTypes, func(h string) bool { return path == h+".value" })
}

func readGolden(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(guardGolden)
	if err != nil {
		t.Fatalf("read %s (go test -run TestRedactionGuard -update writes it): %v", guardGolden, err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

const goldenHeader = `# What prints of each guarded type, filled with sentinels: one line per
# field path whose sentinel printed, with the classes of rendering that
# printed it (see fapitest/redaction_guard_test.go): log (the value's own
# methods: fmt's v, s, q, x and X, log/slog, the templates), fallback
# (fmt's reflection fallback: other verbs, %p, %w, an unexported field)
# and encoding (encoding/json, xml and gob). Rewrite it with
# go test -run TestRedactionGuard -update, and review the diff: a path
# that starts printing must be one that may.
`

func writeGolden(t *testing.T, lines []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(guardGolden), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guardGolden, []byte(goldenHeader+strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// maxFillDepth bounds how deep the filler goes into nested values: deep
// enough for a form parameter's name and value behind
// TokenEndpointRequest's pointer to a pointer, and for the extension
// values an interaction's Values holds, likewise.
const maxFillDepth = 8

// filler fills a value's strings with sentinels, recording where each
// went.
type filler struct {
	sentinels []string
	paths     map[string]string
	secret    map[string]bool
}

func newFiller() *filler {
	return &filler{paths: map[string]string{}, secret: map[string]bool{}}
}

// next is a new sentinel for path. Its number sits inside it, so even a
// base64 form of it, which can lose two bytes at either end, tells it
// from the others.
func (f *filler) next(path string) string {
	s := fmt.Sprintf("GUARDSENT%05dZGUARD", len(f.sentinels)+1)
	f.sentinels = append(f.sentinels, s)
	f.paths[s] = path
	return s
}

var (
	secretType     = reflect.TypeFor[fapi.Secret]()
	urlType        = reflect.TypeFor[fapi.URL]()
	rawMessageType = reflect.TypeFor[json.RawMessage]()
)

// fill sets every string v can hold, below the depth limit, to a
// sentinel of its own: v must be addressable.
func (f *filler) fill(v reflect.Value, path string, depth int) {
	if depth > maxFillDepth || f.fillSpecial(v, path) {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.Set(reflect.ValueOf(f.next(path)).Convert(v.Type()))
	case reflect.Struct:
		f.fillStruct(v, path, depth)
	case reflect.Pointer:
		if elem := v.Type().Elem(); elem.Kind() != reflect.Struct || inModule(elem) {
			p := reflect.New(elem)
			f.fill(p.Elem(), path+".*", depth+1)
			v.Set(p)
		}
	case reflect.Slice:
		f.fillSlice(v, path, depth)
	case reflect.Map:
		f.fillMap(v, path, depth)
	case reflect.Array:
		if v.Len() > 0 && v.Type().Elem().Kind() != reflect.Uint8 {
			f.fill(v.Index(0), path+"[0]", depth+1)
		}
	}
}

// fillSpecial fills the module's own value types that hold a string in a
// form of their own, reporting whether v was one.
func (f *filler) fillSpecial(v reflect.Value, path string) bool {
	switch v.Type() {
	case secretType:
		s := f.next(path)
		f.secret[s] = true
		v.Set(reflect.ValueOf(fapi.NewSecret(s)))
	case urlType:
		u, err := fapi.ParseEndpointURL("https://guard.example/p?code=" + f.next(path))
		if err != nil {
			panic(err)
		}
		v.Set(reflect.ValueOf(u))
	case rawMessageType:
		v.Set(reflect.ValueOf(json.RawMessage(`"` + f.next(path) + `"`)))
	default:
		return false
	}
	return true
}

// fillStruct fills each of v's fields, exported or not, of a struct type
// of this module.
func (f *filler) fillStruct(v reflect.Value, path string, depth int) {
	if !inModule(v.Type()) {
		return
	}
	for i := range v.NumField() {
		field := v.Field(i)
		if !field.CanSet() {
			field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
		}
		f.fill(field, path+"."+v.Type().Field(i).Name, depth+1)
	}
}

func (f *filler) fillSlice(v reflect.Value, path string, depth int) {
	if v.Type().Elem() == reflect.TypeFor[byte]() {
		v.Set(reflect.ValueOf([]byte(f.next(path))).Convert(v.Type()))
		return
	}
	s := reflect.MakeSlice(v.Type(), 1, 1)
	f.fill(s.Index(0), path+"[0]", depth+1)
	v.Set(s)
}

func (f *filler) fillMap(v reflect.Value, path string, depth int) {
	if v.Type().Key().Kind() != reflect.String {
		return
	}
	m := reflect.MakeMapWithSize(v.Type(), 1)
	key := reflect.ValueOf(f.next(path + "{key}")).Convert(v.Type().Key())
	value := reflect.New(v.Type().Elem()).Elem()
	f.fill(value, path+"[]", depth+1)
	m.SetMapIndex(key, value)
	v.Set(m)
}

// inModule reports whether t is declared in this module, whose types the
// filler fills field by field; another package's struct is left zero.
func inModule(t reflect.Type) bool {
	return strings.HasPrefix(t.PkgPath(), "github.com/idfoundry/fapigo")
}
