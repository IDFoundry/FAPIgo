package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/httperror"
)

// reviewedDescriptions are the newError descriptions in this package
// that aren't a string literal or a constant, keyed by their source
// text, each reviewed as naming no request input: anything a client
// chose belongs in newError's cause, never in the public description.
// TestNewErrorDescriptionsNameNoRequestInput fails for one not listed
// here, so a new one is reviewed rather than slipping through.
var reviewedDescriptions = map[string]bool{
	// DenyLocally's application-chosen reason, IsErrorText-checked.
	"reason": true,
	// authTimeProblem's fixed text.
	"problem": true,
	// requestError: a detailedError's fixed text.
	"detailed.description": true,
	// requestError: a request validation error's fixed text; detail naming request input is a detailedError.
	"err.Error()": true,
	// a fixed hint parameter name.
	`name+" must be a non-empty string"`: true,
	// a fixed parameter name.
	`name+" is included more than once"`: true,
	// a constant.
	`"grant_type must be "+CIBAGrantType`: true,
	// a fixed certificate description.
	`subject+" is revoked"`: true,
	// a fixed certificate description.
	`"failed to check the "+subject+"'s revocation status"`: true,
	// tok is openid or offline_access.
	`"the client_credentials grant has no end user: "+tok+" cannot be requested"`: true,
	// a fixed record name.
	`"failed to decode "+what`: true,
	// a constant.
	`fmt.Sprintf("the end user's internal subject is longer than the reversible pairwise deriver's %d-byte limit (pairwise.MaxReversibleSubjectLength)", pairwise.MaxReversibleSubjectLength)`: true,
	// a constant.
	`fmt.Sprintf("at most %d resource indicators may be requested", resourceindicator.MaxPerRequest)`: true,
	// sizes.
	`fmt.Sprintf("ID token claims total %d bytes, over limits.max_id_token_claims_bytes (%d)", size, s.cfg.Limits.MaxIDTokenClaimsBytes)`: true,
	// the application's own claim name, a server_error.
	`fmt.Sprintf("userinfo claims must not set reserved claim %q", name)`: true,
}

// TestNewErrorDescriptionsNameNoRequestInput walks every newError call
// in this package's source: each description must be a string literal
// or string constant that is RFC 6749 §5.2 error text once newError has
// normalized it, or an expression in reviewedDescriptions.
func TestNewErrorDescriptionsNameNoRequestInput(t *testing.T) {
	sources := parsePackageSources(t)
	consts := stringConstants(t, sources)
	calls := 0
	for _, src := range sources {
		ast.Inspect(src.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isNewErrorCall(call) {
				return true
			}
			calls++
			checkNewErrorDescription(t, src, consts, call.Args[2])
			return true
		})
	}
	if calls < 100 {
		t.Fatalf("found %d newError calls, want the package's own (100 or more)", calls)
	}
}

type packageSource struct {
	fset *token.FileSet
	file *ast.File
	text []byte
}

func parsePackageSources(t *testing.T) []packageSource {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var sources []packageSource
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		text, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, text, 0)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, packageSource{fset: fset, file: file, text: text})
	}
	return sources
}

// stringConstants maps each package-level constant declared with a
// single string literal to its value.
func stringConstants(t *testing.T, sources []packageSource) map[string]string {
	t.Helper()
	consts := map[string]string{}
	for _, src := range sources {
		for _, decl := range src.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				addStringConstants(t, consts, spec.(*ast.ValueSpec))
			}
		}
	}
	return consts
}

func addStringConstants(t *testing.T, consts map[string]string, spec *ast.ValueSpec) {
	t.Helper()
	for i, name := range spec.Names {
		if i >= len(spec.Values) {
			continue
		}
		if lit, ok := spec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			consts[name.Name] = s
		}
	}
}

func isNewErrorCall(call *ast.CallExpr) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "newError" && len(call.Args) == 4
}

func checkNewErrorDescription(t *testing.T, src packageSource, consts map[string]string, arg ast.Expr) {
	t.Helper()
	pos := src.fset.Position(arg.Pos())
	description, isConst := "", false
	switch a := arg.(type) {
	case *ast.BasicLit:
		s, err := strconv.Unquote(a.Value)
		if err != nil {
			t.Fatalf("%s: %v", pos, err)
		}
		description, isConst = s, a.Kind == token.STRING
	case *ast.Ident:
		description, isConst = consts[a.Name]
	}
	if isConst {
		if description != "" && httperror.Description(description) == "" {
			t.Errorf("%s: description %q isn't RFC 6749 §5.2 error text", pos, description)
		}
		return
	}
	text := string(src.text[pos.Offset:src.fset.Position(arg.End()).Offset])
	if _, ok := reviewedDescriptions[text]; !ok {
		t.Errorf("%s: description %s is neither a string constant nor a reviewed expression (see reviewedDescriptions)", pos, text)
	}
}

// TestRequestErrorKeepsDetailInCause: a detailedError's detail, which
// may name request input, reaches the log-facing Error() but never the
// public description.
func TestRequestErrorKeepsDetailInCause(t *testing.T) {
	e := requestError(ErrorInvalidRequest, &detailedError{description: "claims.id_token must map each claim name to null or a JSON object", detail: `claim "MARKER"`})
	if got := e.PublicDescription(); got != "claims.id_token must map each claim name to null or a JSON object" {
		t.Errorf("PublicDescription() = %q", got)
	}
	if !strings.Contains(e.Error(), "MARKER") {
		t.Errorf("Error() = %q, want it to carry the detail", e.Error())
	}
	if e.HTTPStatus() != 400 || e.Code() != ErrorInvalidRequest {
		t.Errorf("Code/HTTPStatus = %q/%d, want invalid_request/400", e.Code(), e.HTTPStatus())
	}
}
