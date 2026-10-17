package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/resourceindicator"
	"github.com/idfoundry/fapigo/server"
)

// sentResources returns the resources a server reads from what the
// client sends for resources: the repeated form parameters (through the
// server's own FormRequestFromHTTP), and the request object member,
// decoded as a string or an array of strings as the server does.
func sentResources(t *testing.T, resources []string) (form, object []string) {
	t.Helper()
	joined := strings.Join(resources, resourceSeparator)
	body := encodeForm(map[string]string{resourceParameter: joined})
	req, err := http.NewRequest(http.MethodPost, "https://as.example/par", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsed, err := server.FormRequestFromHTTP(req)
	if err != nil {
		t.Fatalf("server.FormRequestFromHTTP(%q): %v", body, err)
	}
	for _, p := range parsed.Parameters {
		if p.Name == resourceParameter {
			form = append(form, p.Value)
		}
	}

	raw := resourceObjectParameter(joined)
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return form, []string{one}
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("request object resource %s: %v", raw, err)
	}
	return form, object
}

// FuzzResourceIndicatorAgreement checks that the client and the server
// agree on resource indicators. Every resource the server accepts, the
// client sends. And whatever the client accepts and sends, as repeated
// form parameters or as a request object member, the server receives
// unchanged and accepts too: otherwise a client could be issued a token
// whose aud isn't the resource it asked for, or refused one it was told
// it could request.
func FuzzResourceIndicatorAgreement(f *testing.F) {
	f.Add("https://rs.example", "")
	f.Add("https://a.example/x?y=z", "https://b.example")
	f.Add("urn:example:resource", "https://a.example")
	f.Add("https://a.example/#frag", "")
	f.Add("relative/path", "")
	f.Add("https://a.example/\xff", "")
	f.Add("https://a.example/\u00e9", "")
	f.Add("https://a.example/a b", "")
	f.Add("https://a.example/"+strings.Repeat("a", resourceindicator.MaxLength), "")
	f.Add("https://a.example", "https://a.example")

	f.Fuzz(func(t *testing.T, a, b string) {
		for _, r := range []string{a, b} {
			if resourceindicator.Check(r) == nil && checkResources([]string{r}) != nil {
				t.Fatalf("the server accepts %q, the client refuses it: %v", r, checkResources([]string{r}))
			}
		}
		resources := slices.DeleteFunc([]string{a, b}, func(r string) bool { return r == "" })
		if len(resources) > 0 && checkResources(resources) == nil {
			checkServerReceives(t, resources)
		}
	})
}

// checkServerReceives fails t unless resources, which the client
// accepts, are within the server's per-request limit, each accepted by
// resourceindicator.Check, and read back unchanged from both the form
// parameters and the request object member the client sends.
func checkServerReceives(t *testing.T, resources []string) {
	t.Helper()
	if len(resources) > resourceindicator.MaxPerRequest {
		t.Fatalf("the client accepts %d resources, more than the server's %d", len(resources), resourceindicator.MaxPerRequest)
	}
	for _, r := range resources {
		if err := resourceindicator.Check(r); err != nil {
			t.Fatalf("the client accepts %q, the server refuses it: %v", r, err)
		}
	}
	form, object := sentResources(t, resources)
	if !slices.Equal(form, resources) {
		t.Fatalf("form parameters carry %q, want %q", form, resources)
	}
	if !slices.Equal(object, resources) {
		t.Fatalf("the request object carries %q, want %q", object, resources)
	}
}
