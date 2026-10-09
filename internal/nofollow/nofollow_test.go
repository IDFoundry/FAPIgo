package nofollow_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/nofollow"
)

func redirectingServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestClientStopsAtRedirect(t *testing.T) {
	srv := redirectingServer(t)
	original := &http.Client{}
	d := nofollow.Client(original)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/start", nil)
	res, err := d.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want the redirect itself", res.StatusCode)
	}
	if nofollow.Followed(req, res) {
		t.Fatal("Followed = true for an unfollowed redirect")
	}
	if original.CheckRedirect != nil {
		t.Fatal("the caller's own client was modified")
	}
}

type passthrough struct{ c *http.Client }

func (p passthrough) Do(r *http.Request) (*http.Response, error) { return p.c.Do(r) }

func TestFollowedDetectsAClientThatFollowed(t *testing.T) {
	srv := redirectingServer(t)
	d := nofollow.Client(passthrough{c: &http.Client{}}) // not an *http.Client: returned as is

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/start", nil)
	res, err := d.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the followed hop's 200", res.StatusCode)
	}
	if !nofollow.Followed(req, res) {
		t.Fatal("Followed = false for a followed redirect")
	}
}

func TestClientNil(t *testing.T) {
	if got := nofollow.Client(nil); got != nil {
		t.Fatalf("Client(nil) = %v, want nil", got)
	}
	var typedNil *http.Client
	if nofollow.Client(typedNil) != nofollow.Doer(typedNil) {
		t.Fatal("Client(typed nil) should return it unchanged")
	}
}

func TestFollowedWithoutURLs(t *testing.T) {
	withURL, _ := http.NewRequest(http.MethodGet, "https://example.com/a", nil)
	for name, tc := range map[string]struct {
		req *http.Request
		res *http.Response
	}{
		"nil response":                {withURL, nil},
		"response without request":    {withURL, &http.Response{}},
		"answered request has no URL": {withURL, &http.Response{Request: &http.Request{}}},
		"sent request has no URL":     {&http.Request{}, &http.Response{Request: withURL}},
	} {
		t.Run(name, func(t *testing.T) {
			if nofollow.Followed(tc.req, tc.res) {
				t.Fatal("Followed = true without both URLs")
			}
		})
	}
}

// wrapper is a Doer that isn't an *http.Client.
type wrapper struct{ c *http.Client }

func (w wrapper) Do(req *http.Request) (*http.Response, error) { return w.c.Do(req) }

func TestSendOnce(t *testing.T) {
	newPost := func() *http.Request {
		req, err := http.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader("a=1"))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		return req
	}

	req := newPost()
	nofollow.SendOnce(wrapper{c: &http.Client{}}, req)
	if req.GetBody == nil {
		t.Fatal("SendOnce left GetBody nil; net/http's unwritten-request retry needs it set")
	}
	if body, err := req.GetBody(); body != nil || !errors.Is(err, nofollow.ErrBodyNotResent) {
		t.Fatalf("GetBody() = %v, %v; want nil, ErrBodyNotResent", body, err)
	}

	own := newPost()
	nofollow.SendOnce(nofollow.Client(&http.Client{}), own)
	if body, err := own.GetBody(); err != nil || body == nil {
		t.Fatalf("SendOnce changed an *http.Client's GetBody: %v, %v", body, err)
	}

	get, err := http.NewRequest(http.MethodGet, "https://rs.example.com/accounts", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	nofollow.SendOnce(wrapper{c: &http.Client{}}, get)
	if get.GetBody != nil {
		t.Fatal("SendOnce set GetBody on a body-less request")
	}
}
