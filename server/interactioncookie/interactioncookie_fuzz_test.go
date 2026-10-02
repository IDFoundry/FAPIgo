package interactioncookie_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server/interactioncookie"
)

// FuzzRead covers Read on an arbitrary cookie value, which comes from
// the browser: it never panics, and never fails other than with
// ErrNoInteraction.
func FuzzRead(f *testing.F) {
	key := make([]byte, 32)
	c, err := interactioncookie.New([][]byte{key}, interactioncookie.Options{Lifetime: time.Minute})
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	h, in := interaction(&testing.T{})
	w := httptest.NewRecorder()
	if err := c.Set(w, h, in, now); err != nil {
		f.Fatal(err)
	}
	f.Add(w.Result().Cookies()[0].Value)
	f.Add("")
	f.Add("AQAAAAA")
	f.Add("!!")

	f.Fuzz(func(t *testing.T, value string) {
		r := httptest.NewRequest("POST", "/authorize", nil)
		r.AddCookie(&http.Cookie{Name: interactioncookie.DefaultName, Value: value})
		if _, _, err := c.Read(r, now); err != nil && !errors.Is(err, interactioncookie.ErrNoInteraction) {
			t.Fatalf("Read = %v, want nil or ErrNoInteraction", err)
		}
	})
}
