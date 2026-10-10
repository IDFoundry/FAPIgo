package sealedcookie

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// FuzzJarOpen: Open never panics on an arbitrary cookie value, and
// anything it opens is the one value sealed under this key. (Each fuzz
// worker seals afresh with its own nonce, so the cookie strings
// themselves can't be compared.)
func FuzzJarOpen(f *testing.F) {
	jar, err := New("fuzz", [][]byte{bytes.Repeat([]byte{7}, 32)}, "__Host-fuzz", "/")
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	rec := httptest.NewRecorder()
	if err := jar.Set(rec, map[string]string{"k": "v"}, now.Add(time.Hour), now); err != nil {
		f.Fatal(err)
	}
	sealed := ""
	for _, c := range rec.Result().Cookies() {
		sealed = c.Value
	}
	f.Add(sealed)
	f.Add("")
	f.Add("AAAA")
	f.Fuzz(func(t *testing.T, value string) {
		r := httptest.NewRequest(http.MethodGet, "https://rp.example/", nil)
		r.AddCookie(&http.Cookie{Name: "__Host-fuzz", Value: value})
		var v map[string]string
		if jar.Open(r, now, &v) && (len(v) != 1 || v["k"] != "v") {
			t.Fatalf("Open accepted %q, which this jar never sealed: %v", value, v)
		}
	})
}
