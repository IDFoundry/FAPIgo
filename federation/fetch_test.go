package federation_test

import (
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/federation"
)

func TestWriteEntityStatement(t *testing.T) {
	const jwt = "header.payload.signature"
	w := httptest.NewRecorder()

	federation.WriteEntityStatement(w, jwt)

	if got := w.Header().Get("Content-Type"); got != federation.EntityStatementContentType {
		t.Errorf("Content-Type = %q, want %q", got, federation.EntityStatementContentType)
	}
	if got := w.Body.String(); got != jwt {
		t.Errorf("body = %q, want %q", got, jwt)
	}
}
