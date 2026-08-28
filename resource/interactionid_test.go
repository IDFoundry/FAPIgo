package resource_test

import (
	"crypto/rand"
	"errors"
	"regexp"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

// failingReader always errors, standing in for a broken random source.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewInteractionIDIsAWellFormedUUIDv4(t *testing.T) {
	id, err := resource.NewInteractionID(rand.Reader)
	if err != nil {
		t.Fatalf("NewInteractionID: %v", err)
	}
	if !uuidPattern.MatchString(id) {
		t.Fatalf("NewInteractionID() = %q, want an RFC 4122 v4 UUID", id)
	}
}

func TestNewInteractionIDDefaultsToCryptoRandReader(t *testing.T) {
	id, err := resource.NewInteractionID(nil)
	if err != nil {
		t.Fatalf("NewInteractionID(nil): %v", err)
	}
	if !uuidPattern.MatchString(id) {
		t.Fatalf("NewInteractionID(nil) = %q, want an RFC 4122 v4 UUID", id)
	}
}

func TestNewInteractionIDPropagatesRandomReadFailure(t *testing.T) {
	if _, err := resource.NewInteractionID(failingReader{}); err == nil {
		t.Fatalf("NewInteractionID(failing reader) = nil error, want error")
	}
}

func TestNewInteractionIDIsRandomized(t *testing.T) {
	a, err := resource.NewInteractionID(rand.Reader)
	if err != nil {
		t.Fatalf("NewInteractionID: %v", err)
	}
	b, err := resource.NewInteractionID(rand.Reader)
	if err != nil {
		t.Fatalf("NewInteractionID: %v", err)
	}
	if a == b {
		t.Fatalf("NewInteractionID() returned the same value twice: %q", a)
	}
}

func TestResolveInteractionIDEchoesWhenPresented(t *testing.T) {
	id, err := resource.ResolveInteractionID("caller-supplied-value", rand.Reader)
	if err != nil {
		t.Fatalf("ResolveInteractionID: %v", err)
	}
	if id != "caller-supplied-value" {
		t.Fatalf("ResolveInteractionID(presented) = %q, want it echoed back verbatim", id)
	}
}

func TestResolveInteractionIDGeneratesWhenAbsent(t *testing.T) {
	id, err := resource.ResolveInteractionID("", rand.Reader)
	if err != nil {
		t.Fatalf("ResolveInteractionID: %v", err)
	}
	if !uuidPattern.MatchString(id) {
		t.Fatalf("ResolveInteractionID(\"\") = %q, want a generated UUID", id)
	}
}
