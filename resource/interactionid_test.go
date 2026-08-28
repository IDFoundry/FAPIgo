package resource_test

import (
	"crypto/rand"
	"regexp"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

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
