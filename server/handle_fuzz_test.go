package server

import (
	"bytes"
	"encoding/base64"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzParseHandles checks ParseInteractionHandle and
// ParseBackchannelAuthenticationHandle, which read back a handle a
// consent UI or out-of-band authentication component stored somewhere
// of its own, and the digests a handle is then looked up by:
//
//   - each accepts exactly a non-empty value and keeps it unchanged, so
//     String(Parse(s)) == s and Parse(h.String()) == h;
//   - a handle generated from fuzzed randomness is unpadded base64url of
//     32 bytes and round-trips the same way;
//   - the digest a handle is stored under is a function of the whole
//     value, unnormalized: two different values never share one, and an
//     interaction handle's never equals a pushed authorization
//     request's, however the client_id and reference are chosen.
func FuzzParseHandles(f *testing.F) {
	f.Add("", "x", "client", []byte{})
	f.Add("abc", "ABC", "", []byte("0123456789abcdef0123456789abcdef"))
	f.Add("handle ", "handle", "c", []byte{0xff})
	f.Add("a\x00b", "a", "1:a", []byte(nil))
	f.Fuzz(func(t *testing.T, a, b, clientID string, random []byte) {
		checkHandleRoundTrip(t, a)
		checkHandleRoundTrip(t, b)
		checkHandleDigests(t, a, b, clientID)
		checkGeneratedHandle(t, random)
	})
}

// checkHandleRoundTrip checks both parsers accept value exactly when
// it's non-empty, and keep it unchanged.
func checkHandleRoundTrip(t *testing.T, value string) {
	t.Helper()
	ih, ierr := ParseInteractionHandle(value)
	bh, berr := ParseBackchannelAuthenticationHandle(value)
	if (ierr == nil) != (value != "") || (berr == nil) != (value != "") {
		t.Fatalf("Parse(%q) = %v, %v; want acceptance exactly for a non-empty value", value, ierr, berr)
	}
	if value == "" {
		return
	}
	if ih.String() != value || bh.String() != value {
		t.Fatalf("Parse(%q) changed the value to %q, %q", value, ih.String(), bh.String())
	}
	ih2, err1 := ParseInteractionHandle(ih.String())
	bh2, err2 := ParseBackchannelAuthenticationHandle(bh.String())
	if err1 != nil || err2 != nil || ih2 != ih || bh2 != bh {
		t.Fatalf("Parse(h.String()) != h for %q: %v, %v", value, err1, err2)
	}
}

// checkHandleDigests checks the store digests of a and b are distinct
// when a and b are, and are domain-separated from a pushed
// authorization request's.
func checkHandleDigests(t *testing.T, a, b, clientID string) {
	t.Helper()
	if a != b {
		if interactionHandleKey(a) == interactionHandleKey(b) {
			t.Fatalf("interaction handles %q and %q share a store key", a, b)
		}
		if backchannelHandleHash(BackchannelAuthenticationHandle{a}) == backchannelHandleHash(BackchannelAuthenticationHandle{b}) {
			t.Fatalf("backchannel handles %q and %q share a store key", a, b)
		}
	}
	if interactionHandleKey(a) == parReferenceKey(fapi.ClientID(clientID), b) {
		t.Fatalf("interaction handle %q shares a store key with client %q's request_uri %q", a, clientID, b)
	}
	// parReferenceKey's length prefix: moving bytes between the client_id
	// and the reference changes the key.
	if len(clientID) > 0 && parReferenceKey(fapi.ClientID(clientID[:len(clientID)-1]), clientID[len(clientID)-1:]+a) == parReferenceKey(fapi.ClientID(clientID), a) {
		t.Fatalf("client %q's request_uri %q shares a store key with a shorter client_id's", clientID, a)
	}
}

// checkGeneratedHandle checks handles generated from random's bytes
// are what the parsers expect.
func checkGeneratedHandle(t *testing.T, random []byte) {
	t.Helper()
	for name, generate := range map[string]func([]byte) (string, error){
		"interaction": func(r []byte) (string, error) { return generateInteractionHandle(bytes.NewReader(r)) },
		"backchannel": func(r []byte) (string, error) { return generateBackchannelAuthenticationHandle(bytes.NewReader(r)) },
	} {
		value, err := generate(random)
		if (err == nil) != (len(random) >= 32) {
			t.Fatalf("%s handle from %d random bytes: %v", name, len(random), err)
		}
		if err != nil {
			continue
		}
		raw, decErr := base64.RawURLEncoding.Strict().DecodeString(value)
		if decErr != nil || !bytes.Equal(raw, random[:32]) {
			t.Fatalf("%s handle %q isn't base64url of its first 32 random bytes: %v", name, value, decErr)
		}
		checkHandleRoundTrip(t, value)
	}
}
