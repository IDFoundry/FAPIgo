package resource

import (
	"crypto/rand"
	"fmt"
	"io"
)

// InteractionIDHeader is the FAPI 1.0 Part 1 §6.2.1 header name a
// protected resource must set on every response to a request it
// processes — success or error alike.
const InteractionIDHeader = "x-fapi-interaction-id"

// NewInteractionID generates a fresh RFC 4122 version 4 UUID, in the
// canonical 8-4-4-4-12 lowercase hex form the OIDF conformance suite's
// own check parses via java.util.UUID.fromString (confirmed by reading
// CheckForFAPIInteractionIdInResourceResponse directly) — any other
// shape is rejected outright as "Invalid x-fapi-interaction-id - not a
// UUID", not merely a style preference.
func NewInteractionID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	var buf [16]byte
	if _, err := io.ReadFull(random, buf[:]); err != nil {
		return "", err
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}

// ResolveInteractionID implements FAPI 1.0 Part 1 §6.2.1 exactly:
// "shall set the response header x-fapi-interaction-id to the value
// received from the corresponding x-fapi-interaction-id request
// header, or a RFC4122 UUID if the interaction id was not provided" —
// presented is that incoming request header's raw value ("" if
// absent).
//
// An HTTP adapter should call this before doing anything else with a
// protected resource request, then set the result as the response's
// own x-fapi-interaction-id header unconditionally, on every response
// this request produces (including every error path) — this package's
// Verify never touches this header itself, since the value depends on
// nothing Verify computes, only on the raw incoming request.
func ResolveInteractionID(presented string, random io.Reader) (string, error) {
	if presented != "" {
		return presented, nil
	}
	return NewInteractionID(random)
}
