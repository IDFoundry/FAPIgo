package resource

import (
	"github.com/osanderson/go-fapi/keys"
	"github.com/osanderson/go-fapi/storage"
)

// Dependencies are this verifier's injected collaborators. NewVerifier
// rejects a nil value for any field — there is no implicit fallback (no
// default clock, no silently-installed in-memory replay store).
type Dependencies struct {
	// IssuerKeys resolves the authorization server's verification keys.
	IssuerKeys keys.IssuerKeySource

	// Replay detects reuse of a DPoP proof's jti.
	Replay storage.ReplayStore

	// Clock supplies the current time.
	Clock Clock
}
