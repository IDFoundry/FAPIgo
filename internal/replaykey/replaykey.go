// Package replaykey derives the digest a single-use value (a JWT's
// "jti") is recorded under in a storage.ReplayStore, scoped to whoever
// presented it: the authenticated client, or the key a DPoP proof was
// signed with. Scoping means one client or key can't use up a jti
// another will send; without it, a client that knew or guessed another
// client's next jti could make that client's request fail as a replay.
//
// Records written before scoping was introduced were keyed by the jti
// alone, so they don't match a scoped digest: a jti used just before an
// upgrade can be presented once more, until its short lifetime (a
// client assertion's or DPoP proof's maximum age) runs out.
package replaykey

import (
	"crypto/sha256"
	"encoding/binary"
)

// Digest returns SHA-256 over scope's length, scope and jti. The length
// prefix keeps every (scope, jti) pair distinct: no two pairs encode to
// the same input, whatever bytes either holds.
func Digest(scope, jti string) [32]byte {
	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(scope)))
	h.Write(n[:])
	h.Write([]byte(scope))
	h.Write([]byte(jti))
	var d [32]byte
	h.Sum(d[:0])
	return d
}
