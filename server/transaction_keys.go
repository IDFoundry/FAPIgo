package server

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"

	fapi "github.com/idfoundry/fapigo"
)

// parReferenceKeyPrefix and interactionHandleKeyPrefix separate the
// digests a pushed authorization request and an interaction are stored
// under from each other and from every other digest this server stores
// (authorizationCodeHash's, a refresh token's).
const (
	parReferenceKeyPrefix      = "fapigo pushed authorization request\x00"
	interactionHandleKeyPrefix = "fapigo interaction handle\x00"
)

// parReferenceKey is what a pushed authorization request is stored and
// begun under (storage.NewPARRecord.Reference,
// storage.BeginAuthorizationTransaction.Reference): a SHA-256 digest of
// the request_uri's reference bound to the client_id that pushed it,
// base64url-encoded, never the reference itself. So a store read
// yields no live request_uri, as it yields no live code or refresh
// token, and a request_uri presented with another client_id is unknown
// to the store: BeginAuthorization mints no interaction for it. The
// client_id is length-prefixed, so no client_id and reference pair
// collides with another.
func parReferenceKey(clientID fapi.ClientID, reference string) string {
	id := string(clientID)
	sum := sha256.Sum256([]byte(parReferenceKeyPrefix + strconv.Itoa(len(id)) + ":" + id + reference))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// interactionHandleKey is what an interaction is stored and completed
// under (storage.BeginAuthorizationTransaction.Handle,
// storage.CompleteAuthorizationTransaction.Handle): a SHA-256 digest of
// the InteractionHandle, base64url-encoded, never the handle itself.
func interactionHandleKey(handle string) string {
	sum := sha256.Sum256([]byte(interactionHandleKeyPrefix + handle))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
