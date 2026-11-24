package jose

import (
	"crypto"

	fapi "github.com/idfoundry/fapigo"
)

// ThumbprintKeyID is the "kid" a key given without one answers to: the
// RFC 7638 JWK thumbprint of pub as a key for alg, base64url without
// padding — what keys.NewKeyManagerFromSigners names such a key, and
// what a JWS signed with it then names in its header. It returns "" and
// an error when pub doesn't fit alg (see NewJWK).
func ThumbprintKeyID(pub crypto.PublicKey, alg fapi.SignatureAlgorithm) (string, error) {
	jwk, err := NewJWK(pub, alg)
	if err != nil {
		return "", err
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		return "", err
	}
	return thumbprint.String(), nil
}

// AnsweredKeyID is the kid a key answers to: keyID, its own, or, when
// it has none, its thumbprint kid (ThumbprintKeyID) as a key for alg.
// It is "" for a key without a kid whose thumbprint can't be computed,
// which so answers to no kid. This is the rule keys.VerificationKey's
// KeyID doc sets out; every place that matches a client's key to a
// requested kid applies it through this function or AnswersToKeyID.
func AnsweredKeyID(keyID string, pub crypto.PublicKey, alg fapi.SignatureAlgorithm) string {
	if keyID != "" {
		return keyID
	}
	thumbprint, err := ThumbprintKeyID(pub, alg)
	if err != nil {
		return ""
	}
	return thumbprint
}

// AnswersToKeyID reports whether a key with keyID (possibly "") answers
// to kid, a non-empty kid a request names: AnsweredKeyID is kid.
func AnswersToKeyID(keyID string, pub crypto.PublicKey, alg fapi.SignatureAlgorithm, kid string) bool {
	return kid != "" && AnsweredKeyID(keyID, pub, alg) == kid
}
