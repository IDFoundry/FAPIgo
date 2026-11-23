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
