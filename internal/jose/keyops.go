package jose

import (
	"fmt"
	"slices"
	"strings"
)

// RFC 7517 §4.3 "key_ops" values this package acts on. A JWK Set
// entry is only a verification key when its key_ops, if it states
// any, includes keyOpVerify, and only a key to encrypt to when they
// include one of keyOpsEncryption: "encrypt" or "wrapKey" for
// RSA-OAEP-256, "deriveKey" or "deriveBits" for ECDH-ES+A256KW, whose
// key agreement derives the key that wraps the content key.
const keyOpVerify = "verify"

var keyOpsEncryption = []string{"encrypt", "wrapKey", "deriveKey", "deriveBits"}

// keyOpsMember reads a JWK Set entry's "key_ops" on its own: rawJWK
// doesn't model it, so ParseJWK (a DPoP proof's "jwk", say) goes on
// ignoring it.
type keyOpsMember struct {
	KeyOps []string `json:"key_ops,omitempty"`
}

// checkKeyOps refuses an entry whose "key_ops" states the operations
// it is for and names none of allowed. An entry with no key_ops, or an
// empty one, states no restriction and is accepted: Web Crypto exports
// an ECDH public key with "key_ops":[], since key agreement uses no
// public-key operation, so reading the empty list as "no operation"
// would refuse those keys for the one use they have.
func checkKeyOps(keyOps []string, allowed ...string) error {
	if len(keyOps) == 0 {
		return nil
	}
	for _, op := range keyOps {
		if slices.Contains(allowed, op) {
			return nil
		}
	}
	return fmt.Errorf("jose: the entry's key_ops [%s] lists none of %q", quoteKeyOps(keyOps), allowed)
}

// maxQuotedKeyOps is how many of an entry's key_ops an error quotes:
// the set's publisher chooses how many there are.
const maxQuotedKeyOps = 4

// quoteKeyOps quotes keyOps for an error, each cut as quoteKeyID cuts
// a kid, and at most maxQuotedKeyOps of them.
func quoteKeyOps(keyOps []string) string {
	quoted := make([]string, 0, maxQuotedKeyOps+1)
	for i, op := range keyOps {
		if i == maxQuotedKeyOps {
			quoted = append(quoted, fmt.Sprintf("and %d more", len(keyOps)-maxQuotedKeyOps))
			break
		}
		quoted = append(quoted, quoteKeyID(op))
	}
	return strings.Join(quoted, " ")
}
