package keys

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// ClientKeyMaterial is one registered client's public keys, as
// NewStaticClientKeys takes them: its JWK Set document, keys given
// directly, or both (the keys of both are served). A zero
// ClientKeyMaterial registers a client with no keys at all — one that
// signs nothing, such as a client authenticating with a TLS client
// certificate — whose lookups return an empty set.
type ClientKeyMaterial struct {
	// JWKS is the client's JWK Set document (RFC 7517 §5), such as its
	// "jwks" registration metadata (RFC 7591 §2). Its signature keys
	// are served by ResolveVerificationKeys and its encryption keys
	// ("use":"enc", or an "alg" that is a key management algorithm) by
	// ResolveEncryptionKeys. An entry this module can't use — an
	// unsupported algorithm or key type, malformed key material, or an
	// RSA key over 4096 bits — is skipped, as it is in a JWK Set the
	// server fetches; a JWKS with no usable entry at all is refused.
	JWKS []byte

	// VerificationKeys are signature verification keys given directly.
	// Each needs an Algorithm and a PublicKey that fits it, held to
	// the same limits as a key parsed from a JWK Set.
	VerificationKeys []VerificationKey

	// EncryptionKeys are keys to encrypt to the client, given directly,
	// held to the same limits as VerificationKeys.
	EncryptionKeys []ClientEncryptionKey
}

// clientKeySet is one client's validated keys: those that verify its
// signatures and those to encrypt to it.
type clientKeySet struct {
	verification []VerificationKey
	encryption   []ClientEncryptionKey
}

// StaticClientKeys is a ClientKeySource and ClientEncryptionKeySource
// over keys registered up front, client by client — for a deployment
// that keeps its clients' public keys (their registered "jwks", or keys
// loaded from configuration) rather than fetching a jwks_uri; see
// ClientJWKSSource for that.
//
// A lookup only ever searches the requesting client's own keys: a kid
// another client registered never resolves for this one, even when two
// clients use the same kid. A client that wasn't registered is an
// error, never a fallback set. Results are filtered by the requested
// algorithm, and by kid when one is requested.
//
// It performs no network fetch, so it declares LiveFetchHardened. Run
// TestClientKeySourceContract against any other ClientKeySource to
// check it keeps the same per-client isolation.
type StaticClientKeys struct {
	clients map[fapi.ClientID]clientKeySet
}

// NewStaticClientKeys validates every client's keys once, up front, so
// a malformed or unacceptable key fails here rather than on the first
// request that needs it: an empty client ID, a JWKS that doesn't parse
// or holds no usable key, or a key given directly whose algorithm is
// missing or whose public key doesn't fit it (wrong type or curve, an
// RSA modulus under 2048 or over 4096 bits, an RSA exponent other than
// 65537) is an error. The keys are copied, so changing clients
// afterwards doesn't change what the source serves.
func NewStaticClientKeys(clients map[fapi.ClientID]ClientKeyMaterial) (*StaticClientKeys, error) {
	s := &StaticClientKeys{clients: make(map[fapi.ClientID]clientKeySet, len(clients))}
	for id, material := range clients {
		if id == "" {
			return nil, fmt.Errorf("keys: NewStaticClientKeys: a client has no client ID")
		}
		set, err := validateClientKeyMaterial(material)
		if err != nil {
			return nil, fmt.Errorf("keys: NewStaticClientKeys: client %q: %w", id, err)
		}
		s.clients[id] = set
	}
	return s, nil
}

// validateClientKeyMaterial parses material's JWKS and checks its
// directly given keys, returning all of them as one set.
func validateClientKeyMaterial(material ClientKeyMaterial) (clientKeySet, error) {
	var set clientKeySet
	if len(material.JWKS) > 0 {
		parsed, err := parseClientJWKS(material.JWKS)
		if err != nil {
			return clientKeySet{}, fmt.Errorf("jwks: %w", err)
		}
		set = parsed
	}
	for i, k := range material.VerificationKeys {
		if err := jose.ValidateCallerVerificationKey(k.PublicKey, k.Algorithm); err != nil {
			return clientKeySet{}, fmt.Errorf("verification key %d (kid %q): %w", i, k.KeyID, err)
		}
		set.verification = append(set.verification, k)
	}
	for i, k := range material.EncryptionKeys {
		if err := jose.ValidateCallerEncryptionKey(k.PublicKey, k.Algorithm); err != nil {
			return clientKeySet{}, fmt.Errorf("encryption key %d (kid %q): %w", i, k.KeyID, err)
		}
		set.encryption = append(set.encryption, k)
	}
	return set, nil
}

// ResolveVerificationKeys implements ClientKeySource: req.ClientID's
// own keys for req.Algorithm (and req.KeyID, if set), or an error if
// that client wasn't registered. req.Purpose doesn't narrow the result:
// a JWK Set doesn't say which signatures a key is for.
func (s *StaticClientKeys) ResolveVerificationKeys(_ context.Context, req ClientKeyRequest) (VerificationKeySet, error) {
	set, ok := s.clients[req.ClientID]
	if !ok {
		return VerificationKeySet{}, fmt.Errorf("keys: StaticClientKeys: unknown client %q", req.ClientID)
	}
	return VerificationKeySet{Keys: matchVerificationKeys(set, req.Algorithm, req.KeyID)}, nil
}

// ResolveEncryptionKeys implements ClientEncryptionKeySource:
// req.ClientID's own encryption keys for req.Algorithm (and req.KeyID,
// if set), or an error if that client wasn't registered. As with
// keys/ephemeral, req.Purpose doesn't narrow the result: a client
// registering for both ID token and UserInfo encryption with the same
// algorithm should register one key for it.
func (s *StaticClientKeys) ResolveEncryptionKeys(_ context.Context, req ClientEncryptionKeyRequest) (ClientEncryptionKeySet, error) {
	set, ok := s.clients[req.ClientID]
	if !ok {
		return ClientEncryptionKeySet{}, fmt.Errorf("keys: StaticClientKeys: unknown client %q", req.ClientID)
	}
	return ClientEncryptionKeySet{Keys: matchEncryptionKeys(set, req.Algorithm, req.KeyID)}, nil
}

// Capabilities implements KeySourceAssurance: StaticClientKeys never
// fetches over the network.
func (s *StaticClientKeys) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}

// matchVerificationKeys is set's verification keys for alg (and kid, if
// set), in a new slice.
func matchVerificationKeys(set clientKeySet, alg fapi.SignatureAlgorithm, kid string) []VerificationKey {
	var matched []VerificationKey
	for _, k := range set.verification {
		if k.Algorithm == alg && (kid == "" || k.KeyID == kid) {
			matched = append(matched, k)
		}
	}
	return matched
}

// matchEncryptionKeys is set's encryption keys for alg (and kid, if
// set), in a new slice.
func matchEncryptionKeys(set clientKeySet, alg fapi.KeyManagementAlgorithm, kid string) []ClientEncryptionKey {
	var matched []ClientEncryptionKey
	for _, k := range set.encryption {
		if k.Algorithm == alg && (kid == "" || k.KeyID == kid) {
			matched = append(matched, k)
		}
	}
	return matched
}

// parseClientJWKS parses a client's JWK Set into its verification keys
// (internal/jose.ParseJWKSet) and encryption keys
// (internal/jose.ParseEncryptionJWKSet), both held to the 4096-bit
// ceiling for an RSA key a caller supplies. A set with no usable key of
// either kind is an error.
func parseClientJWKS(body []byte) (clientKeySet, error) {
	verification, err := jose.ParseJWKSet(body)
	if err != nil {
		return clientKeySet{}, err
	}
	encryption, err := jose.ParseEncryptionJWKSet(body)
	if err != nil {
		return clientKeySet{}, err
	}
	if len(verification) == 0 && len(encryption) == 0 {
		return clientKeySet{}, fmt.Errorf("jwks contains no usable keys")
	}
	var out clientKeySet
	for _, k := range verification {
		out.verification = append(out.verification, VerificationKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey})
	}
	for _, k := range encryption {
		out.encryption = append(out.encryption, ClientEncryptionKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey})
	}
	return out, nil
}
