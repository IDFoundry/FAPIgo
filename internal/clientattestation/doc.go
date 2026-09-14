// Package clientattestation implements OAuth 2.0 Attestation-Based
// Client Authentication (draft-ietf-oauth-attestation-based-client-auth-07):
// verification of a Client Attestation JWT (§5.1) and the Client
// Attestation Proof of Possession (PoP) JWT (§5.2) it accompanies.
//
// Unlike internal/clientassertion's private_key_jwt, where the JWT is
// signed by the client's own long-lived registered key, a Client
// Attestation is signed by an Attester (a wallet OS or provider's own
// attestation service) that vouches for the Client Instance — its "iss"
// names the Attester, its "sub" names the OAuth client_id. The Client
// Attestation's "cnf" claim carries a Client Instance Key that the
// accompanying, separately-signed PoP JWT must be signed with; verifying
// the PoP therefore requires no server-side key registration at all —
// the key comes from the already-verified Client Attestation itself,
// the same "key travels with the already-verified artifact" trust model
// internal/dpop already uses for a DPoP proof's own embedded "jwk"
// header.
//
// attestation.go verifies the Client Attestation JWT against an
// Attester's public key (resolved by the caller — see server's own
// AttestationVerification keys.VerificationPurpose); pop.go verifies
// the PoP JWT against the Client Instance Key the Client Attestation
// vouched for. Both directions are kept as separate types, mirroring
// internal/clientassertion and internal/requestobject, so each JWT's
// own verification policy can evolve independently.
package clientattestation
