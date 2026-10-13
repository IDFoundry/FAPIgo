package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/storage"
)

// userInfoReservedClaims are the claim names SignUserInfoResponse
// manages itself — a caller's claims must not set them, the same
// reserved-claim discipline IssueIDToken/IssueAccessToken already
// apply to their own standard claims.
var userInfoReservedClaims = []string{"iss", "aud"}

// SignUserInfoResponse signs claims as a JWS (OIDC Core §5.3.2), and —
// if client registered for encrypted UserInfo responses — wraps it in a
// JWE, for an embedder's own UserInfo HTTP handler to serve directly.
// This package never implements a UserInfo endpoint itself (see
// identity_claims.go); this method only gives that handler a ready-made
// signed (and optionally encrypted) artifact, the same way issueIDToken
// already does for the token endpoint.
//
// It always adds "iss" (Config.Issuer) and "aud" (client.ID()) to the
// signed payload itself, on top of whatever claims is passed in — OIDC
// Core §5.3.2: "If signed, the UserInfo Response MUST contain the
// Claims iss (issuer) and aud (audience) as members. The iss value
// MUST be the OP's Issuer Identifier URL. The aud value MUST be or
// include the RP's Client ID value." Requiring every embedder's own
// UserInfo handler to remember to set these itself is exactly the kind
// of caller mistake this package avoids everywhere else it issues a
// signed artifact (IssueIDToken/IssueAccessToken own their own
// standard claims the same way) — and, unlike those two, is not merely
// hypothetical: cmd/conformance-as's own UserInfo handler omitted them
// until this method started setting them itself.
//
// It fails with ErrorServerError if Config.Algorithms.UserInfo is unset
// — calling this without configuring a UserInfo signing algorithm is a
// caller mistake, not a silent fall-through to plain JSON, since the
// embedder specifically opted into calling it. It also fails if claims
// itself sets "iss" or "aud" — see userInfoReservedClaims.
//
// For a client that gets pairwise subs, claims' "sub" must be the one
// the client was given (resource.AuthorizationContext.ClientSubject),
// never the user's internal subject (AuthorizationContext.Subject): it
// must carry Config.Subjects' Prefix and a well-formed body, and, when
// Dependencies.PairwiseSubjects can map a sub back, one it issued to the
// client's current sector. Anything else fails with ErrorServerError.
func (s *Server) SignUserInfoResponse(ctx context.Context, client storage.RegisteredClient, claims map[string]json.RawMessage) (string, *Error) {
	if !s.cfg.Algorithms.UserInfo.IsValid() {
		return "", newError(ErrorServerError, 500, "userinfo signing is not configured", nil)
	}
	for _, reserved := range userInfoReservedClaims {
		if _, ok := claims[reserved]; ok {
			return "", newError(ErrorServerError, 500, fmt.Sprintf("userinfo claims must not set reserved claim %q", reserved), nil)
		}
	}
	if subErr := s.checkUserInfoSubject(ctx, client, claims["sub"]); subErr != nil {
		return "", subErr
	}

	signer, kid, err := s.newSigner(ctx, keys.UserInfoSigning, s.cfg.Algorithms.UserInfo)
	if err != nil {
		return "", newError(ErrorServerError, 500, "failed to resolve userinfo signing key", err)
	}
	issJSON, err := json.Marshal(s.cfg.Issuer.String())
	if err != nil {
		return "", newError(ErrorServerError, 500, "failed to encode userinfo iss", err)
	}
	audJSON, err := json.Marshal(client.ID().String())
	if err != nil {
		return "", newError(ErrorServerError, 500, "failed to encode userinfo aud", err)
	}
	signedClaims := make(map[string]json.RawMessage, len(claims))
	for k, v := range claims {
		signedClaims[k] = v
	}
	signedClaims["iss"] = issJSON
	signedClaims["aud"] = audJSON
	payload, err := json.Marshal(signedClaims)
	if err != nil {
		return "", newError(ErrorServerError, 500, "failed to marshal userinfo claims", err)
	}
	signedJWT, err := jose.Sign(signer, jose.Header{Algorithm: s.cfg.Algorithms.UserInfo, KeyID: kid}, payload)
	if err != nil {
		return "", newError(ErrorServerError, 500, "failed to sign userinfo response", err)
	}

	keyManagement, contentEncryption, encrypted := client.UserInfoEncryption()
	if !encrypted {
		return signedJWT, nil
	}
	encryptedJWT, err := s.encryptUserInfoResponse(ctx, client.ID(), keyManagement, contentEncryption, signedJWT)
	if err != nil {
		return "", newError(ErrorServerError, 500, "failed to encrypt userinfo response", err)
	}
	return encryptedJWT, nil
}

// encryptUserInfoResponse wraps signedJWT in a JWE (sign-then-encrypt,
// OIDC Core §5.3.2) for a client that registered for encrypted UserInfo
// responses. Mirrors encryptIDToken (idtoken_encryption.go) exactly,
// parameterized on keys.UserInfoEncryption instead of
// keys.IDTokenEncryption and checked against
// Algorithms.UserInfoEncryptionKeyManagement/ContentEncryption instead
// of the ID token pair — a client's own registration is not itself
// authority to use an algorithm the operator hasn't enabled server-wide.
func (s *Server) encryptUserInfoResponse(ctx context.Context, clientID fapi.ClientID, keyManagement fapi.KeyManagementAlgorithm, contentEncryption fapi.ContentEncryptionAlgorithm, signedJWT string) (string, error) {
	if !s.cfg.Algorithms.UserInfoEncryptionKeyManagement.Contains(keyManagement) {
		return "", fmt.Errorf("server: userinfo encryption key management algorithm %v is not permitted", keyManagement)
	}
	if !s.cfg.Algorithms.UserInfoEncryptionContentEncryption.Contains(contentEncryption) {
		return "", fmt.Errorf("server: userinfo encryption content encryption algorithm %v is not permitted", contentEncryption)
	}

	key, err := s.resolveClientEncryptionKey(ctx, clientID, keys.UserInfoEncryption, keyManagement)
	if err != nil {
		return "", fmt.Errorf("resolve client encryption key: %w", err)
	}

	compact, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: keyManagement, Encryption: contentEncryption,
		RecipientKey: key.PublicKey, KeyID: key.KeyID,
		// "JWT" (RFC 7519 §5.2's canonical form) — the nested payload is
		// itself a signed JWT, not the UserInfo claims re-encoded.
		ContentType: "JWT",
		Random:      s.deps.Random, Plaintext: []byte(signedJWT),
	})
	if err != nil {
		return "", fmt.Errorf("encrypt userinfo response: %w", err)
	}
	return compact, nil
}

// checkUserInfoSubject refuses a UserInfo "sub" (raw, nil when absent)
// that isn't a pairwise sub this server issued to client, when client
// gets pairwise subs: signing the user's internal subject to a pairwise
// client would give away exactly what its pairwise sub hides. A public
// client's sub isn't checked.
func (s *Server) checkUserInfoSubject(ctx context.Context, client storage.RegisteredClient, raw json.RawMessage) *Error {
	subjectType, typeErr := s.subjectTypeFor(client)
	if typeErr != nil {
		return typeErr
	}
	if subjectType != fapi.SubjectTypePairwise {
		return nil
	}
	notIssued := func(cause error) *Error {
		return newError(ErrorServerError, 500, "userinfo sub must be the client's pairwise sub (resource.AuthorizationContext.ClientSubject), not the user's internal subject", cause)
	}
	var sub string
	if err := json.Unmarshal(raw, &sub); err != nil || sub == "" {
		return notIssued(err)
	}
	body, hasPrefix := strings.CutPrefix(sub, effectiveSubjects(s.cfg).Prefix.String())
	if !hasPrefix {
		return notIssued(nil)
	}
	if err := pairwise.CheckBody(body); err != nil {
		return notIssued(err)
	}
	if _, err := s.internalSubjectFor(ctx, client, sub); err != nil && !errors.Is(err, ErrNoPairwiseSubjectLookup) {
		return notIssued(err)
	}
	return nil
}
