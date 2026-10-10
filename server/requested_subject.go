package server

import (
	"context"
	"encoding/json"
	"errors"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
)

// requiredSubject returns the end user a request names as the one it
// is for: the subject of its "id_token_hint" (OIDC Core §3.1.2.1, CIBA
// Core §7.1), or of a "sub" value in its "claims" parameter (OIDC Core
// §5.5.1), "" when it names none. The completion must authenticate that
// user or fail: OIDC Core §5.5.1 says the server "MUST NOT reply with
// an ID Token or Access Token for a different user".
//
// A hint that isn't an ID token this server issued to clientID, a
// malformed sub value, and two that name different users are all
// invalid_request: answering such a request for whoever logs in would
// ignore what the client asked for.
func (s *Server) requiredSubject(ctx context.Context, params map[string]json.RawMessage, clientID fapi.ClientID) (string, *Error) {
	claimed, err := claimsSubValue(params)
	if err != nil {
		return "", newError(ErrorInvalidRequest, 400, err.Error(), nil)
	}
	raw, ok := params["id_token_hint"]
	if !ok {
		return claimed, nil
	}
	hint, err := jsonStringValue(raw)
	if err != nil || hint == "" {
		return "", newError(ErrorInvalidRequest, 400, "id_token_hint must be a non-empty string", err)
	}
	subject, hintErr := s.verifyIDTokenHint(ctx, hint, clientID)
	if hintErr != nil {
		return "", hintErr
	}
	if claimed != "" && claimed != subject {
		return "", newError(ErrorInvalidRequest, 400, "id_token_hint and the claims parameter's sub value name different end users", nil)
	}
	return subject, nil
}

// verifyIDTokenHint returns the subject of hint, an ID token this server
// issued to clientID: signed with one of its ID-token keys, current or
// previous, under Algorithms.IDToken, with this server's issuer and an
// aud containing clientID. Its expiry isn't checked (see
// token.IDToken.VerifyHint). An encrypted ID token isn't accepted: the
// client decrypts it and sends the signed ID token inside, as OIDC Core
// §3.1.2.1 provides.
func (s *Server) verifyIDTokenHint(ctx context.Context, hint string, clientID fapi.ClientID) (string, *Error) {
	invalid := func(cause error) (string, *Error) {
		return "", newError(ErrorInvalidRequest, 400, "id_token_hint is not an ID token this server issued to the client", cause)
	}
	if s.cfg.OAuthOnly {
		return invalid(errors.New("this server issues no ID tokens"))
	}
	parsed, err := token.ParseIDToken(hint)
	if err != nil {
		return invalid(err)
	}
	source, err := keys.NewLocalIssuerKeys(s.cfg.Issuer, s.deps.Keys)
	if err != nil {
		return "", newError(ErrorServerError, 500, "failed to resolve the ID token keys", err)
	}
	set, err := source.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer: s.cfg.Issuer.String(), Purpose: keys.IDTokenVerification,
		Algorithm: s.cfg.Algorithms.IDToken, KeyID: parsed.KeyID(),
	})
	if err != nil {
		return "", newError(ErrorServerError, 500, "failed to resolve the ID token keys", err)
	}
	policy := token.IDTokenHintPolicy{ExpectedIssuer: s.cfg.Issuer.String(), Client: clientID.String(), Algorithm: s.cfg.Algorithms.IDToken}
	verifyErr := errors.New("no ID token key matches its kid")
	for _, k := range set.Keys {
		var subject string
		if subject, verifyErr = parsed.VerifyHint(k.PublicKey, policy); verifyErr == nil {
			return subject, nil
		}
	}
	return invalid(verifyErr)
}

// claimsSubValue returns the "sub" value the "claims" parameter requests
// for the ID token or UserInfo (OIDC Core §5.5.1), "" when it requests
// none. A value that isn't a non-empty string, a miscased member, and
// two locations asking for different values are errors.
func claimsSubValue(params map[string]json.RawMessage) (string, error) {
	top, ok := claimsMembers(params["claims"])
	if !ok {
		return "", nil
	}
	var subject string
	for _, location := range [...]string{"id_token", "userinfo"} {
		value, err := claimsLocationSubValue(claimsLocation(top, location), location)
		if err != nil {
			return "", err
		}
		if value == "" {
			continue
		}
		if subject != "" && value != subject {
			return "", errors.New(`claims: the id_token and userinfo "sub" values differ`)
		}
		subject = value
	}
	return subject, nil
}

// claimsLocationSubValue returns the "sub" entry's "value" among one
// location's claim requests, "" when there is none.
func claimsLocationSubValue(requests map[string]json.RawMessage, location string) (string, error) {
	raw, ok := requests["sub"]
	if !ok || isJSONNull(raw) {
		return "", nil
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
		return "", errors.New(`claims: the ` + location + ` "sub" entry must be a JSON object or null`)
	}
	if err := checkMemberCase(entry, `claims: the `+location+` "sub" entry's`, "essential", "value", "values"); err != nil {
		return "", err
	}
	v, ok := entry["value"]
	if !ok {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(v, &value); err != nil || value == "" {
		return "", errors.New(`claims: the ` + location + ` "sub" entry's "value" must be a non-empty string`)
	}
	return value, nil
}

// meetsRequiredSubject reports whether subject is the end user required
// names (see requiredSubject): always, when it names none.
func meetsRequiredSubject(required string, subject AuthenticatedSubject) bool {
	return required == "" || subject.id.value == required
}
