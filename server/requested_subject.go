package server

import (
	"context"
	"encoding/json"
	"errors"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
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

// VerifyIDTokenHint returns the subject (its "sub") of hint, an ID token
// this server issued to clientID: signed with one of its ID token keys,
// current or previous, under Algorithms.IDToken, with this server's
// issuer, clientID in its aud, and, when present, clientID as its azp.
// It is for flows outside this package that take an ID token as a hint,
// such as RP-Initiated Logout's id_token_hint: whose session to end,
// and which client asked.
//
// Its expiry isn't checked: an ID token used as a hint is typically
// expired, and OIDC Core §3.1.2.1 has servers accept it anyway. So the
// result only says who the token was about, never that the user is
// authenticated now; don't treat it as a login. It is the sub the client
// was given: for a client with pairwise subjects, its pairwise sub, so
// compare it with Server.ClientSubject for a user whose session you
// know, or map it to the user with ResolveIDTokenHint. An encrypted ID token
// isn't accepted: the client decrypts it and sends the signed token
// inside.
//
// A hint that isn't such an ID token is an *Error with
// ErrorInvalidRequest; a failure to resolve this server's own keys is
// ErrorServerError.
func (s *Server) VerifyIDTokenHint(ctx context.Context, hint string, clientID fapi.ClientID) (string, error) {
	if hint == "" {
		return "", newError(ErrorInvalidRequest, 400, "id_token_hint must be a non-empty string", nil)
	}
	subject, err := s.verifyIDTokenHint(ctx, hint, clientID)
	if err != nil {
		return "", err
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

// claimsLocationSubValue returns the end user one location's "sub"
// entry names, "" when it names none: its "value", or the single
// member of its "values". A "values" naming several users is refused
// rather than ignored: the request names its end user, so it must name
// one, and answering it for whoever logs in would ignore it.
func claimsLocationSubValue(requests map[string]json.RawMessage, location string) (string, error) {
	raw, ok := requests["sub"]
	if !ok || isJSONNull(raw) {
		return "", nil
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
		return "", errors.New(`claims: the ` + location + ` "sub" entry must be a JSON object or null`)
	}
	prefix := `claims: the ` + location + ` "sub" entry's`
	if err := checkMemberCase(entry, prefix, "essential", "value", "values"); err != nil {
		return "", err
	}
	value, err := subEntryValue(entry, prefix)
	if err != nil {
		return "", err
	}
	values, err := subEntryValues(entry, prefix)
	if err != nil {
		return "", err
	}
	if value != "" && values != "" && value != values {
		return "", errors.New(prefix + ` "value" and "values" name different end users`)
	}
	if value != "" {
		return value, nil
	}
	return values, nil
}

// subEntryValue returns a "sub" entry's "value", "" when it has none.
func subEntryValue(entry map[string]json.RawMessage, prefix string) (string, error) {
	v, ok := entry["value"]
	if !ok {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(v, &value); err != nil || value == "" {
		return "", errors.New(prefix + ` "value" must be a non-empty string`)
	}
	return value, nil
}

// subEntryValues returns the one end user a "sub" entry's "values"
// names, "" when it has none.
func subEntryValues(entry map[string]json.RawMessage, prefix string) (string, error) {
	v, ok := entry["values"]
	if !ok {
		return "", nil
	}
	var values []string
	if err := json.Unmarshal(v, &values); err != nil || len(values) != 1 || values[0] == "" {
		return "", errors.New(prefix + ` "values" must be an array of exactly one non-empty string`)
	}
	return values[0], nil
}

// meetsRequiredSubject reports whether the authenticated end user, whose
// sub at the client is clientSub, is the one required names (see
// requiredSubject): always, when it names none. required is the client's
// view of the user, as its id_token_hint or "sub" value named it, so it
// is compared with the user's sub at that client, pairwise or public.
func meetsRequiredSubject(required, clientSub string) bool {
	return required == "" || clientSub == required
}

// backchannelSubjects refuses a client whose sub couldn't be issued at
// completion (checkClientSubjectIssuable), before its user is asked to
// approve anything, and returns the sub the request requires (its
// id_token_hint's or "claims" sub, "" for none) with its internal
// subject (backchannelRequiredInternalSubject).
func (s *Server) backchannelSubjects(ctx context.Context, client storage.RegisteredClient, params map[string]json.RawMessage) (string, string, *Error) {
	if err := s.checkClientSubjectIssuable(client); err != nil {
		return "", "", err
	}
	required, err := s.requiredSubject(ctx, params, client.ID())
	if err != nil {
		return "", "", err
	}
	internal, err := s.backchannelRequiredInternalSubject(ctx, client, params, required)
	if err != nil {
		return "", "", err
	}
	return required, internal, nil
}

// backchannelRequiredInternalSubject is requiredInternalSubject for a
// CIBA request. An id_token_hint is how a CIBA request identifies its
// end user (CIBA Core §7.1), so the server must find the user from it:
// from a pairwise client whose subs it can't map back (a one-way deriver
// with no Dependencies.PairwiseSubjectResolver), the hint can't identify
// anyone, and is invalid_request. Its login_hint and login_hint_token forms are
// unaffected, and a "claims" sub value is still enforced at completion.
func (s *Server) backchannelRequiredInternalSubject(ctx context.Context, client storage.RegisteredClient, params map[string]json.RawMessage, required string) (string, *Error) {
	internal, unmappable, mapErr := s.requiredInternalSubject(ctx, client, required)
	if mapErr != nil {
		return "", mapErr
	}
	if _, hinted := params["id_token_hint"]; hinted && unmappable {
		return "", newError(ErrorInvalidRequest, 400, "id_token_hint can't identify an end user of a pairwise client when pairwise subjects are derived one way; use login_hint or login_hint_token", nil)
	}
	return internal, nil
}
