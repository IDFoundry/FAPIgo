package server

import (
	"context"
	"errors"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/storage"
)

// ClientSubject returns the sub that subject has at the client clientID:
// subject's own ID for a client whose end users get public subjects, or
// its pairwise subject for that client's sector (OpenID Connect Core
// §8), exactly as the client's ID tokens carry it.
//
// Use it to compare a user the application knows with a sub a client
// sent: a pairwise client's login_hint, the RequiredSubject of an
// interaction when the server can't map a pairwise sub back to a user
// (pairwise.OneWay), or the sub of an ID token VerifyIDTokenHint
// returned. Errors are *Error: an unknown client, a zero subject, or a
// pairwise subject that couldn't be derived.
func (s *Server) ClientSubject(ctx context.Context, clientID fapi.ClientID, subject AuthenticatedSubject) (string, error) {
	if subject.id.value == "" {
		return "", newError(ErrorServerError, 500, "subject is zero (use NewAuthenticatedSubject)", nil)
	}
	client, err := s.deps.Clients.ResolveClient(ctx, clientID)
	if err != nil {
		return "", newError(ErrorInvalidClient, 401, "client is not registered", err)
	}
	sub, _, subErr := s.clientSubjectFor(ctx, client, subject.id.value)
	if subErr != nil {
		return "", subErr
	}
	return sub, nil
}

// subjectAtClient is clientSubjectFor for the client clientID. The
// client is resolved even when the server's configuration has no
// pairwise default or deriver: a client registered for pairwise subjects
// must then fail closed, not get the internal subject.
func (s *Server) subjectAtClient(ctx context.Context, clientID fapi.ClientID, internal string) (string, string, *Error) {
	client, err := s.deps.Clients.ResolveClient(ctx, clientID)
	if err != nil {
		return "", "", newError(ErrorServerError, 500, "failed to resolve the client for its subject type", err)
	}
	return s.clientSubjectFor(ctx, client, internal)
}

// subjectTypeFor returns the subject type client's end users get: its
// registered one, or Config.Subjects' Default. Under
// SubjectTypesPairwiseOnly a client registered as public is refused, so
// no client can opt out.
func (s *Server) subjectTypeFor(client storage.RegisteredClient) (fapi.SubjectType, *Error) {
	subjects := effectiveSubjects(s.cfg)
	subjectType := client.SubjectType()
	if subjectType == 0 {
		subjectType = subjects.Default
	}
	if subjects.Enforcement == SubjectTypesPairwiseOnly && subjectType != fapi.SubjectTypePairwise {
		return 0, newError(ErrorServerError, 500, "the client is registered for public subjects, but this server issues only pairwise subjects", nil)
	}
	return subjectType, nil
}

// clientSubjectFor returns the sub the end user internal has at client,
// and the sector it was derived for: internal itself and "" for a public
// client, otherwise Config.Subjects' Prefix followed by what
// Dependencies.PairwiseSubjects derives for the client's sector, and
// that sector. It fails closed: a pairwise client never falls back to
// the internal subject.
func (s *Server) clientSubjectFor(ctx context.Context, client storage.RegisteredClient, internal string) (string, string, *Error) {
	subjectType, typeErr := s.subjectTypeFor(client)
	if typeErr != nil {
		return "", "", typeErr
	}
	if subjectType != fapi.SubjectTypePairwise {
		return internal, "", nil
	}
	if s.deps.PairwiseSubjects == nil {
		return "", "", newError(ErrorServerError, 500, "the client is registered for pairwise subjects, but dependencies.pairwise_subjects is nil", nil)
	}
	sector := client.Sector()
	in, err := pairwise.NewInput(s.cfg.Issuer.String(), sector, internal)
	if err != nil {
		return "", "", newError(ErrorServerError, 500, "the client's pairwise subject can't be derived (does it have a sector?)", err)
	}
	ctx, cancel := context.WithTimeout(ctx, keyCheckTimeout)
	defer cancel()
	body, err := s.deps.PairwiseSubjects.DerivePairwiseSubject(ctx, in)
	if err == nil {
		err = pairwise.CheckBody(body)
	}
	if err != nil {
		return "", "", newError(ErrorServerError, 500, "failed to derive the client's pairwise subject", err)
	}
	sub := effectiveSubjects(s.cfg).Prefix.String() + body
	if _, err := NewSubjectID(sub); err != nil {
		return "", "", newError(ErrorServerError, 500, "the derived pairwise subject isn't a usable sub", err)
	}
	return sub, sector, nil
}

// errNoSubjectLookup reports that the server can't map a client's
// pairwise sub back to its end user: Config.Subjects' Derivation is
// pairwise.OneWay.
var errNoSubjectLookup = errors.New("pairwise subjects are derived one way (pairwise.OneWay), so a pairwise sub can't be mapped back to its end user")

// internalSubjectFor maps sub, as the client client sees it, back to the
// end user's internal subject: sub itself for a public client; through
// Dependencies.PairwiseSubjects' pairwise.Lookup for a pairwise client
// under pairwise.Reversible. It returns errNoSubjectLookup, unwrapped,
// when the server can't map pairwise subs back (pairwise.OneWay), and
// otherwise an invalid_request *Error for a sub that names no end user
// of this server at this client.
func (s *Server) internalSubjectFor(ctx context.Context, client storage.RegisteredClient, sub string) (string, error) {
	subjectType, typeErr := s.subjectTypeFor(client)
	if typeErr != nil {
		return "", typeErr
	}
	if subjectType != fapi.SubjectTypePairwise {
		return sub, nil
	}
	subjects := effectiveSubjects(s.cfg)
	lookup, ok := s.deps.PairwiseSubjects.(pairwise.Lookup)
	if subjects.Derivation != pairwise.Reversible || !ok {
		return "", errNoSubjectLookup
	}
	body, hasPrefix := strings.CutPrefix(sub, subjects.Prefix.String())
	if !hasPrefix || pairwise.CheckBody(body) != nil {
		return "", newError(ErrorInvalidRequest, 400, "the sub isn't a pairwise subject this server issued to the client", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, keyCheckTimeout)
	defer cancel()
	internal, err := lookup.LookupInternalSubject(ctx, s.cfg.Issuer.String(), client.Sector(), body)
	switch {
	case errors.Is(err, pairwise.ErrSubjectNotFound):
		return "", newError(ErrorInvalidRequest, 400, "the sub isn't a pairwise subject this server issued to the client", err)
	case err != nil:
		return "", newError(ErrorServerError, 500, "failed to look up the client's pairwise subject", err)
	}
	return internal, nil
}

// distinctClientSubject returns clientSub for grantRecord.ClientSubject:
// "" when it is the internal subject itself (a public client), so the
// grants of public clients are stored as before.
func distinctClientSubject(clientSub, internal string) string {
	if clientSub == internal {
		return ""
	}
	return clientSub
}

// requiredInternalSubject maps required, the end user a pairwise client's
// request named (see requiredSubject), back to the internal subject the
// application knows, for requestRecord.RequiredInternalSubject. It
// returns "" when there is nothing to map (no required subject, or a
// public client, whose view is the internal subject), and unmappable
// when the client is pairwise but the server can't map its subs back
// (pairwise.OneWay): then the application gets the client's view, which
// it can compare with ClientSubject. A pairwise sub this server never
// issued to the client is invalid_request.
func (s *Server) requiredInternalSubject(ctx context.Context, client storage.RegisteredClient, required string) (internal string, unmappable bool, mapErr *Error) {
	if required == "" {
		return "", false, nil
	}
	mapped, err := s.internalSubjectFor(ctx, client, required)
	var serverErr *Error
	switch {
	case errors.Is(err, errNoSubjectLookup):
		return "", true, nil
	case errors.As(err, &serverErr):
		return "", false, serverErr
	case err != nil:
		return "", false, newError(ErrorServerError, 500, "failed to map the required subject", err)
	}
	return distinctClientSubject(mapped, required), false, nil
}
