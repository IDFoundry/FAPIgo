package jose

import (
	"errors"
	"slices"
	"strings"
)

// ErrOtherExplicitType reports a JWT whose "typ" names a different,
// explicitly typed kind of JWT than the one being parsed.
var ErrOtherExplicitType = errors.New("jose: header typ names another kind of JWT")

// TypeIs reports whether typ names the media type want, comparing as
// RFC 7515 §4.1.9 asks: case-insensitively (RFC 2045), and with
// "application/" implied for a value containing no '/'. So
// "application/at+jwt" and "AT+JWT" are both TypeIs(_, "at+jwt").
func TypeIs(typ, want string) bool {
	return mediaType(typ) == mediaType(want)
}

func mediaType(typ string) string {
	typ = strings.ToLower(typ)
	if !strings.Contains(typ, "/") {
		typ = "application/" + typ
	}
	return typ
}

// explicitTypes is the "typ" of every explicitly typed JWT (RFC 8725
// §3.11) this library produces or consumes, plus the related ones a
// party it trusts could plausibly sign: DPoP proofs, JWT access tokens,
// request objects, client attestations and their PoPs, client
// authentication assertions (draft-ietf-oauth-rfc7523bis), OpenID
// Federation's statements, trust marks and responses, logout tokens,
// Security Event Tokens and signed introspection responses.
var explicitTypes = []string{
	"dpop+jwt",
	"at+jwt",
	"oauth-authz-req+jwt",
	"oauth-client-attestation+jwt",
	"oauth-client-attestation-pop+jwt",
	"client-authentication+jwt",
	"entity-statement+jwt",
	"trust-mark+jwt",
	"trust-mark-delegation+jwt",
	"trust-mark-status-response+jwt",
	"resolve-response+jwt",
	"jwk-set+jwt",
	"logout+jwt",
	"secevent+jwt",
	"token-introspection+jwt",
}

// RefuseOtherExplicitType returns ErrOtherExplicitType when typ names an
// explicitly typed kind of JWT other than own. It is for the kinds whose
// specifications leave "typ" optional — ID tokens, JARM responses,
// client assertions — so a missing or generic typ ("JWT") is accepted,
// but a token that says it is something else isn't taken for one of
// these: a resource-bound access token signed by the same key as ID
// tokens, say, or a client's request object offered as its client
// assertion (RFC 8725 §3.11).
func RefuseOtherExplicitType(typ string, own ...string) error {
	if typ == "" {
		return nil
	}
	for _, t := range own {
		if TypeIs(typ, t) {
			return nil
		}
	}
	if slices.ContainsFunc(explicitTypes, func(t string) bool { return TypeIs(typ, t) }) {
		return ErrOtherExplicitType
	}
	return nil
}
