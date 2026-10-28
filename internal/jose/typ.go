package jose

import (
	"errors"
	"slices"
	"strings"
)

// ErrOtherExplicitType reports a JWT whose "typ" names a different,
// explicitly typed kind of JWT than the one being parsed.
var ErrOtherExplicitType = errors.New("jose: header typ names another kind of JWT")

// ErrUnexpectedType reports a JWT whose "typ" is neither absent, the
// generic "JWT", nor the media type of the kind being parsed.
var ErrUnexpectedType = errors.New(`jose: header typ is neither absent, "JWT", nor the expected media type`)

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

// RequireGenericType returns ErrUnexpectedType unless typ is absent or
// the generic "JWT" (RFC 7519 §5.1, which the OpenID Foundation
// conformance suite sends), compared as TypeIs compares, so
// "application/jwt" and "jwt" are accepted too. It is the allow-list
// for the kinds whose specifications leave "typ" optional and register
// no media type of their own — ID tokens, JARM responses, signed
// UserInfo responses — so a JWT that says it is anything else,
// including a kind this library has never heard of (an SD-JWT, a status
// list token) or a known type with parameters RefuseOtherExplicitType's
// list wouldn't match ("at+jwt; charset=x"), isn't taken for one of
// these (RFC 8725 §3.11).
func RequireGenericType(typ string) error {
	if typ == "" || TypeIs(typ, "JWT") {
		return nil
	}
	return ErrUnexpectedType
}

// RefuseOtherExplicitType returns ErrOtherExplicitType when typ names an
// explicitly typed kind of JWT other than own. It is for the kinds whose
// specifications leave "typ" optional but which may also carry a media
// type of their own — client assertions — so a missing or generic typ
// ("JWT") is accepted, but a token that says it is something else isn't
// taken for one of these: a client's request object offered as its
// client assertion, say (RFC 8725 §3.11).
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
