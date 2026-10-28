package resource

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/pairwise"
)

// Limits bounds the clock tolerances this verifier enforces for DPoP
// proof verification — format-independent, unlike the JWT-specific
// concerns (issuer, audience, algorithm, max token lifetime) that
// moved into JWTAccessTokens itself; see its own doc comment. None of
// these have an implicit default — NewVerifier rejects a zero (or, for
// MaxClockSkew, negative) value, and a zero DPoPNonceLifetime when
// Dependencies.Nonces is set.
type Limits struct {
	// MaxDPoPProofAge bounds how old (relative to verification time) a
	// DPoP proof's iat claim may be. At most 5 minutes under
	// AssuranceProduction (RFC 9449 §11.1).
	MaxDPoPProofAge time.Duration

	// MaxClockSkew bounds how far in the future an iat claim may be, and
	// extends how long past a token's own expiry it's still accepted.
	// Zero means no tolerance. AssuranceProduction requires 10 to 60
	// seconds, as server.New does: FAPI 2.0 Security Profile §5.3.2.1
	// has a JWT with iat up to 10 seconds in the future accepted.
	MaxClockSkew time.Duration

	// DPoPNonceLifetime bounds how long an issued DPoP nonce remains
	// valid. Required only when Dependencies.Nonces is non-nil — see
	// its own doc comment; NewVerifier rejects a zero value in that
	// case, exactly like MaxDPoPProofAge above, but leaves it
	// unvalidated when nonce-challenge support is disabled. At most 15
	// minutes under AssuranceProduction, set or not.
	DPoPNonceLifetime time.Duration
}

// Config is this verifier's immutable configuration. It is copied by
// NewVerifier; mutating a Config after passing it to NewVerifier has no
// effect.
type Config struct {
	Limits Limits

	// ResourceURLs are this resource server's own external URLs, as
	// clients call it: each an origin ("https://api.example"),
	// optionally with a path prefix ("https://api.example/accounts"),
	// parsed with fapi.ParseEndpointURL and carrying no query. Required.
	//
	// A DPoP proof's htu must name the URL a request was made to (RFC
	// 9449 §4.3), and only this resource server knows its own: the
	// request's Host header, and the path a front end forwards it under,
	// are the client's to choose. For a request built by
	// VerifyRequestFromHTTP, Verify takes the target to be the request's
	// escaped path (never its decoded one, which names another resource
	// when a segment holds "%2F") at each origin here whose path prefix
	// covers it, and refuses a request no prefix covers. An explicit
	// VerifyRequest.URL must be under one of them too. Several origins
	// serve one resource server reachable under more than one name, an
	// mTLS alias host among them; a proof naming any of them is
	// accepted. A URL parsed with fapi.AllowLoopbackHTTP is refused
	// under AssuranceProduction.
	ResourceURLs []fapi.URL

	// Assurance is how strictly NewVerifier checks Dependencies; see
	// AssuranceLevel. Required: the zero value is refused.
	Assurance AssuranceLevel

	// Deployment says whether this verifier runs as one instance or as
	// a fleet sharing the storage tier; see Deployment. Required under
	// AssuranceProduction, where DeploymentHorizontallyScaled also
	// requires every store AssuranceProduction checks to declare
	// storage.Capabilities.CrossInstanceConsistent. May be left zero
	// under AssuranceDevelopment, where it's ignored.
	Deployment Deployment

	// PairwisePrefix is the authorization server's
	// Config.Subjects.Prefix, which Verify strips from a pairwise sub
	// before looking it up (Dependencies.PairwiseSubjects). Required
	// with Dependencies.PairwiseSubjects, and must be left zero
	// without it.
	PairwisePrefix pairwise.Prefix

	// PairwiseResolution is what Verify does with a pairwise sub; see
	// PairwiseResolution. The zero value maps it back to the end user
	// through Dependencies.PairwiseSubjects or
	// Dependencies.PairwiseSubjectResolver, as the OpenID Provider's own
	// resource servers do; PairwiseClientSubjectsOnly is for a resource
	// server outside the OP, which must never hold what reverses a
	// pairwise sub.
	PairwiseResolution PairwiseResolution
}
