package server

// BoundAuthReqIDPreimage is the string backchannelAuthReqIDHash takes
// the digest of for authReqID bound, at a server of issuer, to
// instanceKey and dpopJKT: what a test presents as an auth_req_id, as
// an attacker would, hoping its digest as an unbound auth_req_id is the
// bound request's. collides reports whether it is; the length-prefixed
// binding keeps it from being.
func BoundAuthReqIDPreimage(issuer, authReqID, instanceKey, dpopJKT string) (preimage string, collides bool) {
	preimage = backchannelAuthReqIDHashPrefix + lengthPrefixed(issuer) + lengthPrefixed(instanceKey) + lengthPrefixed(dpopJKT) + authReqID
	return preimage, backchannelAuthReqIDHash(issuer, preimage, "", "") == backchannelAuthReqIDHash(issuer, authReqID, instanceKey, dpopJKT)
}
