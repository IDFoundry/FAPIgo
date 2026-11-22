package server

import "strconv"

// BoundAuthReqIDPreimage is the string backchannelAuthReqIDHash takes
// the digest of for authReqID bound to instanceKey and dpopJKT, for a
// test to present as an auth_req_id, as an attacker would. ok reports
// that the string's own unbound digest is that bound one, which is what
// makes it worth presenting.
func BoundAuthReqIDPreimage(authReqID, instanceKey, dpopJKT string) (preimage string, ok bool) {
	preimage = backchannelAuthReqIDHashPrefix +
		strconv.Itoa(len(instanceKey)) + ":" + instanceKey +
		strconv.Itoa(len(dpopJKT)) + ":" + dpopJKT + authReqID
	return preimage, backchannelAuthReqIDHash(preimage, "", "") == backchannelAuthReqIDHash(authReqID, instanceKey, dpopJKT)
}
