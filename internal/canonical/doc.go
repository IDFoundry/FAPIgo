// Package canonical implements shared canonicalization rules — URL/URI
// canonicalization, JSON canonicalization where required for signature
// input, and parameter-ordering/normalization — so client, server and
// resource agree byte-for-byte on what they are signing, verifying or
// comparing.
//
// Divergent canonicalization between roles is a common source of
// signature-verification and replay-detection bugs; keeping exactly one
// implementation here is what prevents that class of bug rather than
// merely reducing it.
package canonical
