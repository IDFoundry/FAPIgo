package pairwise

import "errors"

// ErrSubjectNotFound is what a Lookup's error wraps when no internal
// subject's body under the issuer and sector is the one asked for: a
// sub this deployment never issued to that sector, or an altered one.
// Any other error means the lookup couldn't be answered (an unreachable
// store, say), and a caller must not read it as "no such subject".
var ErrSubjectNotFound = errors.New("pairwise: no subject has this body")

// errZeroInput is a Deriver's answer to the zero Input, which NewInput
// never returns.
var errZeroInput = errors.New("pairwise: input is the zero Input (use NewInput)")
