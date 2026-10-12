package pairwise

import "errors"

// errZeroInput is a Deriver's answer to the zero Input, which NewInput
// never returns.
var errZeroInput = errors.New("pairwise: input is the zero Input (use NewInput)")
