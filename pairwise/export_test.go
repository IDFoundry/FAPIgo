package pairwise

// NewReversibleForVectors is NewReversible without its key-quality
// checks: the published test vectors (testdata/reversible_vectors.json)
// use sequential-byte keys, some of them printable text, which
// NewReversible refuses as a likely passphrase.
var NewReversibleForVectors = newReversible
