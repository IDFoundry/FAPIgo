package server

// NewIssuingPairwiseSubjects is New without the check that refuses a
// configuration in which a client could be pairwise, which stays until
// every token and response carries the pairwise sub: tests exercise
// what's built so far through it.
func NewIssuingPairwiseSubjects(cfg Config, deps Dependencies) (*Server, error) {
	return newServer(cfg, deps, true)
}
