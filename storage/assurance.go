package storage

// StoreAssurance is a self-asserted declaration of a storage backend's
// operational guarantees. A storage implementation (ClientRepository,
// TransactionStore, GrantStore, ReplayStore, SessionStore) optionally
// implements it by exposing a Capabilities method; server checks it
// under AssuranceProduction rather than trusting that a store meant for
// a quick prototype (e.g. an in-memory map) is safe to run in
// production.
//
// Because these properties are self-asserted, not verified, a
// downstream (or first-party) implementation should also run the
// reusable contract test suite this package provides — TestGrantStoreContract,
// TestTransactionStoreContract, TestReplayStoreContract and
// TestSessionStoreContract — against its own factory, rather than
// relying on the capability declaration alone. The contract suite
// verifies what's observable through the public interface (the
// single-use/atomic-consume guarantee under concurrency, faithful
// round-tripping of stored fields, replay/duplicate rejection,
// namespace isolation); it cannot verify claims that are specific to a
// backend's own storage technology and invisible at this interface
// (encryption at rest, cross-instance consistency, transactional
// rollback behavior) — verifying those remains the implementation's own
// responsibility.
type StoreAssurance interface {
	Capabilities() Capabilities
}

// Capabilities describes what a storage backend's implementer asserts
// about its operational guarantees.
type Capabilities struct {
	// Durable means state survives a process restart — an in-memory map
	// is not durable.
	Durable bool

	// AtomicConsume means every Consume/Redeem/BeginAuthorization/
	// CompleteAuthorization-style method is a single atomic
	// check-and-retire operation: two concurrent calls for the same key
	// can never both succeed.
	AtomicConsume bool

	// SerializableRedemption means concurrent operations on *different*
	// keys do not observe each other's partial effects — the backend
	// provides at least SERIALIZABLE (or equivalent) isolation for the
	// operations this package's interfaces define.
	SerializableRedemption bool

	// CrossInstanceConsistent means the store is safe to share across
	// multiple server processes/instances (e.g. a shared database, not a
	// per-process in-memory map) — required for any horizontally scaled
	// deployment.
	CrossInstanceConsistent bool

	// EncryptedAtRest means persisted data is encrypted at rest.
	EncryptedAtRest bool
}
