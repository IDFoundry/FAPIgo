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
	// can never both succeed. For a store used by one process only — a
	// native app's own session store — a mutex around the read and the
	// delete gives that. A store other processes also open (an app
	// extension or widget sharing the app's data container) needs what
	// holds across processes: a file lock, or the database's own
	// transaction.
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

	// SingleUserAgent means a client.SessionStore holds only the
	// authorizations begun by the one user agent it serves: a native
	// app's own on-device storage, say, which nothing else writes. A
	// session found by a callback's state was then begun by the user
	// agent the callback reached, which is what binding the session
	// handle to the user agent establishes (RFC 9700 §4.7), so the
	// client may take the session from the callback itself
	// (client.AuthorizationCallback.Session left empty). Never declare it
	// for a store shared by many users' sessions — a web application's
	// database, a server-side cache — where an attacker's own session is
	// also found by its state, and the binding is what refuses it.
	SingleUserAgent bool
}
