// Package memstore provides in-memory implementations of every
// storage interface server.Dependencies needs (ClientRepository,
// TransactionStore, GrantStore, ReplayStore, ...) plus client's own
// SessionStore — for local development and testing only. Never
// production.
//
// Every type here is non-durable (an in-process map, gone on restart)
// and grows unboundedly for the life of the process — there is no
// expiry-driven garbage collection. That's fine for a short local
// development session; it is not fine for anything long-running.
//
// None of these types implement storage.StoreAssurance, and that is
// deliberate, not an oversight: server.New, client.New and
// resource.NewVerifier each reject a store that doesn't implement
// StoreAssurance at all under their production assurance level, which
// is exactly what already makes them correctly refuse every type in
// this package there. Adding a StoreAssurance
// declaration here — even one that honestly reports Durable: false —
// would only add a false sense of having addressed production-readiness
// to a package that fundamentally cannot be production-ready. Don't.
package memstore
