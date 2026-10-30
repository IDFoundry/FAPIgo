-- The Authorization Server's stores. {{key}} is a case-sensitive text
-- type, {{blob}} a binary one, and {name} a table or index name with
-- the DB's prefix. Times are BIGINT Unix nanoseconds. sweep_after is
-- the time after which Sweep deletes a row: the latest instant anything
-- still needs it.

-- Pushed authorization requests (TransactionStore), keyed by the
-- server's digest of the request_uri reference and client_id. consumed
-- is 1 once an interaction begun from it has completed; sweep_after
-- grows to cover the latest interaction begun from it.
CREATE TABLE {par_requests} (
	reference {{key}} PRIMARY KEY,
	client_id {{key}} NOT NULL,
	request {{blob}} NOT NULL,
	expires_at BIGINT NOT NULL,
	consumed INTEGER NOT NULL DEFAULT 0,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {par_requests_sweep} ON {par_requests} (sweep_after);

-- Interactions in progress (TransactionStore), keyed by the server's
-- digest of the interaction handle, each with a copy of its pushed
-- request.
CREATE TABLE {interactions} (
	handle {{key}} PRIMARY KEY,
	reference {{key}} NOT NULL,
	client_id {{key}} NOT NULL,
	request {{blob}} NOT NULL,
	expires_at BIGINT NOT NULL,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {interactions_sweep} ON {interactions} (sweep_after);

-- Authorization codes (GrantStore), keyed by the server's SHA-256
-- digest of the code. redeemed is 1 once redeemed; the row is kept,
-- for reuse detection, until the code and the tokens its redemption
-- issued have all expired.
CREATE TABLE {authorization_codes} (
	code_hash {{blob}} PRIMARY KEY,
	client_id {{key}} NOT NULL,
	record {{blob}} NOT NULL,
	expires_at BIGINT NOT NULL,
	redeemed INTEGER NOT NULL DEFAULT 0,
	issued_access_token_key {{key}},
	issued_refresh_token_hash {{blob}},
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {authorization_codes_sweep} ON {authorization_codes} (sweep_after);

-- Refresh tokens (GrantStore), keyed by the server's SHA-256 digest of
-- the token. Revoking one deletes its row.
CREATE TABLE {refresh_tokens} (
	token_hash {{blob}} PRIMARY KEY,
	client_id {{key}} NOT NULL,
	record {{blob}} NOT NULL,
	expires_at BIGINT NOT NULL,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {refresh_tokens_sweep} ON {refresh_tokens} (sweep_after);

-- Use-once digests (ReplayStore), per namespace.
CREATE TABLE {replay} (
	namespace {{key}} NOT NULL,
	digest {{blob}} NOT NULL,
	sweep_after BIGINT NOT NULL,
	PRIMARY KEY (namespace, digest)
);
CREATE INDEX {replay_sweep} ON {replay} (sweep_after);

-- DPoP nonces (NonceStore), keyed by the nonce.
CREATE TABLE {dpop_nonces} (
	nonce {{key}} PRIMARY KEY,
	expires_at BIGINT NOT NULL,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {dpop_nonces_sweep} ON {dpop_nonces} (sweep_after);

-- Revoked keys (RevocationStore): access token keys, "grant:" and
-- "code-grant:" keys. sweep_after is the latest expiry it was revoked
-- with.
CREATE TABLE {revocations} (
	revocation_key {{key}} PRIMARY KEY,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {revocations_sweep} ON {revocations} (sweep_after);

-- Registered clients (ClientRepository), managed by the operator: one
-- row per client, its configuration a versioned JSON document (see the
-- package documentation). The stores never write it.
CREATE TABLE {clients} (
	client_id {{key}} PRIMARY KEY,
	config {{text}} NOT NULL
);
