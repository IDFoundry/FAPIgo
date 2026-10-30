-- Opaque access tokens, CIBA requests and pairwise subjects. As in
-- 0001: {{key}} is a case-sensitive text type, {{blob}} a binary one,
-- {name} a table or index name with the DB's prefix, times are BIGINT
-- Unix nanoseconds, and sweep_after is the time after which Sweep
-- deletes a row. record and decision columns are blobs Options.Sealer
-- seals.

-- Opaque access tokens (AccessTokenStore), keyed by the server's
-- SHA-256 digest of the token. record is the token's versioned JSON
-- record (subject, scope, binding, claims).
CREATE TABLE {access_tokens} (
	token_hash {{blob}} PRIMARY KEY,
	client_id {{key}} NOT NULL,
	record {{blob}} NOT NULL,
	expires_at BIGINT NOT NULL,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {access_tokens_sweep} ON {access_tokens} (sweep_after);

-- CIBA backchannel authentication requests
-- (BackchannelAuthenticationStore), keyed by the server's digest of the
-- auth_req_id, and found by the digest of the embedder's handle too.
-- record holds the request, and for ping delivery the auth_req_id and
-- client notification token; decision holds the grant and reason once
-- decided. status is the storage.BackchannelAuthenticationStatus;
-- redeemed is 1 once a poll has observed an approval. last_polled_at is
-- the last counted poll, NULL before the first and after a ping
-- request's decision (whose next poll the interval doesn't apply to);
-- poll_interval is in nanoseconds.
CREATE TABLE {backchannel_authentications} (
	auth_req_id_hash {{blob}} PRIMARY KEY,
	handle_hash {{blob}} NOT NULL UNIQUE,
	client_id {{key}} NOT NULL,
	delivery_mode {{key}} NOT NULL,
	record {{blob}} NOT NULL,
	decision {{blob}} NOT NULL,
	status INTEGER NOT NULL,
	redeemed INTEGER NOT NULL DEFAULT 0,
	poll_interval BIGINT NOT NULL,
	last_polled_at BIGINT,
	expires_at BIGINT NOT NULL,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {backchannel_authentications_sweep} ON {backchannel_authentications} (sweep_after);

-- Pairwise subject identifiers (PairwiseSubjectStore): one body per
-- issuer, sector and internal subject, and each body unique within its
-- issuer and sector. Never swept: a user's identifier for a sector must
-- stay the same for as long as relying parties may hold it.
CREATE TABLE {pairwise_subjects} (
	issuer {{key}} NOT NULL,
	sector {{key}} NOT NULL,
	subject {{key}} NOT NULL,
	body {{key}} NOT NULL,
	PRIMARY KEY (issuer, sector, subject),
	UNIQUE (issuer, sector, body)
);
