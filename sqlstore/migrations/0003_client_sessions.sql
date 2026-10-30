-- The client's (relying party's) sessions. As in 0001: {{key}} is a
-- case-sensitive text type, {{blob}} a binary one, {name} a table or
-- index name with the DB's prefix, times are BIGINT Unix nanoseconds,
-- and sweep_after is the time after which Sweep deletes a row.

-- In-progress authorization attempts (client SessionStore), keyed by
-- the state the client generated for each. record is the client's
-- opaque versioned JSON session record (its nonce, PKCE verifier,
-- expected issuer, redirect URI and response mode), a blob
-- Options.Sealer seals. A session is deleted when consumed, or swept
-- once it expires.
CREATE TABLE {client_sessions} (
	state {{key}} PRIMARY KEY,
	record {{blob}} NOT NULL,
	expires_at BIGINT NOT NULL,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {client_sessions_sweep} ON {client_sessions} (sweep_after);
