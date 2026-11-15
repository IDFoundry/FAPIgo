-- The grant registry and the CIBA inbox. As in 0001: {{key}} is a
-- case-sensitive text type, {{blob}} a binary one, {name} a table or
-- index name with the DB's prefix, times are BIGINT Unix nanoseconds,
-- and sweep_after is the time after which Sweep deletes a row.

-- Each grant the server issued a refresh token for (storage.GrantRegistry),
-- keyed by the digest of its refresh token the server derives, and
-- listed by subject_key, a digest of the issuer and the end user's
-- subject. record is the server's opaque grant entry, a blob
-- Options.Sealer seals. An entry is deleted when its grant is revoked,
-- or swept once its refresh token expires.
CREATE TABLE {grant_registry} (
	entry_key {{key}} PRIMARY KEY,
	subject_key {{key}} NOT NULL,
	client_id {{key}} NOT NULL,
	record {{blob}} NOT NULL,
	expires_at BIGINT NOT NULL,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {grant_registry_subject} ON {grant_registry} (subject_key, expires_at);
CREATE INDEX {grant_registry_sweep} ON {grant_registry} (sweep_after);

-- Each pending CIBA request filed under the end user its hint names
-- (storage.BackchannelInbox), keyed by its handle hash, as
-- {backchannel_authentications} is, and listed by subject_key. record
-- is the server's opaque inbox entry, which holds the request's
-- backchannel authentication handle: a blob Options.Sealer seals. An
-- entry is deleted once its request is decided, or swept once it
-- expires.
CREATE TABLE {backchannel_inbox} (
	handle_hash {{blob}} PRIMARY KEY,
	subject_key {{key}} NOT NULL,
	client_id {{key}} NOT NULL,
	record {{blob}} NOT NULL,
	expires_at BIGINT NOT NULL,
	sweep_after BIGINT NOT NULL
);
CREATE INDEX {backchannel_inbox_subject} ON {backchannel_inbox} (subject_key, expires_at);
CREATE INDEX {backchannel_inbox_sweep} ON {backchannel_inbox} (sweep_after);
