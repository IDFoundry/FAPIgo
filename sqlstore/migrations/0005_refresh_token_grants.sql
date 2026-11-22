-- Refresh tokens indexed by the grants they were issued from, and
-- marked revoked. As in 0001: {{key}} is a case-sensitive text type,
-- {{blob}} a binary one, {name} a table or index name with the DB's
-- prefix, times are BIGINT Unix nanoseconds, and sweep_after is the
-- time after which Sweep deletes a row. Only adds: a release that
-- doesn't know this table or column keeps working on the tables it
-- does know.

-- One row for each refresh token and each of its grant keys
-- (storage.NewRefreshToken.GrantKeys: digests the server derives from
-- its issuer and a grant's ID), so revoking a grant revokes its refresh
-- tokens (storage.GrantRefreshTokenRevoker). A row is swept once its
-- token expires.
CREATE TABLE {refresh_token_grants} (
	grant_key {{key}} NOT NULL,
	token_hash {{blob}} NOT NULL,
	sweep_after BIGINT NOT NULL,
	PRIMARY KEY (grant_key, token_hash)
);
CREATE INDEX {refresh_token_grants_sweep} ON {refresh_token_grants} (sweep_after);

-- revoked is 1 for a tombstone: the row RevokeRefreshToken writes under
-- a hash it found no token to delete for, so a token stored under it
-- later can't be (the primary key refuses it) and is never redeemed. A
-- tombstone's record is the one byte 3, a sealed record's format byte
-- with nothing after it, which no release opens, and its expires_at the
-- earliest time there is; it's swept an hour after it's written.
ALTER TABLE {refresh_tokens} ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
