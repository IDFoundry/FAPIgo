-- Refresh tokens indexed by the grants they were issued from. As in
-- 0001: {{key}} is a case-sensitive text type, {{blob}} a binary one,
-- {name} a table or index name with the DB's prefix, times are BIGINT
-- Unix nanoseconds, and sweep_after is the time after which Sweep
-- deletes a row. Only adds: a release that doesn't know this table
-- keeps working on the tables it does know.

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
