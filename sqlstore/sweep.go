package sqlstore

import (
	"context"
	"time"
)

// sweptTables are the tables whose rows Sweep deletes once past their
// sweep_after.
var sweptTables = []string{
	"par_requests",                // NewPARRecord.ExpiresAt, or a later interaction's
	"interactions",                // BeginAuthorizationTransaction.HandleExpiresAt
	"authorization_codes",         // NewAuthorizationCode.ExpiresAt, or a later issued token's
	"refresh_tokens",              // NewRefreshToken.ExpiresAt
	"replay",                      // ReplayUse.ExpiresAt
	"dpop_nonces",                 // NonceIssuance.ExpiresAt
	"revocations",                 // the latest expiresAt a key was revoked with
	"access_tokens",               // NewAccessToken.ExpiresAt
	"backchannel_authentications", // NewBackchannelAuthentication.ExpiresAt + BackchannelExpiredRetention
}

// Sweep deletes every row that expired before now, from every table
// that has them, and returns how many it deleted. The stores never
// delete an expired row themselves — the server refuses an expired
// record it reads — so run Sweep periodically (every few minutes, say)
// to keep the tables from growing without bound.
//
// A row is kept until everything that may still need it has expired: a
// pushed request until the last interaction begun from it, a redeemed
// authorization code until the tokens its redemption issued (so that
// reusing the code still revokes them, RFC 6749 §4.1.2), and a CIBA
// request until BackchannelExpiredRetention after it expires (so that a
// late poll is told it expired).
//
// Pass the server's own time (server.Dependencies.Clock). Running Sweep
// late only keeps rows longer; passing a time ahead of the server's
// would forget replay digests and revocations the server still relies
// on.
func (d *DB) Sweep(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	for _, name := range sweptTables {
		err := d.writeOne(ctx, func(q querier) error {
			res, err := q.ExecContext(ctx, d.q("DELETE FROM {"+name+"} WHERE sweep_after < ?"), nanos(now))
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			total += n
			return err
		})
		if err != nil {
			return total, unavailable("sweep "+name, err)
		}
	}
	return total, nil
}
