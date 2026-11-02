package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// ClientRepository is a storage.ClientRepository:
// server.Dependencies.Clients. It reads the clients table, which the
// operator manages — with Put and Delete, or with SQL writing each
// client's configuration as the JSON document MarshalClientConfig
// produces (see the package documentation). The server never writes
// it.
type ClientRepository struct{ d *DB }

// Clients returns d's storage.ClientRepository.
func (d *DB) Clients() *ClientRepository { return &ClientRepository{d} }

// ResolveClient implements storage.ClientRepository: the client in the
// row whose client_id is exactly id (compared byte for byte), built
// with storage.NewRegisteredClient from its configuration on every
// call, so a change to the table takes effect on the next request. An
// unknown id is an error wrapping ErrNotFound; a row whose
// configuration doesn't parse, or that NewRegisteredClient refuses, is
// the operator's mistake rather than the client's, so its error wraps
// ErrClientConfig and storage.ErrStoreUnavailable, and the server
// answers it with 500 server_error rather than invalid_client.
func (r *ClientRepository) ResolveClient(ctx context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	config, err := r.config(ctx, "resolve client", id)
	if err != nil {
		return storage.RegisteredClient{}, err
	}
	return resolveRow(id, config)
}

// config is the configuration document of the client registered as
// id, for op: an error wrapping ErrNotFound for an unknown id.
func (r *ClientRepository) config(ctx context.Context, op string, id fapi.ClientID) ([]byte, error) {
	if !validTextKey(string(id)) {
		return nil, fmt.Errorf("sqlstore: %s: %w", op, notFound("client"))
	}
	var config []byte
	err := r.d.queryRow(ctx, "SELECT config FROM {clients} WHERE client_id = ?", string(id)).Scan(&config)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("sqlstore: %s %q: %w", op, id, notFound("client"))
	case err != nil:
		return nil, unavailable(op, err)
	}
	return config, nil
}

// resolveRow is the client registered as id with configuration config,
// as ResolveClient builds it.
func resolveRow(id fapi.ClientID, config []byte) (storage.RegisteredClient, error) {
	cfg, err := ParseClientConfig(id, config)
	if err != nil {
		return storage.RegisteredClient{}, fmt.Errorf("sqlstore: resolve client %q: %w: %w", id, storage.ErrStoreUnavailable, err)
	}
	client, err := storage.NewRegisteredClient(cfg)
	if err != nil {
		return storage.RegisteredClient{}, fmt.Errorf("sqlstore: resolve client %q: %w: %w: %w", id, storage.ErrStoreUnavailable, ErrClientConfig, err)
	}
	return client, nil
}

// All returns every registered client, in client_id order, as
// ResolveClient builds each: a row that doesn't make a valid client
// yields its error (wrapping ErrClientConfig) in place of the client,
// and the iteration goes on. A failure to read the table is yielded
// once, last. It reads the rows before yielding any, so the loop may
// use the database. Run server.Server.CheckClientRegistration over it
// at startup, to find a client the server can't honour before its
// first request does:
//
//	for client, err := range db.Clients().All(ctx) {
//		if err == nil {
//			err = srv.CheckClientRegistration(client)
//		}
//		if err != nil {
//			return err
//		}
//	}
func (r *ClientRepository) All(ctx context.Context) iter.Seq2[storage.RegisteredClient, error] {
	return func(yield func(storage.RegisteredClient, error) bool) {
		ids, configs, err := r.rows(ctx)
		for i, id := range ids {
			if !yield(resolveRow(id, configs[i])) {
				return
			}
		}
		if err != nil {
			yield(storage.RegisteredClient{}, unavailable("list clients", err))
		}
	}
}

// rows reads every row of the clients table, in client_id order, and
// any error that stopped it.
func (r *ClientRepository) rows(ctx context.Context) ([]fapi.ClientID, [][]byte, error) {
	rows, err := r.d.db.QueryContext(ctx, r.d.q("SELECT client_id, config FROM {clients} ORDER BY client_id")) // NOSONAR: go:S2077 — a constant query of this package's; q substitutes only the validated TablePrefix.
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	var (
		ids     []fapi.ClientID
		configs [][]byte
	)
	for rows.Next() {
		var (
			id     string
			config []byte
		)
		if err := rows.Scan(&id, &config); err != nil {
			return ids, configs, err
		}
		ids = append(ids, fapi.ClientID(id))
		configs = append(configs, config)
	}
	return ids, configs, rows.Err()
}

// Put registers cfg's client with no keys in the clients table,
// replacing any client registered under its ID, keys included: use
// PutWithKeys for a client whose keys DB.ClientKeys serves. It refuses
// a configuration storage.NewRegisteredClient refuses, or one
// MarshalClientConfig can't write. Run
// server.Server.CheckClientRegistration on the client too, for what
// only the server can check.
func (r *ClientRepository) Put(ctx context.Context, cfg storage.RegisteredClientConfig) error {
	return r.PutWithKeys(ctx, cfg, ClientKeyRegistration{})
}

// PutWithKeys is Put for a client whose keys the clients table holds
// too, for DB.ClientKeys: its jwks_uri, or its inline JWK Set. It
// refuses what MarshalClientConfigWithKeys refuses. The keys take
// effect on the next request, as the configuration does.
func (r *ClientRepository) PutWithKeys(ctx context.Context, cfg storage.RegisteredClientConfig, reg ClientKeyRegistration) error {
	if _, err := storage.NewRegisteredClient(cfg); err != nil {
		return fmt.Errorf("sqlstore: put client: %w", err)
	}
	if !validTextKey(string(cfg.ID)) {
		return errors.New("sqlstore: put client: client_id isn't valid UTF-8 without NUL")
	}
	config, err := MarshalClientConfigWithKeys(cfg, reg)
	if err != nil {
		return fmt.Errorf("sqlstore: put client: %w", err)
	}
	err = r.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, r.d.q("INSERT INTO {clients} (client_id, config) VALUES (?, ?) ON CONFLICT (client_id) DO UPDATE SET config = excluded.config"),
			string(cfg.ID), string(config))
		return err
	})
	if err != nil {
		return unavailable("put client", err)
	}
	return nil
}

// Delete removes the client registered as id, reporting whether there
// was one.
func (r *ClientRepository) Delete(ctx context.Context, id fapi.ClientID) (bool, error) {
	if !validTextKey(string(id)) {
		return false, nil
	}
	var n int64
	err := r.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, r.d.q("DELETE FROM {clients} WHERE client_id = ?"), string(id))
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return false, unavailable("delete client", err)
	}
	return n > 0, nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (r *ClientRepository) Capabilities() storage.Capabilities { return r.d.capabilities() }

// ClientKeys returns a keys.ClientJWKSSource serving each client's keys
// from its row of the clients table — its jwks_uri or jwks member
// (ClientKeyRegistration) — for server.Dependencies.ClientKeys (and
// ClientEncryptionKeys), so the clients table is the one registry of
// clients and their keys: a client PutWithKeys registers, or whose keys
// it changes, is served its keys on the next request, with no restart.
// The source reads the row on every resolution; it parses an inline
// JWK Set once per distinct set, and fetches a jwks_uri through
// fetcher, caching it as keys.ClientJWKSSource describes (opts tune
// that). fetcher may be nil when no client registers a jwks_uri; under
// server.AssuranceProduction, a fetcher must be
// fapihttp.Client.HardenedForProduction (see
// keys.ClientJWKSSource.Capabilities). An unknown client is an error
// wrapping ErrNotFound; a row whose keys don't parse, one wrapping
// ErrClientConfig and storage.ErrStoreUnavailable.
func (d *DB) ClientKeys(fetcher *fapihttp.Client, opts ...keys.ClientJWKSOption) (*keys.ClientJWKSSource, error) {
	r := d.Clients()
	return keys.NewClientJWKSSource(fetcher, r.lookupKeys, opts...)
}

// lookupKeys is ClientKeys' keys.ClientJWKSLookup.
func (r *ClientRepository) lookupKeys(ctx context.Context, id fapi.ClientID) (fapi.URL, []byte, error) {
	config, err := r.config(ctx, "client keys", id)
	if err != nil {
		return fapi.URL{}, nil, err
	}
	reg, err := ParseClientKeys(config)
	if err != nil {
		return fapi.URL{}, nil, fmt.Errorf("sqlstore: client keys %q: %w: %w", id, storage.ErrStoreUnavailable, err)
	}
	return reg.JWKSURI, reg.JWKS, nil
}
