package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
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
	if !validTextKey(string(id)) {
		return storage.RegisteredClient{}, fmt.Errorf("sqlstore: resolve client: %w", notFound("client"))
	}
	var config []byte
	err := r.d.queryRow(ctx, "SELECT config FROM {clients} WHERE client_id = ?", string(id)).Scan(&config)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.RegisteredClient{}, fmt.Errorf("sqlstore: resolve client %q: %w", id, notFound("client"))
	case err != nil:
		return storage.RegisteredClient{}, unavailable("resolve client", err)
	}
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

// Put registers cfg's client, replacing any client registered under its
// ID. It refuses a configuration storage.NewRegisteredClient refuses,
// or one MarshalClientConfig can't write.
func (r *ClientRepository) Put(ctx context.Context, cfg storage.RegisteredClientConfig) error {
	if _, err := storage.NewRegisteredClient(cfg); err != nil {
		return fmt.Errorf("sqlstore: put client: %w", err)
	}
	if !validTextKey(string(cfg.ID)) {
		return errors.New("sqlstore: put client: client_id isn't valid UTF-8 without NUL")
	}
	config, err := MarshalClientConfig(cfg)
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
