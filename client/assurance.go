package client

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/depcheck"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// AssuranceLevel gates how strict New's validation of Dependencies is —
// mirrors server.AssuranceLevel exactly, for the identical reason: an
// in-memory Dependencies.Sessions (memstore.NewSessionStore(), the
// obvious first choice for a new integration) has the same
// non-durable, unbounded-growth profile server.New already refuses
// under AssuranceProduction, but client.New previously asked no such
// question at all.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment permits a configuration meant for local
	// development only — most importantly, it does not require
	// Dependencies.Sessions to declare storage.StoreAssurance
	// capabilities.
	AssuranceDevelopment

	// AssuranceProduction rejects a Dependencies.Sessions that doesn't
	// declare storage.StoreAssurance capabilities asserting at least
	// Durable and AtomicConsume. SessionStore.Consume is a single-use
	// check-and-retire operation — the same category
	// server.AssuranceProduction already requires AtomicConsume for
	// (Transactions, Grants, Replay) — so a store that doesn't
	// implement StoreAssurance at all is rejected rather than assumed
	// adequate, exactly like server's own rule. This does not verify
	// the declaration; see storage.StoreAssurance's own doc comment
	// for why a store should also run storage.TestSessionStoreContract
	// against itself. The same "declaring capabilities is not optional"
	// stance applies to Dependencies.IssuerKeys: it must implement
	// keys.KeySourceAssurance and declare LiveFetchHardened — see that
	// interface's own doc comment for why a plain IssuerKeySource has no
	// structural way to tell a hardened implementation from a naive one
	// apart from this declaration. Likewise Dependencies.Keys, and
	// Dependencies.Decryption when set, must implement
	// keys.KeyCustodyAssurance and declare Durable: keys/ephemeral's
	// in-memory keys, regenerated on every restart, never qualify.
	// Dependencies.Random must be crypto/rand.Reader itself: state,
	// nonce, PKCE verifiers and every jti this client signs are only as
	// unguessable as that reader, and nothing about an io.Reader says
	// whether it is a CSPRNG.
	// The issuer and every Endpoints URL must be https (one parsed with
	// fapi.AllowLoopbackHTTP is refused), and ProtectedResource's Do
	// refuses a loopback http resource URL before sending anything. A
	// native app's loopback redirect URI is unaffected.
	// Dependencies.Clock must declare ClockAssurance (SystemClock does),
	// and read within Limits.MaxClockSkew of time.Now when New runs: a
	// fixed or offset test clock would accept what has long expired.
	// Limits must keep to these bounds (RecommendedLimits does, with
	// MaxIDTokenLifetime set to the server's ID token lifetime):
	// MaxClockSkew from 10 to 60 seconds (FAPI 2.0 Security Profile
	// §5.3.2.1, as server.New requires), SessionLifetime at most an
	// hour, ClientAssertionLifetime at most 5 minutes,
	// MaxIDTokenLifetime at most 24 hours (OpenID Providers commonly
	// issue ID tokens for an hour, some for several), and
	// MaxJARMResponseLifetime at most 10 minutes (JARM §2.1).
	AssuranceProduction
)

// checkStoreAssurance requires store to implement storage.StoreAssurance
// and to assert Durable and AtomicConsume — mirrors server's own
// helper of the same name and signature (minus requireAtomicConsume,
// since Sessions is client's only store-shaped dependency and always
// needs it).
func checkStoreAssurance(name string, store any) error {
	asserter, ok := store.(storage.StoreAssurance)
	if !ok {
		return fmt.Errorf("client: dependencies: %s must implement storage.StoreAssurance under AssuranceProduction", name)
	}
	caps := asserter.Capabilities()
	if !caps.Durable {
		return fmt.Errorf("client: dependencies: %s must declare Durable capability under AssuranceProduction", name)
	}
	if !caps.AtomicConsume {
		return fmt.Errorf("client: dependencies: %s must declare AtomicConsume capability under AssuranceProduction", name)
	}
	return nil
}

// checkClock requires clock to declare ClockAssurance, and its reading
// to be within skew of the system's time now.
func checkClock(clock Clock, skew time.Duration) error {
	if !depcheck.ReadsSystemTime(clock) {
		return fmt.Errorf("client: dependencies: clock must be SystemClock, or declare client.ClockAssurance, under AssuranceProduction")
	}
	if offset := depcheck.ClockOffset(clock.Now()); offset > skew {
		return fmt.Errorf("client: dependencies: clock reads %v away from the system's time, more than limits.max_clock_skew (%v), under AssuranceProduction", offset.Round(time.Second), skew)
	}
	return nil
}

// checkRandom requires random to be crypto/rand.Reader itself.
func checkRandom(random io.Reader) error {
	if random != rand.Reader {
		return fmt.Errorf("client: dependencies: random must be crypto/rand.Reader itself under AssuranceProduction: pass it directly, not a wrapper, which nothing can verify reads a CSPRNG")
	}
	return nil
}

// checkKeyCustody requires manager — a keys.KeyManager or
// keys.Decrypter — to implement keys.KeyCustodyAssurance and declare
// Durable, mirroring server's own helper.
func checkKeyCustody(name string, manager any) error {
	asserter, ok := manager.(keys.KeyCustodyAssurance)
	if !ok {
		return fmt.Errorf("client: dependencies: %s must implement keys.KeyCustodyAssurance under AssuranceProduction (keys/ephemeral never does; pass keys.DeclareCustody to keys.NewKeyManagerFromSigners)", name)
	}
	if !asserter.KeyCustody().Durable {
		return fmt.Errorf("client: dependencies: %s must declare Durable key custody under AssuranceProduction", name)
	}
	return nil
}

// checkKeySourceAssurance requires source to implement
// keys.KeySourceAssurance and to declare LiveFetchHardened — mirrors
// server's own helper of the same name and signature.
func checkKeySourceAssurance(name string, source any) error {
	asserter, ok := source.(keys.KeySourceAssurance)
	if !ok {
		return fmt.Errorf("client: dependencies: %s must implement keys.KeySourceAssurance under AssuranceProduction", name)
	}
	if !asserter.Capabilities().LiveFetchHardened {
		return fmt.Errorf("client: dependencies: %s must declare LiveFetchHardened capability under AssuranceProduction", name)
	}
	return nil
}

// checkHTTPHardening requires httpClient to be an *http.Client
// fapihttp.HardeningOf recognises (one from fapihttp.NewClient, or a
// copy of it, with its transport as NewClient built it) that allows no
// loopback address: the endpoints this client calls can come from
// fetched metadata, and only that transport keeps them off internal
// hosts. Its allowed private hosts are an explicit allow-list, and are
// permitted.
func checkHTTPHardening(httpClient fapihttp.HTTPClient) error {
	c, ok := httpClient.(*http.Client)
	if !ok {
		return fmt.Errorf("client: dependencies: http must be an *http.Client from fapihttp.NewClient under AssuranceProduction, not %T (for mutual TLS, set fapihttp.TransportConfig.Certificates)", httpClient)
	}
	hardening, ok := fapihttp.HardeningOf(c)
	if !ok {
		return fmt.Errorf("client: dependencies: http must be an *http.Client from fapihttp.NewClient under AssuranceProduction, with its transport as NewClient built it: no proxy, dialer or TLS verification change, and not cloned or wrapped (for mutual TLS, set fapihttp.TransportConfig.Certificates)")
	}
	if hardening.AllowsLoopback() {
		return fmt.Errorf("client: dependencies: http's transport allows loopback addresses (fapihttp.TransportConfig's loopback fields), which is not permitted under AssuranceProduction")
	}
	return nil
}
