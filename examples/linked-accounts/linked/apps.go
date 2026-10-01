package linked

import (
	"context"
	"encoding/json"
	"sync"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

// customer is one of Alder Bank's customers.
type customer struct {
	username, pin, name string
	accounts            []bankAccount
}

type bankAccount struct {
	IBAN, Name string
	Balance    string
	// Transactions are the account's recent transactions, newest first.
	Transactions []transaction
}

type transaction struct {
	Date, Description, Amount string
}

var customers = []customer{{
	username: "sam", pin: "2468", name: "Sam Rivera",
	accounts: []bankAccount{
		{IBAN: "XA21ALDR00001234567890", Name: "Everyday", Balance: "1,284.17", Transactions: []transaction{
			{"28 Sep", "Harbour Coffee", "-4.80"}, {"27 Sep", "Northgate Outfitters", "-129.00"}, {"25 Sep", "Salary", "+2,150.00"},
		}},
		{IBAN: "XA87ALDR00009876543210", Name: "Savings", Balance: "8,450.00", Transactions: []transaction{
			{"01 Sep", "Transfer from Everyday", "+300.00"},
		}},
		{IBAN: "XA43ALDR00005555222211", Name: "Joint with Alex", Balance: "642.90", Transactions: []transaction{
			{"26 Sep", "Grocer & Co", "-86.40"},
		}},
	},
}}

func customerByName(username string) (customer, bool) {
	for _, c := range customers {
		if c.username == username {
			return c, true
		}
	}
	return customer{}, false
}

func (c customer) account(iban string) (bankAccount, bool) {
	for _, a := range c.accounts {
		if a.IBAN == iban {
			return a, true
		}
	}
	return bankAccount{}, false
}

// app is a client registered at Alder Bank: Pocketwise, or Thriftly —
// another budgeting app with its own valid credentials, which the attack
// lab borrows.
type app struct {
	clientID fapi.ClientID
	name     string
	// keys signs the app's client assertions and DPoP proofs.
	keys     keys.KeyManager
	authJWKS json.RawMessage
}

const (
	pocketwiseClientID fapi.ClientID = "pocketwise"
	thriftlyClientID   fapi.ClientID = "thriftly"
)

type apps struct{ pocketwise, thriftly app }

func (w *World) newApps() (apps, error) {
	pocketwise, err := newApp(pocketwiseClientID, "Pocketwise")
	if err != nil {
		return apps{}, err
	}
	thriftly, err := newApp(thriftlyClientID, "Thriftly")
	if err != nil {
		return apps{}, err
	}
	return apps{pocketwise: pocketwise, thriftly: thriftly}, nil
}

func newApp(id fapi.ClientID, name string) (app, error) {
	km, err := newAppKeys()
	if err != nil {
		return app{}, err
	}
	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{{Manager: km, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256}}, nil)
	if err != nil {
		return app{}, err
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		return app{}, err
	}
	return app{clientID: id, name: name, keys: km, authJWKS: jwks}, nil
}

// newAppKeys is a client assertion key and a DPoP key.
func newAppKeys() (*ephemeral.KeyManager, error) {
	return ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAuthentication: fapi.ES256, keys.DPoPProofSigning: fapi.ES256,
	})
}

// rotatingDPoPKeys is an app's key manager whose DPoP key can be
// replaced while its client assertion key stays: a confidential client
// may rotate its DPoP key at any time (RFC 9449 §5), and the next token
// it gets is bound to the new one.
type rotatingDPoPKeys struct {
	base keys.KeyManager

	mu   sync.Mutex
	dpop keys.KeyManager
}

func (r *rotatingDPoPKeys) current(purpose keys.SigningPurpose) keys.KeyManager {
	if purpose != keys.DPoPProofSigning {
		return r.base
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dpop == nil {
		return r.base
	}
	return r.dpop
}

// Sign implements keys.KeyManager.
func (r *rotatingDPoPKeys) Sign(ctx context.Context, req keys.SigningRequest) (keys.Signature, error) {
	return r.current(req.Purpose).Sign(ctx, req)
}

// PublicKey implements keys.KeyManager.
func (r *rotatingDPoPKeys) PublicKey(ctx context.Context, purpose keys.SigningPurpose, alg fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return r.current(purpose).PublicKey(ctx, purpose, alg)
}

// rotate replaces the DPoP key.
func (r *rotatingDPoPKeys) rotate() error {
	next, err := newAppKeys()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dpop = next
	return nil
}
