package keys

// KeyCustody is what a KeyManager or Decrypter self-declares about how
// its private keys are held — checked by server.AssuranceProduction and
// client.AssuranceProduction the same way storage.StoreAssurance is for
// a store, and for the same reason: nothing about a Sign or
// UnwrapContentEncryptionKey method says whether the key behind it
// survives a restart. keys/ephemeral, which generates keys in memory at
// startup, declares nothing, and is rejected there.
type KeyCustody struct {
	// Durable is true iff the keys survive a process restart: loaded
	// from durable storage, or held by an HSM or KMS. Without it, every
	// restart invalidates every token already signed and every JWKS a
	// relying party has cached — and, for a Decrypter, anything already
	// encrypted to the old key.
	Durable bool

	// CrossInstanceConsistent is true iff every instance of a
	// horizontally scaled deployment uses the same keys, so an artifact
	// one instance signs verifies against the JWKS another serves.
	// Required by server.AssuranceProduction only with
	// server.Config.HorizontallyScaled, as for stores.
	CrossInstanceConsistent bool
}

// KeyCustodyAssurance is the interface a KeyManager or Decrypter
// implementation declares its KeyCustody through. There is no default:
// one that doesn't implement it is rejected under production assurance,
// the same "declaring capabilities is not optional" stance
// KeySourceAssurance and storage.StoreAssurance take. Its method is
// named KeyCustody, not Capabilities, so a type that is also a key
// source can implement both.
type KeyCustodyAssurance interface {
	KeyCustody() KeyCustody
}

// CustodyOption declares the KeyCustody of the keys behind a KeyManager
// or Decrypter built by NewKeyManagerFromSigners, NewDecrypter or
// NewSingleKeyDecrypter — which wrap caller-supplied keys, so only the
// caller knows how they are held.
type CustodyOption func(*KeyCustody)

// DeclareCustody declares custody for a constructor that wraps
// caller-supplied keys — for example
// keys.DeclareCustody(keys.KeyCustody{Durable: true, CrossInstanceConsistent: true})
// for a KMS-backed crypto.Signer every instance shares. It is the
// caller's own assertion; this package can't verify it.
func DeclareCustody(custody KeyCustody) CustodyOption {
	return func(c *KeyCustody) { *c = custody }
}

// custodyDeclaration records a constructor's CustodyOptions; declared
// is false when none was given, so the built value implements
// KeyCustodyAssurance only when the caller actually declared something.
type custodyDeclaration struct {
	custody  KeyCustody
	declared bool
}

func applyCustodyOptions(opts []CustodyOption) custodyDeclaration {
	var d custodyDeclaration
	for _, opt := range opts {
		if opt != nil {
			opt(&d.custody)
			d.declared = true
		}
	}
	return d
}
