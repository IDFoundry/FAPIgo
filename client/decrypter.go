package client

import (
	"context"

	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
)

// decrypterUnwrapper adapts a keys.Decrypter to internal/jwe.Unwrapper,
// so this client's own ID-token decryption key can be used with
// internal/jwe without this package ever holding — or internal/jwe
// ever being handed — the private key itself. The decryption-side
// counterpart of keyManagerSigner. It is never handed to a caller.
type decrypterUnwrapper struct {
	decrypter keys.Decrypter
	purpose   keys.DecryptionPurpose
}

// UnwrapCEK implements internal/jwe.Unwrapper.
func (u decrypterUnwrapper) UnwrapCEK(ctx context.Context, header jwe.Header, encryptedKey []byte) ([]byte, error) {
	return u.decrypter.UnwrapContentEncryptionKey(ctx, keys.UnwrapRequest{
		Purpose: u.purpose, Algorithm: header.Algorithm, KeyID: header.KeyID, EncryptedKey: encryptedKey,
		EphemeralPublicKey:  header.EphemeralPublicKey,
		AgreementPartyUInfo: header.AgreementPartyUInfo, AgreementPartyVInfo: header.AgreementPartyVInfo,
	})
}
