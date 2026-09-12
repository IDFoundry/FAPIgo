package federation

import (
	"crypto"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// signClaims marshals claims and signs them as a compact JWT with the
// given typ/kid — the "marshal payload, build header, sign" tail every
// JWT this package creates (an Entity Statement, a Trust Mark, a Trust
// Mark Delegation, a Trust Mark Status Response) ends with, once its
// own claim-shape-specific validation and map-building is done.
// Extracted once two near-identical copies of this tail (Create's own
// and createTrustMarkLikeJWT's) tripped SonarCloud's duplication gate
// in PR #274 — shared here up front rather than risking a third copy.
func signClaims(signer crypto.Signer, algorithm fapi.SignatureAlgorithm, keyID, typ string, claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("federation: marshal claims: %w", err)
	}
	header := jose.Header{Algorithm: algorithm, Type: typ, KeyID: keyID}
	token, err := jose.Sign(signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("federation: %w", err)
	}
	return token, nil
}
