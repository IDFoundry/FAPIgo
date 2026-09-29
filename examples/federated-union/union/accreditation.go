package union

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
)

// accreditation is a country's accreditation body: the only entity the
// Union recognises as able to certify that country's identity provider
// at a high level of assurance.
type accreditation struct {
	entity *entity
	issuer *federation.TrustMarkIssuer
	markTy string
}

func (w *World) newAccreditation(c country, ta *entity) (*accreditation, error) {
	host := "accreditation." + c.key + ".localhost"
	key, err := newSigningKey(c.key+"-accreditation-1", keys.FederationEntitySigning)
	if err != nil {
		return nil, err
	}
	e := &entity{
		id: w.entityID(host), host: host, name: c.name + " Accreditation Office", role: "accreditation body",
		country: c.key, key: key, authorityHints: []string{ta.id},
	}
	if err := w.add(e); err != nil {
		return nil, err
	}
	issuer, err := federation.NewTrustMarkIssuer(federation.TrustMarkIssueConfig{EntityID: e.id},
		federation.TrustMarkIssueDependencies{Signer: key.signer, Algorithm: fapi.ES256, KeyID: key.kid, Clock: federation.SystemClock{}})
	if err != nil {
		return nil, err
	}
	return &accreditation{entity: e, issuer: issuer, markTy: w.loaHighType}, nil
}

// certify issues a fresh level-of-assurance-high Trust Mark about
// subject.
func (a *accreditation) certify(subject string) (federation.RawTrustMark, error) {
	jwt, err := a.issuer.TrustMark(federation.TrustMarkParams{Subject: subject, TrustMarkType: a.markTy, Lifetime: time.Hour})
	if err != nil {
		return federation.RawTrustMark{}, err
	}
	return federation.RawTrustMark{TrustMarkType: a.markTy, TrustMark: jwt}, nil
}
