package federation

import "encoding/json"

// federationEntityType is the Entity Type Identifier every federation
// participant's own operational metadata (fetch/list/resolve endpoints,
// organization info) is published under (OpenID Federation 1.0
// §5.1.1) — distinct from openid_provider/openid_relying_party/etc.,
// which describe the protocol-specific role an entity plays, not its
// federation membership itself.
const federationEntityType = "federation_entity"

// entityMetadata is the subset of an Entity's federation_entity
// metadata this package's own Resolve/CheckTrustMarkStatus need — just
// enough to walk a Trust Chain and query a Trust Mark Status endpoint,
// not a general-purpose federation_entity metadata type. A caller that
// needs the rest (organization_name, contacts, ...) reads
// Claims.Metadata["federation_entity"] directly.
type entityMetadata struct {
	FetchEndpoint           string `json:"federation_fetch_endpoint"`
	TrustMarkStatusEndpoint string `json:"federation_trust_mark_status_endpoint"`
}

// parseEntityMetadata extracts federation_entity metadata from
// metadata (an Entity Statement's own Claims.Metadata), returning the
// zero value if the entity declared no federation_entity metadata at
// all — an Entity Configuration with no Subordinates has no fetch
// endpoint to publish, which is a normal shape, not an error; Resolve
// itself decides whether a missing FetchEndpoint is fatal (it needs
// one on every Intermediate/Trust Anchor it walks through, but never
// on the leaf subject itself).
func parseEntityMetadata(metadata map[string]json.RawMessage) (entityMetadata, error) {
	raw, ok := metadata[federationEntityType]
	if !ok {
		return entityMetadata{}, nil
	}
	var m entityMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return entityMetadata{}, err
	}
	return m, nil
}
