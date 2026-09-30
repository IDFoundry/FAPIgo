package federation

import (
	"encoding/json"
	"testing"
)

// TestParseEntityMetadataRejectsCaseVariantMemberNames covers a
// federation_entity member naming a parameter only case-insensitively:
// it is not that parameter, so it must not be read as one.
func TestParseEntityMetadataRejectsCaseVariantMemberNames(t *testing.T) {
	for name, raw := range map[string]string{
		"fetch endpoint":             `{"Federation_Fetch_Endpoint":"https://attacker.example/fetch"}`,
		"trust mark status endpoint": `{"FEDERATION_TRUST_MARK_STATUS_ENDPOINT":"https://attacker.example/status"}`,
	} {
		if m, err := parseEntityMetadata(map[string]json.RawMessage{federationEntityType: json.RawMessage(raw)}); err == nil {
			t.Errorf("parseEntityMetadata(%s) = %+v, nil error; want error", name, m)
		}
	}
	m, err := parseEntityMetadata(map[string]json.RawMessage{federationEntityType: json.RawMessage(`{"federation_fetch_endpoint":"https://ta.example/fetch","organization_name":"TA"}`)})
	if err != nil || m.FetchEndpoint != "https://ta.example/fetch" {
		t.Errorf("parseEntityMetadata(exact names) = %+v, %v; want the fetch endpoint", m, err)
	}
}
