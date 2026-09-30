package federation

import (
	"encoding/json"
	"testing"
)

func TestApplySuperiorMetadataEdgeCases(t *testing.T) {
	superior := map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"client_name":"x"}`)}

	// No superior metadata: the subject's own, unchanged.
	subject := map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"client_name":"own"}`)}
	if got, err := applySuperiorMetadata(subject, nil); err != nil || string(got["openid_relying_party"]) != `{"client_name":"own"}` {
		t.Errorf("no superior metadata = %v, %v; want the subject's own", got, err)
	}
	// The subject declares the Entity Type with a null value: the
	// superior's parameters become its metadata.
	got, err := applySuperiorMetadata(map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`null`)}, superior)
	if err != nil || string(got["openid_relying_party"]) != `{"client_name":"x"}` {
		t.Errorf("null subject metadata = %v, %v; want the superior's parameters", got, err)
	}
	// The subject's own value for the type isn't an object.
	if _, err := applySuperiorMetadata(map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`[1]`)}, superior); err == nil {
		t.Error("subject metadata not an object = nil error, want error")
	}
}
