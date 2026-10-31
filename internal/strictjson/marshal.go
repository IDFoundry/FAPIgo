package strictjson

import (
	"bytes"
	"encoding/json"
)

// MarshalUnescaped is json.Marshal without its HTML escaping: '<', '>'
// and '&' stay as they are, in a string or a json.RawMessage v holds,
// rather than becoming \u003c, \u003e and \u0026. That escaping only
// guards JSON pasted into an HTML <script>, and each escape is six bytes
// for one, so JSON a client sent within a size bound and re-encoded with
// json.Marshal can come back over it, and carry bytes other than the
// ones checked. Re-encoding validated JSON with MarshalUnescaped keeps it
// as it was, but for insignificant whitespace and U+2028 and U+2029,
// which encoding/json escapes whatever the setting (in a
// json.RawMessage too, from Go 1.27).
func MarshalUnescaped(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
