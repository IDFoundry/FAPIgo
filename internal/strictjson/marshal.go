package strictjson

import (
	"bytes"
	"encoding/json"
)

// MarshalUnescaped is json.Marshal without its HTML escaping: '<', '>'
// and '&' stay as they are rather than becoming \u003c, \u003e and
// \u0026, in a string or a json.RawMessage v holds, and in a
// json.RawMessage so do U+2028 and U+2029 rather than becoming \u2028
// and \u2029. That escaping only guards JSON pasted into an HTML
// <script>, and each escape is six bytes for one or three, so JSON a
// client sent within a size bound and re-encoded with json.Marshal can
// come back over it, and carry bytes other than the ones checked.
// Re-encoding validated JSON with MarshalUnescaped keeps it as it was,
// but for insignificant whitespace.
func MarshalUnescaped(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
