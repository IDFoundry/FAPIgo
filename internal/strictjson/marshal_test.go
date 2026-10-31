package strictjson

import (
	"encoding/json"
	"testing"
)

// TestMarshalUnescaped covers what json.Marshal would escape: '<', '>'
// and '&', in a string or a json.RawMessage.
func TestMarshalUnescaped(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want string
	}{
		{"string", "<a>&", `"<a>&"`},
		{"raw message", []json.RawMessage{json.RawMessage(`{"a": "<&>"}`)}, `[{"a":"<&>"}]`},
		{"escaped raw message kept", json.RawMessage(`"\u003c"`), `"\u003c"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalUnescaped(tt.v)
			if err != nil {
				t.Fatalf("MarshalUnescaped: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("MarshalUnescaped = %s, want %s", got, tt.want)
			}
		})
	}
	if _, err := MarshalUnescaped(make(chan int)); err == nil {
		t.Error("MarshalUnescaped(chan) = nil error, want error")
	}
}
