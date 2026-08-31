package dpop

import "testing"

func TestResolveHeaderValues(t *testing.T) {
	tests := []struct {
		name      string
		values    []string
		wantProof string
		wantOK    bool
	}{
		{name: "absent", values: nil, wantProof: "", wantOK: true},
		{name: "single", values: []string{"proof-1"}, wantProof: "proof-1", wantOK: true},
		{name: "duplicated", values: []string{"proof-1", "proof-2"}, wantProof: "", wantOK: false},
		{name: "three", values: []string{"proof-1", "proof-2", "proof-3"}, wantProof: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, ok := ResolveHeaderValues(tt.values)
			if proof != tt.wantProof || ok != tt.wantOK {
				t.Errorf("ResolveHeaderValues(%v) = (%q, %v), want (%q, %v)", tt.values, proof, ok, tt.wantProof, tt.wantOK)
			}
		})
	}
}
