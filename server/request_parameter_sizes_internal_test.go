package server

import "testing"

// TestBackchannelParameterSizesCoverEveryCoreParameter: every core
// parameter a backchannel authentication request stores is bounded,
// either in backchannelParameterSizes or by the check of its own that
// the table's doc comment names, so a core parameter added later can't
// go unbounded unnoticed.
func TestBackchannelParameterSizesCoverEveryCoreParameter(t *testing.T) {
	boundElsewhere := map[string]bool{
		"scope": true, "binding_message": true, "client_notification_token": true,
		"claims": true, "authorization_details": true,
	}
	listed := map[string]bool{}
	for _, ps := range backchannelParameterSizes {
		if _, core := coreBackchannelAuthenticationParameters[ps.name]; !core {
			t.Errorf("%s is bounded, but isn't a core parameter", ps.name)
		}
		listed[ps.name] = true
	}
	for name := range coreBackchannelAuthenticationParameters {
		if listed[name] == boundElsewhere[name] {
			t.Errorf("%s: in backchannelParameterSizes %t, bounded elsewhere %t; want exactly one", name, listed[name], boundElsewhere[name])
		}
	}
}
