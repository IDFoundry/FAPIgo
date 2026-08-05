package server

// AssuranceLevel gates how strict New's validation of Config and
// Dependencies is.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment permits a configuration meant for local
	// development only — most importantly, it does not require an
	// AuditSink.
	AssuranceDevelopment

	// AssuranceProduction rejects a configuration missing anything this
	// module considers necessary for a real deployment. Today that means
	// requiring Dependencies.Audit; further checks (store durability and
	// atomicity capabilities, HSM-backed keys where required) will be
	// added here as the mechanisms to check them are built.
	AssuranceProduction
)
