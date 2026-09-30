module github.com/idfoundry/fapigo/examples/decoupled-checkout

go 1.26.6

require (
	github.com/idfoundry/fapigo v0.0.0-00010101000000-000000000000
	github.com/idfoundry/fapigo/examples/internal/demokit v0.0.0-00010101000000-000000000000
)

// The demo always builds against this checkout of the library, not a
// published release, so a library change and the demo using it land
// together.
replace (
	github.com/idfoundry/fapigo => ../..
	github.com/idfoundry/fapigo/examples/internal/demokit => ../internal/demokit
)
