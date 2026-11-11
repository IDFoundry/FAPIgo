module github.com/idfoundry/fapigo/interop/fapigo-client

go 1.26.11

require github.com/idfoundry/fapigo v0.0.0-00010101000000-000000000000

// The driver always builds against this checkout of the library, not a
// published release, so a library change and the interop run against
// it land together.
replace github.com/idfoundry/fapigo => ../..
