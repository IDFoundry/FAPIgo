module github.com/idfoundry/fapigo/examples/linked-accounts

go 1.26.10

require (
	github.com/idfoundry/fapigo v0.66.0
	github.com/idfoundry/fapigo/examples/internal/demokit v0.0.0-00010101000000-000000000000
	github.com/idfoundry/fapigo/sqlstore v0.0.0-00010101000000-000000000000
	modernc.org/sqlite v1.61.0
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.49.0 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

// The demo always builds against this checkout of the library and its
// sqlstore module, not a published release, so a library change and the
// demo using it land together.
replace (
	github.com/idfoundry/fapigo => ../..
	github.com/idfoundry/fapigo/examples/internal/demokit => ../internal/demokit
	github.com/idfoundry/fapigo/sqlstore => ../../sqlstore
)
