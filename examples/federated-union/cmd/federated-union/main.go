// Command federated-union runs the Meridian Union demo: three fictional
// countries' identity federations joined into one OpenID Federation.
//
//	go run ./cmd/federated-union -open
//
// With -open it starts Chrome on the console, in a separate profile
// (state/chrome-profile) that accepts the demo's certificate — and only
// that one — without a warning.
//
// It keeps the demo CA and TLS certificate in a state directory (-state,
// default .union-state), so a browser told to trust the CA once stays
// that way; -reset starts over with a new one. Everything else — keys,
// registrations, sign-ins — is in memory and starts fresh each run.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/idfoundry/fapigo/examples/federated-union/union"
	"github.com/idfoundry/fapigo/examples/internal/demokit"
)

// caName is the demo CA's name, as a browser's trust store shows it.
const caName = "Meridian Union demo CA"

func main() {
	// Not 8443: a locally running OIDF conformance suite uses that.
	port := flag.Int("port", 8643, "HTTPS port every demo host is served on")
	state := flag.String("state", ".union-state", "directory the demo CA and TLS certificate are kept in")
	reset := flag.Bool("reset", false, "delete the state directory first, issuing a new CA")
	open := flag.Bool("open", false, "open the console in Chrome, in a separate profile that accepts the demo's certificate (no warnings)")
	chrome := flag.String("chrome", "", "with -open: the Chrome or Chromium executable (default: look in the usual places)")
	flag.Parse()

	if *reset {
		if err := os.RemoveAll(*state); err != nil {
			log.Fatalf("reset %s: %v", *state, err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, options{port: *port, state: *state, open: *open, chrome: *chrome}); err != nil {
		log.Fatal(err)
	}
}

// options are the command-line choices run acts on.
type options struct {
	port   int
	state  string
	open   bool   // open Chrome on the console once listening
	chrome string // Chrome's path, when not in the usual places
}

func run(ctx context.Context, opts options) error {
	port, state := opts.port, opts.state
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	n, err := demokit.New(addr, union.Hosts(), state, caName)
	if err != nil {
		return err
	}
	world, err := union.New(port, n)
	if err != nil {
		return fmt.Errorf("build the union: %w", err)
	}
	listeners, err := demokit.Listen(port)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: world.Handler(), TLSConfig: n.ServerTLS(), ReadHeaderTimeout: 10 * time.Second}
	failed := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func() {
			if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
				failed <- err
			}
		}()
	}

	console := world.URL("console.localhost", "/")
	caPath, err := filepath.Abs(n.CAPath())
	if err != nil {
		return err
	}
	printBanner(world, console, caPath, opts.open)
	if opts.open {
		if err := demokit.OpenChrome(opts.chrome, state, n.ServingSPKIHash(), console); err != nil {
			log.Printf("-open: %v", err)
		}
	}

	select {
	case <-ctx.Done():
	case err = <-failed:
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return err
}

func printBanner(world *union.World, console, caPath string, opened bool) {
	browser := `Opening it in Chrome, in a separate profile that accepts the demo's
certificate without a warning. Use that window for the whole demo.
(Chrome's banner about an unsupported command-line flag is expected.)`
	if !opened {
		browser = `Run with -open to get a Chrome window that accepts the demo's
certificate without a warning.`
	}
	fmt.Printf(`
Meridian Union demo is running (Ctrl-C to stop)

  console   %s   start here
  services  %s
            %s

%s

For any other browser, trust the demo CA once. It can only vouch for
*.localhost, and is kept across runs (see the README to remove it):
  %s

`, console, world.URL("bank.southport.localhost", "/"), world.URL("telco.eastmark.localhost", "/"),
		browser, demokit.TrustCommand(caPath, caName))
}
