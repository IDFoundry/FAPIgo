// Command payroll-run runs the payroll-run demo: a payroll provider pays
// a company's staff through its bank's API, server to server, with
// mutual TLS client authentication, certificate-bound access tokens and
// a Rich Authorization Request checked against a standing mandate — and
// an attack lab that tries to get around each of those.
//
//	go run ./cmd/payroll-run -open
//
// With -open it starts Chrome on the console, in a separate profile
// (state/chrome-profile) that accepts the demo's certificate — and only
// that one — without a warning.
//
// It keeps the demo CA and TLS certificate in a state directory (-state,
// default .payroll-state), so a browser told to trust the CA once stays
// that way; -reset starts over with a new one. Everything else — keys,
// registrations, client certificates, runs — is in memory and starts fresh each run.
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

	"github.com/idfoundry/fapigo/examples/internal/demokit"
	"github.com/idfoundry/fapigo/examples/payroll-run/payroll"
)

// caName is the demo CA's name, as a browser's trust store shows it.
const caName = "Payroll run demo CA"

func main() {
	// Not 8443 (a locally running OIDF conformance suite), nor 8643 to
	// 8645 (the other example demos), so all four can run at once.
	port := flag.Int("port", 8646, "HTTPS port every demo host is served on")
	state := flag.String("state", ".payroll-state", "directory the demo CA and TLS certificate are kept in")
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
	if err := run(ctx, *port, *state, *open, *chrome); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, port int, state string, open bool, chrome string) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	n, err := demokit.New(addr, payroll.Hosts(), state, caName)
	if err != nil {
		return err
	}
	world, err := payroll.New(port, n)
	if err != nil {
		return fmt.Errorf("build the demo: %w", err)
	}
	listeners, err := demokit.Listen(port)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: world.Handler(), TLSConfig: n.ServerTLS(payroll.ClientCertificateHosts()...), ReadHeaderTimeout: 10 * time.Second}
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
	printBanner(console, caPath, open)
	if open {
		if err := demokit.OpenChrome(chrome, state, n.ServingSPKIHash(), console); err != nil {
			log.Printf("-open: %v", err)
		}
	}

	select {
	case <-ctx.Done():
	case err = <-failed:
	}
	// ctx is already cancelled by now: shut down with its values, not
	// its cancellation.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return err
}

func printBanner(console, caPath string, opened bool) {
	browser := `Opening it in Chrome, in a separate profile that accepts the demo's
certificate without a warning. Use that window for the whole demo.
(Chrome's banner about an unsupported command-line flag is expected.)`
	if !opened {
		browser = `Run with -open to get a Chrome window that accepts the demo's
certificate without a warning.`
	}
	fmt.Printf(`
Payroll run demo is running (Ctrl-C to stop)

  console   %s   start here

%s

For any other browser, trust the demo CA once. It can only vouch for
*.localhost, and is kept across runs (see the README to remove it):
  %s

`, console, browser, demokit.TrustCommand(caPath, caName))
}
