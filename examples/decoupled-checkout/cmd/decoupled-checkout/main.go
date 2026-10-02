// Command decoupled-checkout runs the decoupled-checkout demo: Alder
// Bank's customer approves, on their phone, payments and account access
// started on other devices, with CIBA and Rich Authorization Requests.
//
//	go run ./cmd/decoupled-checkout -open
//
// With -open it starts Chrome on the console, in a separate profile
// (state/chrome-profile) that accepts the demo's certificate — and only
// that one — without a warning.
//
// It keeps the demo CA and TLS certificate in a state directory (-state,
// default .checkout-state), so a browser told to trust the CA once stays
// that way; -reset starts over with a new one. Everything else — keys,
// registrations, requests — is in memory and starts fresh each run.
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

	"github.com/idfoundry/fapigo/examples/decoupled-checkout/checkout"
	"github.com/idfoundry/fapigo/examples/internal/demokit"
)

// caName is the demo CA's name, as a browser's trust store shows it.
const caName = "Decoupled checkout demo CA"

func main() {
	// Not 8443 (a locally running OIDF conformance suite), nor 8643
	// (the federated-union demo), so both demos can run at once.
	port := flag.Int("port", 8644, "HTTPS port every demo host is served on")
	state := flag.String("state", ".checkout-state", "directory the demo CA and TLS certificate are kept in")
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
	n, err := demokit.New(addr, checkout.Hosts(), state, caName)
	if err != nil {
		return err
	}
	world, err := checkout.New(port, n)
	if err != nil {
		return fmt.Errorf("build the demo: %w", err)
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
Decoupled checkout demo is running (Ctrl-C to stop)

  console   %s   start here

%s

For any other browser, trust the demo CA once. It can only vouch for
*.localhost, and is kept across runs (see the README to remove it):
  %s

`, console, browser, demokit.TrustCommand(caPath, caName))
}
