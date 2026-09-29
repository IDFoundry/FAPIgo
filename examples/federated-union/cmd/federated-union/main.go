// Command federated-union runs the Meridian Union demo: three fictional
// countries' identity federations joined into one OpenID Federation.
//
//	go run ./cmd/federated-union -open
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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/idfoundry/fapigo/examples/federated-union/internal/demonet"
	"github.com/idfoundry/fapigo/examples/federated-union/union"
)

func main() {
	port := flag.Int("port", 8443, "HTTPS port every demo host is served on")
	state := flag.String("state", ".union-state", "directory the demo CA and TLS certificate are kept in")
	reset := flag.Bool("reset", false, "delete the state directory first, issuing a new CA")
	open := flag.Bool("open", false, "open the console in the default browser once running")
	flag.Parse()

	if *reset {
		if err := os.RemoveAll(*state); err != nil {
			log.Fatalf("reset %s: %v", *state, err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *port, *state, *open); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, port int, state string, open bool) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	n, err := demonet.New(addr, union.Hosts(), state)
	if err != nil {
		return err
	}
	world, err := union.New(port, n)
	if err != nil {
		return fmt.Errorf("build the union: %w", err)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: world.Handler(), TLSConfig: n.ServerTLS(), ReadHeaderTimeout: 10 * time.Second}
	failed := make(chan error, 1)
	go func() {
		if err := srv.ServeTLS(listener, "", ""); !errors.Is(err, http.ErrServerClosed) {
			failed <- err
		}
	}()

	console := world.URL("console.localhost", "/")
	caPath, err := filepath.Abs(n.CAPath())
	if err != nil {
		return err
	}
	printBanner(world, console, caPath, n.ServingSPKIHash())
	if open {
		if err := openBrowser(console); err != nil {
			log.Printf("open %s: %v", console, err)
		}
	}

	select {
	case <-ctx.Done():
	case err = <-failed:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return err
}

func printBanner(world *union.World, console, caPath, spki string) {
	fmt.Printf(`
Meridian Union demo is running (Ctrl-C to stop)

  console   %s   start here
  services  %s
            %s

Every page is served with one certificate from the demo CA, which can
only vouch for *.localhost. Either:

  trust the CA once (kept across runs; see the README to remove it):
    %s

  or open a throwaway Chrome profile that accepts just this certificate:
    %s

`, console, world.URL("bank.southport.localhost", "/"), world.URL("telco.eastmark.localhost", "/"),
		trustCommand(caPath), chromeCommand(console, spki))
}

// trustCommand adds the demo CA to the current user's trust store.
func trustCommand(caPath string) string {
	switch runtime.GOOS {
	case "darwin":
		return fmt.Sprintf("security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db %q", caPath)
	case "windows":
		return fmt.Sprintf("certutil -user -addstore Root %q", caPath)
	default:
		return fmt.Sprintf("certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n \"Meridian Union demo CA\" -i %q", caPath)
	}
}

// chromeCommand starts Chrome with a fresh profile that accepts the
// certificate whose key hashes to spki, and nothing else it would
// otherwise reject. Chrome only honours that flag with its own
// --user-data-dir.
func chromeCommand(url, spki string) string {
	flags := "--ignore-certificate-errors-spki-list=" + spki
	switch runtime.GOOS {
	case "darwin":
		return fmt.Sprintf(`open -na "Google Chrome" --args --user-data-dir="$(mktemp -d)" %s %s`, flags, url)
	case "windows":
		return fmt.Sprintf(`start chrome --user-data-dir="%%TEMP%%\union-chrome" %s %s`, flags, url)
	default:
		return fmt.Sprintf(`google-chrome --user-data-dir="$(mktemp -d)" %s %s`, flags, url)
	}
}

// openBrowser opens url, the demo's own console URL, with the
// platform's default handler.
func openBrowser(url string) error {
	name, args := "xdg-open", []string{url}
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	}
	return exec.Command(name, args...).Start() //nolint:gosec // G204: a fixed opener and the demo's own URL, never user input
}
