// Command federated-union runs the Meridian Union demo: three fictional
// countries' identity federations joined into one OpenID Federation.
// Open https://console.localhost:8443/ once it's running.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/idfoundry/fapigo/examples/federated-union/internal/demonet"
	"github.com/idfoundry/fapigo/examples/federated-union/union"
)

func main() {
	port := flag.Int("port", 8443, "HTTPS port every demo host is served on")
	caFile := flag.String("ca", "union-ca.pem", "where to write the demo CA certificate, for a browser to trust")
	flag.Parse()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(*port))
	n, err := demonet.New(addr, union.Hosts())
	if err != nil {
		log.Fatalf("demo network: %v", err)
	}
	if err := os.WriteFile(*caFile, n.CAPEM(), 0o600); err != nil {
		log.Fatalf("write %s: %v", *caFile, err)
	}
	world, err := union.New(*port, n)
	if err != nil {
		log.Fatalf("build the union: %v", err)
	}

	srv := &http.Server{Addr: addr, Handler: world.Handler(), TLSConfig: n.ServerTLS(), ReadHeaderTimeout: 10 * time.Second}
	fmt.Printf("Meridian Union demo\n\n  console:  %s\n  services: %s\n            %s\n\nDemo CA written to %s (trust it in your browser, or accept the certificate warning).\n",
		world.URL("console.localhost", "/"), world.URL("bank.southport.localhost", "/"), world.URL("telco.eastmark.localhost", "/"), *caFile)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
