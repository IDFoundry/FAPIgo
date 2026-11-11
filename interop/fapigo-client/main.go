// Command fapigo-client is the interop suite's driver for FAPIgo's
// client package: it runs complete FAPI 2.0 flows, one named leg each,
// against an independent authorization server, using the client
// package's public API the way an integrator would.
//
//	fapigo-client -config driver.json [-leg name]
//
// The configuration (see runConfig) names the issuer, the CA its TLS
// certificate chains to, and each leg's client registration; the
// suite's runner writes it (interop/run-oidc-provider.sh,
// interop/run-keycloak.sh). It exits
// non-zero if any leg fails.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/idfoundry/fapigo/client"
)

// legTimeout bounds one leg, CIBA polling included.
const legTimeout = 60 * time.Second

// cibaPingLeg is the leg that needs the notification endpoint served.
const cibaPingLeg = "ciba-ping"

type leg struct {
	name        string
	description string
	run         func(context.Context, run) error
}

var legs = []leg{
	{"code-pkjwt-dpop", "authorization code + PAR + PKCE + private_key_jwt + DPoP; ID token, UserInfo, refresh", codeDPoP},
	{"code-mtls-mtls", "authorization code + PAR + PKCE + mutual-TLS client authentication + certificate-bound tokens (mTLS aliases); UserInfo, refresh", codeMTLS},
	{"message-signing", "JAR via PAR + JARM + private_key_jwt + DPoP; UserInfo, refresh", messageSigning},
	{"client-credentials", "client_credentials + private_key_jwt + DPoP (+ resource indicator where configured)", clientCredentials},
	{"ciba-poll", "CIBA poll + private_key_jwt + certificate-bound tokens; UserInfo", cibaPoll},
	{cibaPingLeg, "CIBA ping + private_key_jwt + certificate-bound tokens; UserInfo", cibaPing},
}

func main() {
	configPath := flag.String("config", "", "the driver configuration the runner wrote")
	only := flag.String("leg", "", "run only this leg")
	flag.Parse()
	log.SetFlags(0)
	if *configPath == "" {
		log.Fatal("usage: fapigo-client -config driver.json [-leg name]")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if !runLegs(cfg, *only) {
		os.Exit(1)
	}
}

func runLegs(cfg runConfig, only string) bool {
	notifications := make(chan client.BackchannelNotification, 1)
	if _, ok := cfg.Legs[cibaPingLeg]; ok && (only == "" || only == cibaPingLeg) {
		stop, err := serveNotifications(cfg.Notification, notifications)
		if err != nil {
			log.Printf("FAIL %s: notification endpoint: %v", cibaPingLeg, err)
			return false
		}
		defer stop()
	}

	passed, ran := true, 0
	for i, l := range legs {
		if only != "" && l.name != only {
			continue
		}
		ran++
		label := fmt.Sprintf("%d %s (%s)", i+1, l.name, l.description)
		legCfg, ok := cfg.Legs[l.name]
		switch {
		case !ok:
			log.Printf("FAIL %s: no client configured for this leg", label)
			passed = false
		case legCfg.Skip != "":
			log.Printf("SKIP %s: %s", label, legCfg.Skip)
		default:
			ctx, cancel := context.WithTimeout(context.Background(), legTimeout)
			start := time.Now()
			err := l.run(ctx, run{cfg: cfg, leg: legCfg, notifications: notifications})
			cancel()
			if err != nil {
				log.Printf("FAIL %s: %v", label, err)
				passed = false
			} else {
				log.Printf("PASS %s [%s]", label, time.Since(start).Round(time.Millisecond))
			}
		}
	}
	if ran == 0 {
		log.Printf("FAIL: no leg named %q", only)
		return false
	}
	return passed
}

// serveNotifications serves the CIBA ping leg's
// client_notification_endpoint over HTTPS, with a certificate from the
// run's test CA.
func serveNotifications(cfg notificationConfig, notifications chan<- client.BackchannelNotification) (func(), error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler:           notificationHandler(notifications),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go func() {
		if err := server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("notification endpoint: %v", err)
		}
	}()
	return func() { _ = server.Close() }, nil
}
