package fapihttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"weak"
)

// Hardening describes the hardened transport behind an *http.Client
// NewClient built: which of TransportConfig's exceptions it was built
// with. HardeningOf returns it.
type Hardening struct {
	allowsLoopback      bool
	allowedPrivateHosts []string
}

// AllowsLoopback reports whether the transport was built with any of
// TransportConfig's loopback exceptions (TransportConfig.AllowsLoopback).
func (h Hardening) AllowsLoopback() bool {
	return h.allowsLoopback
}

// AllowedPrivateHosts returns a copy of the transport's
// TransportConfig.AllowedPrivateHosts: the hosts it may dial at a
// private address.
func (h Hardening) AllowedPrivateHosts() []string {
	return slices.Clone(h.allowedPrivateHosts)
}

// hardenedTransports records every transport NewClient builds, keyed
// weakly so the record never keeps a transport alive: a cleanup deletes
// the entry once the transport is collected.
var hardenedTransports sync.Map // weak.Pointer[http.Transport] -> hardenedRecord

// hardenedRecord is what NewClient built a transport with.
type hardenedRecord struct {
	hardening  Hardening
	dialerCode uintptr         // the code pointer of the safeDialContext closure
	dialer     *identityMarker // the marker this transport's dialer answers with
}

// identityMarker is a value only one closure NewClient builds holds, so
// HardeningOf can tell which transport's closure it's looking at: Go
// func values can't be compared, and every closure from one function
// literal shares its code. It isn't zero-sized, so distinct markers
// never share an address.
type identityMarker struct{ _ byte }

// identityProbe is the error a closure NewClient built answers an
// identity probe with, carrying its marker.
type identityProbe struct{ marker *identityMarker }

func (identityProbe) Error() string { return "fapihttp: identity probe" }

// identityProbeNetwork is the network HardeningOf dials to probe a
// dialer's identity: one net/http never passes, so the dialer can't
// mistake a real dial for it.
const identityProbeNetwork = "fapihttp-identity-probe"

// registerHardened records t, built by NewClient from cfg, whose dialer
// answers the identity probe with dialer.
func registerHardened(t *http.Transport, cfg TransportConfig, dialer *identityMarker) {
	key := weak.Make(t)
	hardenedTransports.Store(key, hardenedRecord{
		hardening: Hardening{
			allowsLoopback:      cfg.AllowsLoopback(),
			allowedPrivateHosts: slices.Clone(cfg.AllowedPrivateHosts),
		},
		dialerCode: reflect.ValueOf(t.DialContext).Pointer(),
		dialer:     dialer,
	})
	runtime.AddCleanup(t, func(k weak.Pointer[http.Transport]) { hardenedTransports.Delete(k) }, key)
}

// HardeningOf reports whether c sends its requests through a transport
// NewClient built that is still intact, and if so how it was built. A
// production check can refuse an *http.Client it doesn't recognise, and
// one whose Hardening allows more than it should (AllowsLoopback, say).
//
// It recognises a copy of NewClient's *http.Client (one with Timeout,
// CheckRedirect or Jar changed, say), which shares its Transport. It
// doesn't recognise a transport NewClient didn't build: http.Transport's
// Clone, a transport wrapped in another RoundTripper (for
// instrumentation, say), or any other. Those fail closed: false.
//
// A recognised transport counts as intact only while nothing that
// decides where it connects, or how it checks the server, has been
// changed since NewClient built it: its DialContext is still the
// address-validating dialer, Proxy, Dial, DialTLS and DialTLSContext are
// still unset (a proxy, or another dialer, would connect where the
// validation never looked), and TLSClientConfig still requires TLS 1.2
// or later and doesn't skip verification. Adding a client certificate
// (TransportConfig.Certificates, or setting TLSClientConfig.Certificates
// afterwards) changes none of that. The dialer must be this transport's
// own: another NewClient transport's dialer, which may grant different
// exceptions, doesn't count.
func HardeningOf(c *http.Client) (Hardening, bool) {
	if c == nil {
		return Hardening{}, false
	}
	return HardeningOfTransport(c.Transport)
}

// HardeningOfTransport is HardeningOf for a RoundTripper: rt itself must
// be the transport NewClient built, intact.
func HardeningOfTransport(rt http.RoundTripper) (Hardening, bool) {
	t, ok := rt.(*http.Transport)
	if !ok || t == nil {
		return Hardening{}, false
	}
	v, ok := hardenedTransports.Load(weak.Make(t))
	if !ok {
		return Hardening{}, false
	}
	record := v.(hardenedRecord)
	if !transportIntact(t, record) {
		return Hardening{}, false
	}
	return Hardening{
		allowsLoopback:      record.hardening.allowsLoopback,
		allowedPrivateHosts: slices.Clone(record.hardening.allowedPrivateHosts),
	}, true
}

// transportIntact reports whether t still dials only through its own
// address-validating dialer, as record describes, and still verifies
// servers over TLS 1.2 or later.
func transportIntact(t *http.Transport, record hardenedRecord) bool {
	if !isOwnDialer(t.DialContext, record) {
		return false
	}
	if t.Proxy != nil || t.Dial != nil || t.DialTLS != nil || t.DialTLSContext != nil { //nolint:staticcheck // Dial and DialTLS are deprecated, but a caller can still set them
		return false
	}
	return tlsIntact(t.TLSClientConfig)
}

// isOwnDialer reports whether dial is the address-validating closure
// NewClient built for record's transport. Only a closure with that code
// is probed, so no other function is ever called.
func isOwnDialer(dial func(context.Context, string, string) (net.Conn, error), record hardenedRecord) bool {
	if dial == nil || reflect.ValueOf(dial).Pointer() != record.dialerCode {
		return false
	}
	_, err := dial(context.Background(), identityProbeNetwork, "")
	var probe identityProbe
	return errors.As(err, &probe) && probe.marker == record.dialer
}

// tlsIntact reports whether cfg still requires TLS 1.2 or later and
// verifies the server.
func tlsIntact(cfg *tls.Config) bool {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.MinVersion < tls.VersionTLS12 {
		return false
	}
	return cfg.MaxVersion == 0 || cfg.MaxVersion >= tls.VersionTLS12
}
