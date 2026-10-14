package fapihttp

import (
	"crypto/tls"
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
	hardening Hardening
	dialer    uintptr // the code pointer of its safeDialContext dialer
}

// registerHardened records t, built by NewClient from cfg.
func registerHardened(t *http.Transport, cfg TransportConfig) {
	key := weak.Make(t)
	hardenedTransports.Store(key, hardenedRecord{
		hardening: Hardening{
			allowsLoopback:      cfg.AllowsLoopback(),
			allowedPrivateHosts: slices.Clone(cfg.AllowedPrivateHosts),
		},
		dialer: reflect.ValueOf(t.DialContext).Pointer(),
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
// afterwards) changes none of that. The dialer check compares code, not
// closures: it can't tell this transport's dialer from another
// NewClient transport's, which validates addresses just the same but
// may grant different exceptions.
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
	if !transportIntact(t, record.dialer) {
		return Hardening{}, false
	}
	return Hardening{
		allowsLoopback:      record.hardening.allowsLoopback,
		allowedPrivateHosts: slices.Clone(record.hardening.allowedPrivateHosts),
	}, true
}

// transportIntact reports whether t still dials only through its
// address-validating dialer (whose code pointer is dialer) and still
// verifies servers over TLS 1.2 or later.
func transportIntact(t *http.Transport, dialer uintptr) bool {
	if t.DialContext == nil || reflect.ValueOf(t.DialContext).Pointer() != dialer {
		return false
	}
	if t.Proxy != nil || t.Dial != nil || t.DialTLS != nil || t.DialTLSContext != nil { //nolint:staticcheck // Dial and DialTLS are deprecated, but a caller can still set them
		return false
	}
	return tlsIntact(t.TLSClientConfig)
}

// tlsIntact reports whether cfg still requires TLS 1.2 or later and
// verifies the server.
func tlsIntact(cfg *tls.Config) bool {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.MinVersion < tls.VersionTLS12 {
		return false
	}
	return cfg.MaxVersion == 0 || cfg.MaxVersion >= tls.VersionTLS12
}
