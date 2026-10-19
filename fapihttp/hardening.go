package fapihttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	verifyCode uintptr         // the code pointer of the VerifyConnection wrapper, if any
	verifier   *identityMarker // the marker its VerifyConnection answers with; nil when unset
	rootCAs    *x509.CertPool  // TransportConfig.RootCAs; nil for the system's
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

// identityProbeServerName is the server name HardeningOf passes to
// probe a VerifyConnection's identity: a NUL can't appear in a host
// name, so no real handshake carries it.
const identityProbeServerName = "\x00fapihttp-identity-probe"

// verifyConnectionWith wraps verify so it answers the identity probe
// with marker, and otherwise runs verify.
func verifyConnectionWith(marker *identityMarker, verify func(tls.ConnectionState) error) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if cs.ServerName == identityProbeServerName {
			return identityProbe{marker: marker}
		}
		return verify(cs)
	}
}

// identityProbeNetwork is the network HardeningOf dials to probe a
// dialer's identity: one net/http never passes, so the dialer can't
// mistake a real dial for it.
const identityProbeNetwork = "fapihttp-identity-probe"

// registerHardened records t, built by NewClient from cfg, whose dialer
// answers the identity probe with dialer, and its VerifyConnection (when
// cfg set one) with verifier.
func registerHardened(t *http.Transport, cfg TransportConfig, dialer, verifier *identityMarker) {
	key := weak.Make(t)
	record := hardenedRecord{
		hardening: Hardening{
			allowsLoopback:      cfg.AllowsLoopback(),
			allowedPrivateHosts: slices.Clone(cfg.AllowedPrivateHosts),
		},
		dialerCode: reflect.ValueOf(t.DialContext).Pointer(),
		dialer:     dialer,
		verifier:   verifier,
		rootCAs:    cfg.RootCAs,
	}
	if verifier != nil {
		record.verifyCode = reflect.ValueOf(t.TLSClientConfig.VerifyConnection).Pointer()
	}
	hardenedTransports.Store(key, record)
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
// changed since NewClient built it:
//   - its DialContext is still its own address-validating dialer
//     (another NewClient transport's dialer, which may grant different
//     exceptions, doesn't count), and Proxy, Dial, DialTLS and
//     DialTLSContext are still unset: a proxy, or another dialer, would
//     connect where the validation never looked;
//   - TLSClientConfig still requires TLS 1.2 or later, verifies the
//     server against the RootCAs it was built with
//     (TransportConfig.RootCAs, or the system's), with the
//     VerifyConnection it was built with (or none), has no
//     VerifyPeerCertificate, ServerName, Time or KeyLogWriter set, and
//     offers under TLS 1.2 only the ECDHE AES-GCM cipher suites
//     NewClient set (FAPI-CIBA §7.9), or some of them.
//
// Adding a client certificate (TransportConfig.Certificates, or setting
// TLSClientConfig.Certificates afterwards) changes none of that. Nor can
// Transport.RegisterProtocol route "https" or "http" requests anywhere
// else: NewClient has both taken, so registering either panics.
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
	return tlsIntact(t.TLSClientConfig, record)
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

// tlsIntact reports whether cfg still verifies the server as NewClient
// set it up to, over TLS 1.2 or later: certificate verification on,
// against the same roots, with the same VerifyConnection (or none), no
// fixed server name or clock, no secure-cipher-suite override, and no
// key log.
func tlsIntact(cfg *tls.Config, record hardenedRecord) bool {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.MinVersion < tls.VersionTLS12 {
		return false
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS12 {
		return false
	}
	// VerifyPeerCertificate and ServerName change what is verified, Time
	// when, and KeyLogWriter writes out every session's keys.
	if cfg.VerifyPeerCertificate != nil || cfg.ServerName != "" || cfg.Time != nil || cfg.KeyLogWriter != nil {
		return false
	}
	if cfg.RootCAs != record.rootCAs || !onlyPermittedCipherSuites(cfg.CipherSuites) {
		return false
	}
	return isOwnVerifier(cfg.VerifyConnection, record)
}

// isOwnVerifier reports whether verify is the VerifyConnection NewClient
// set for record's transport: nil when TransportConfig set none, and
// otherwise its own wrapper. Only a closure with the wrapper's code is
// probed, so no other function is ever called.
func isOwnVerifier(verify func(tls.ConnectionState) error, record hardenedRecord) bool {
	if record.verifier == nil {
		return verify == nil
	}
	if verify == nil || reflect.ValueOf(verify).Pointer() != record.verifyCode {
		return false
	}
	var probe identityProbe
	return errors.As(verify(tls.ConnectionState{ServerName: identityProbeServerName}), &probe) && probe.marker == record.verifier
}

// onlyPermittedCipherSuites reports whether suites names at least one
// TLS 1.2 cipher suite and only ones in tls12CipherSuites. An empty list
// is Go's default, which offers CBC suites too.
func onlyPermittedCipherSuites(suites []uint16) bool {
	if len(suites) == 0 {
		return false
	}
	for _, suite := range suites {
		if !slices.Contains(tls12CipherSuites, suite) {
			return false
		}
	}
	return true
}
