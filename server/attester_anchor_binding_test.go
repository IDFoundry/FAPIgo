package server_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const otherAttesterIssuer = "https://attester-a.example.com"

// boundChain is X5CAttesterChain with AttesterIssuerBoundToAnchor over
// anchors.
func boundChain(anchors server.StaticAttesterAnchors) server.X5CAttesterChain {
	return server.X5CAttesterChain{Anchors: anchors, IssuerBinding: server.AttesterIssuerBoundToAnchor}
}

// TestCrossAttesterViaOwnCA is the case AttesterIssuerBoundToAnchor
// exists for: two attesters' own CAs share one anchor pool, and attester
// A's CA issues a certificate naming attester B (the client's attester).
// AttesterIssuerInCertificate can't tell — the certificate does name B —
// but bound to anchors, A's root vouches only for A.
func TestCrossAttesterViaOwnCA(t *testing.T) {
	rootA := newTestCert(t, "attester A CA", certOptions{isCA: true})
	rootB := newTestCert(t, "attester B CA", certOptions{isCA: true})
	forged := newTestCert(t, "A posing as B", certOptions{parent: &rootA, uris: []string{testAttesterIssuer}})

	for name, tc := range map[string]struct {
		trust  server.X5CAttesterChain
		wantOK bool
	}{
		"issuer in certificate accepts it (shared pool)": {server.X5CAttesterChain{
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(rootA, rootB)},
			IssuerBinding: server.AttesterIssuerInCertificate,
		}, true},
		"bound to anchor refuses it": {boundChain(server.StaticAttesterAnchors{
			{Certificate: rootA.cert, Issuers: []string{otherAttesterIssuer}},
			{Certificate: rootB.cert, Issuers: []string{testAttesterIssuer}},
		}), false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, tc.trust)
			instanceKey := generateKey(t)
			err := requestWithAttestation(t, h, createX5CAttestation(t, forged.key, x5cOf(forged), "", &instanceKey.PublicKey, h.now), instanceKey)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q (%v), want %q", code, err, server.ErrorInvalidClient)
			}
		})
	}
}

// TestAttesterIssuerBoundToAnchor covers the mode's accepting and
// refusing cases with a pool shared by two attesters.
func TestAttesterIssuerBoundToAnchor(t *testing.T) {
	rootA := newTestCert(t, "attester A CA", certOptions{isCA: true})
	rootB := newTestCert(t, "attester B CA", certOptions{isCA: true})
	intermediateB := newTestCert(t, "attester B issuing CA", certOptions{parent: &rootB, isCA: true})
	shared := newTestCert(t, "trust list CA for A and B", certOptions{isCA: true})

	anchors := server.StaticAttesterAnchors{
		{Certificate: rootA.cert, Issuers: []string{otherAttesterIssuer}},
		{Certificate: rootB.cert, Issuers: []string{testAttesterIssuer}},
		{Certificate: shared.cert, Issuers: []string{otherAttesterIssuer, testAttesterIssuer}},
	}
	for name, tc := range map[string]struct {
		leaf   func() (testCert, []testCert)
		wantOK bool
	}{
		"B's root, certificate names B": {func() (testCert, []testCert) {
			l := newTestCert(t, "B", certOptions{parent: &rootB, uris: []string{testAttesterIssuer}})
			return l, []testCert{l}
		}, true},
		"B's intermediate, certificate names B": {func() (testCert, []testCert) {
			l := newTestCert(t, "B", certOptions{parent: &intermediateB, uris: []string{testAttesterIssuer}})
			return l, []testCert{l, intermediateB}
		}, true},
		"anchor bound to several attesters": {func() (testCert, []testCert) {
			l := newTestCert(t, "B", certOptions{parent: &shared, uris: []string{testAttesterIssuer}})
			return l, []testCert{l}
		}, true},
		"B's root, certificate names no attester": {func() (testCert, []testCert) {
			l := newTestCert(t, "B", certOptions{parent: &rootB})
			return l, []testCert{l}
		}, false},
		"A's root, certificate names B": {func() (testCert, []testCert) {
			l := newTestCert(t, "A posing as B", certOptions{parent: &rootA, uris: []string{testAttesterIssuer}})
			return l, []testCert{l}
		}, false},
		"untrusted root": {func() (testCert, []testCert) {
			stranger := newTestCert(t, "stranger CA", certOptions{isCA: true})
			l := newTestCert(t, "B", certOptions{parent: &stranger, uris: []string{testAttesterIssuer}})
			return l, []testCert{l}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, boundChain(anchors))
			leaf, chain := tc.leaf()
			instanceKey := generateKey(t)
			err := requestWithAttestation(t, h, createX5CAttestation(t, leaf.key, x5cOf(chain...), "", &instanceKey.PublicKey, h.now), instanceKey)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q (%v), want %q", code, err, server.ErrorInvalidClient)
			}
		})
	}
}

// anchorSource is a custom AttesterAnchorSource, implementing only that
// interface: it returns anchors, or fails.
type anchorSource struct {
	anchors []server.AttesterAnchor
	err     error
}

func (f anchorSource) AttesterAnchors(context.Context, storage.RegisteredClient) ([]server.AttesterAnchor, error) {
	return f.anchors, f.err
}

// boundTrustAnchors implements both AttesterTrustAnchors and
// AttesterAnchorSource: a type whose bindings TrustAnchors would drop,
// which New refuses as TrustAnchors.
type boundTrustAnchors struct{ cert *x509.Certificate }

func (b boundTrustAnchors) TrustAnchors(context.Context, storage.RegisteredClient) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pool.AddCert(b.cert)
	return pool, nil
}

func (b boundTrustAnchors) AttesterAnchors(context.Context, storage.RegisteredClient) ([]server.AttesterAnchor, error) {
	return []server.AttesterAnchor{{Certificate: b.cert, Issuers: []string{testAttesterIssuer}}}, nil
}

// TestCustomAttesterAnchorSource covers a source of the application's
// own, implementing only AttesterAnchorSource.
func TestCustomAttesterAnchorSource(t *testing.T) {
	rootB := newTestCert(t, "attester B CA", certOptions{isCA: true})
	leaf := newTestCert(t, "B", certOptions{parent: &rootB, uris: []string{testAttesterIssuer}})
	h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{
		Anchors:       anchorSource{anchors: []server.AttesterAnchor{{Certificate: rootB.cert, Issuers: []string{testAttesterIssuer}}}},
		IssuerBinding: server.AttesterIssuerBoundToAnchor,
	})
	instanceKey := generateKey(t)
	if err := requestWithAttestation(t, h, createX5CAttestation(t, leaf.key, x5cOf(leaf), "", &instanceKey.PublicKey, h.now), instanceKey); err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
}

// TestAttesterAnchorSourceFailures covers a dynamic source that errors,
// returns nothing, or returns an unusable anchor: each rejects the
// attestation.
func TestAttesterAnchorSourceFailures(t *testing.T) {
	rootB := newTestCert(t, "attester B CA", certOptions{isCA: true})
	leaf := newTestCert(t, "B", certOptions{parent: &rootB, uris: []string{testAttesterIssuer}})
	for name, source := range map[string]anchorSource{
		"error":            {err: errors.New("trust list unavailable")},
		"no anchors":       {},
		"anchor unbound":   {anchors: []server.AttesterAnchor{{Certificate: rootB.cert}}},
		"anchor certless":  {anchors: []server.AttesterAnchor{{Issuers: []string{testAttesterIssuer}}}},
		"empty identifier": {anchors: []server.AttesterAnchor{{Certificate: rootB.cert, Issuers: []string{""}}}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{Anchors: source, IssuerBinding: server.AttesterIssuerBoundToAnchor})
			instanceKey := generateKey(t)
			err := requestWithAttestation(t, h, createX5CAttestation(t, leaf.key, x5cOf(leaf), "", &instanceKey.PublicKey, h.now), instanceKey)
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q (%v), want %q", code, err, server.ErrorInvalidClient)
			}
		})
	}
}

// TestNewAttesterAnchorBindingRequirements covers New's checks for the
// mode: Anchors and only Anchors under AttesterIssuerBoundToAnchor,
// TrustAnchors and only TrustAnchors otherwise, and usable static
// anchors.
func TestNewAttesterAnchorBindingRequirements(t *testing.T) {
	root := newTestCert(t, "attester CA", certOptions{isCA: true})
	cases := map[string]struct {
		trust   server.AttesterTrust
		wantErr bool
	}{
		"static bound anchors":         {boundChain(server.StaticAttesterAnchors{{Certificate: root.cert, Issuers: []string{testAttesterIssuer}}}), false},
		"bound mode without Anchors":   {server.X5CAttesterChain{IssuerBinding: server.AttesterIssuerBoundToAnchor}, true},
		"bound mode with TrustAnchors": {server.X5CAttesterChain{TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(root)}, IssuerBinding: server.AttesterIssuerBoundToAnchor}, true},
		"bound mode with both fields": {server.X5CAttesterChain{
			Anchors:       server.StaticAttesterAnchors{{Certificate: root.cert, Issuers: []string{testAttesterIssuer}}},
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
			IssuerBinding: server.AttesterIssuerBoundToAnchor,
		}, true},
		"custom source": {server.X5CAttesterChain{Anchors: anchorSource{}, IssuerBinding: server.AttesterIssuerBoundToAnchor}, false},
		"Anchors under issuer in certificate": {server.X5CAttesterChain{
			Anchors:       server.StaticAttesterAnchors{{Certificate: root.cert, Issuers: []string{testAttesterIssuer}}},
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
			IssuerBinding: server.AttesterIssuerInCertificate,
		}, true},
		"Anchors under trust-anchor binding": {server.X5CAttesterChain{
			Anchors:       server.StaticAttesterAnchors{{Certificate: root.cert, Issuers: []string{testAttesterIssuer}}},
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
			IssuerBinding: server.AttesterIssuerByTrustAnchors,
		}, true},
		"empty static anchors":                                 {boundChain(server.StaticAttesterAnchors{}), true},
		"anchor bound to no attester":                          {boundChain(server.StaticAttesterAnchors{{Certificate: root.cert}}), true},
		"anchor without a certificate":                         {boundChain(server.StaticAttesterAnchors{{Issuers: []string{testAttesterIssuer}}}), true},
		"empty attester identifier":                            {boundChain(server.StaticAttesterAnchors{{Certificate: root.cert, Issuers: []string{""}}}), true},
		"bound anchors as TrustAnchors, issuer in certificate": {server.X5CAttesterChain{TrustAnchors: boundTrustAnchors{root.cert}, IssuerBinding: server.AttesterIssuerInCertificate}, true},
		"bound anchors as TrustAnchors, by trust anchors":      {server.X5CAttesterChain{TrustAnchors: boundTrustAnchors{root.cert}, IssuerBinding: server.AttesterIssuerByTrustAnchors}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies()
			deps.AttesterTrust = tc.trust
			_, err := server.New(validAttestationConfig(t), deps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestStaticAttesterAnchorsIsNotTrustAnchors pins that bound anchors
// can't be set as X5CAttesterChain.TrustAnchors, where their attester
// bindings would be dropped and every anchor would vouch for every
// attester.
func TestStaticAttesterAnchorsIsNotTrustAnchors(t *testing.T) {
	var anchors any = server.StaticAttesterAnchors{}
	if _, ok := anchors.(server.AttesterTrustAnchors); ok {
		t.Fatal("StaticAttesterAnchors implements AttesterTrustAnchors; its bindings would be ignored there")
	}
}
