package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ClientCertificateCRLs checks a client certificate (TrustedClientCAs),
// or an attester's signing certificate (X5CAttesterChain), against
// Certificate Revocation Lists (RFC 5280 §5). Every certificate in the
// verified chain below the trust anchor is checked against a CRL its
// issuer signed: the leaf, and any intermediate CA — from
// TrustedClientCAs.Intermediates, or the attestation's "x5c". The trust
// anchor itself, from TrustedClientCAs.Roots or the attester trust
// anchors, is never checked — see TrustedClientCAs.
//
// A list is used for an issuer only when its issuer name matches, its
// signature verifies against that issuer's key, and the check's Now
// falls between its thisUpdate and nextUpdate. A certificate a usable
// list names by serial number is revoked: the error wraps
// ErrCertificateRevoked, refusing the client with invalid_client. A
// certificate whose issuer has no usable list at all, or a Lists that
// fails, can't be decided: that error doesn't wrap it, and refuses the
// request with server_error (500) — a missing or stale CRL fails closed
// rather than letting a revoked certificate through, without telling
// the client its certificate is revoked when nobody knows. Only
// complete, direct CRLs are used: a delta CRL, or one whose issuing
// distribution point extension limits its scope, is never treated as
// complete and is skipped.
type ClientCertificateCRLs struct {
	// Lists returns the current CRLs, at least one from each CA that
	// issues a certificate in the chain: the CA issuing client (or
	// attester) certificates, and the CA above each intermediate. It is called on every check: keep the
	// parsed lists in memory and refresh them in the background before
	// their nextUpdate, rather than fetching here. Required.
	Lists func(ctx context.Context) ([]*x509.RevocationList, error)
}

var (
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// CheckRevocation implements ClientCertificateRevocation.
func (c ClientCertificateCRLs) CheckRevocation(ctx context.Context, check ClientCertificateRevocationCheck) error {
	if c.Lists == nil {
		return errors.New("client certificate CRLs: lists is required")
	}
	lists, err := c.Lists(ctx)
	if err != nil {
		return fmt.Errorf("client certificate CRLs: %w", err)
	}
	for i := 0; i+1 < len(check.Chain); i++ {
		if err := checkAgainstCRLs(check.Chain[i], check.Chain[i+1], lists, check); err != nil {
			return err
		}
	}
	return nil
}

// checkAgainstCRLs reports an error wrapping ErrCertificateRevoked when
// cert is revoked according to a usable CRL from issuer, and a plain
// error when issuer has no usable CRL.
func checkAgainstCRLs(cert, issuer *x509.Certificate, lists []*x509.RevocationList, check ClientCertificateRevocationCheck) error {
	usable := false
	for _, list := range lists {
		if !crlUsableFor(list, issuer, check) {
			continue
		}
		usable = true
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("client certificate CRLs: certificate %q (serial %s): %w", cert.Subject, cert.SerialNumber, ErrCertificateRevoked)
			}
		}
	}
	if !usable {
		return fmt.Errorf("client certificate CRLs: no current CRL from %q", issuer.Subject)
	}
	return nil
}

// crlUsableFor reports whether list is a complete, current CRL that
// issuer signed.
func crlUsableFor(list *x509.RevocationList, issuer *x509.Certificate, check ClientCertificateRevocationCheck) bool {
	if list == nil || !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
		return false
	}
	if list.NextUpdate.IsZero() || check.Now.Before(list.ThisUpdate) || !check.Now.Before(list.NextUpdate) {
		return false
	}
	for _, ext := range list.Extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) || ext.Id.Equal(oidIssuingDistributionPoint) {
			return false
		}
	}
	return list.CheckSignatureFrom(issuer) == nil
}

func (c ClientCertificateCRLs) validate() error {
	if c.Lists == nil {
		return errors.New("client certificate CRLs: lists is required")
	}
	return nil
}
