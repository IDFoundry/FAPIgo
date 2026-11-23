package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
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
// signature verifies against that issuer's key, the check's Now falls
// between its thisUpdate and nextUpdate, and it is a complete, direct
// CRL this type can read (below); any other list is skipped, as if
// Lists hadn't returned it. A certificate a usable list names by serial
// number is revoked: the error wraps ErrCertificateRevoked, refusing the
// client with invalid_client. A certificate whose issuer has no usable
// list at all, or a Lists that fails, can't be decided: that error
// doesn't wrap it, and refuses the request with server_error (500) — a
// missing, stale or unreadable CRL fails closed rather than letting a
// revoked certificate through, without telling the client its
// certificate is revoked when nobody knows.
//
// A delta CRL, or one whose issuing distribution point extension limits
// its scope, is never treated as complete. RFC 5280 (§5.2, §5.3) forbids
// using a CRL carrying a critical extension, on the list or on one of
// its entries, that the reader can't process, so a list is skipped when
// a critical extension other than an authority key identifier or a CRL
// number marks it, or a critical extension other than a reason code or
// an invalidity date marks one of its entries; a non-critical extension
// never makes a list unreadable. A critical issuer alternative name
// makes a list unreadable, since this type identifies a list's issuer by
// its issuer name and signature alone, and so does the certificate
// issuer entry extension, critical by definition, with which an indirect
// CRL gives entries another CA (an indirect CRL also carries an issuing
// distribution point). If your CA marks an extension of its own
// critical, have Lists return a list from that CA without it, or check
// revocation with a ClientCertificateRevocation of your own that
// processes it: otherwise the CA's certificates get server_error.
type ClientCertificateCRLs struct {
	// Lists returns the current CRLs, at least one from each CA that
	// issues a certificate in the chain: the CA issuing client (or
	// attester) certificates, and the CA above each intermediate. It is called on every check: keep the
	// parsed lists in memory and refresh them in the background before
	// their nextUpdate, rather than fetching here. Required.
	Lists func(ctx context.Context) ([]*x509.RevocationList, error)
}

var (
	oidAuthorityKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidCRLNumber                = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidReasonCode               = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidInvalidityDate           = asn1.ObjectIdentifier{2, 5, 29, 24}
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

// crlUsableFor reports whether list is a current CRL that issuer
// signed, complete and readable (crlExtensionsReadable,
// crlEntryExtensionsReadable).
func crlUsableFor(list *x509.RevocationList, issuer *x509.Certificate, check ClientCertificateRevocationCheck) bool {
	if list == nil || !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
		return false
	}
	if list.NextUpdate.IsZero() || check.Now.Before(list.ThisUpdate) || !check.Now.Before(list.NextUpdate) {
		return false
	}
	if !crlExtensionsReadable(list.Extensions) || !crlEntryExtensionsReadable(list.RevokedCertificateEntries) {
		return false
	}
	return list.CheckSignatureFrom(issuer) == nil
}

// crlExtensionsReadable reports whether a CRL with extensions is
// complete and direct, and marks critical no extension this type
// doesn't process: RFC 5280 §5.2 has a reader that can't process a
// critical CRL extension not use the CRL at all. A delta CRL indicator,
// or an issuing distribution point limiting the list's scope, makes it
// incomplete, critical or not. Of the other extensions RFC 5280 defines
// for a CRL, crypto/x509 reads the authority key identifier (refusing
// to parse a list that marks it critical) and the CRL number, and
// neither changes which certificates a list covers: the signature check
// identifies the key, and the number orders a CA's lists, which this
// type needs no order of, since a certificate any current list names is
// revoked. Both are processed, critical or not. Anything else critical
// makes the list unreadable: an issuer alternative name, as this type
// identifies the issuer by its name and signature alone; a freshest CRL
// or authority information access extension, which RFC 5280 never
// marks critical; or a private one.
func crlExtensionsReadable(extensions []pkix.Extension) bool {
	for _, ext := range extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) || ext.Id.Equal(oidIssuingDistributionPoint) {
			return false
		}
		if ext.Critical && !ext.Id.Equal(oidAuthorityKeyIdentifier) && !ext.Id.Equal(oidCRLNumber) {
			return false
		}
	}
	return true
}

// crlEntryExtensionsReadable reports whether no entry of a CRL with
// entries marks critical an extension this type doesn't process: RFC
// 5280 §5.3 has a reader that can't process a critical entry extension
// not use the CRL at all. A reason code or an invalidity date says only
// why, or since when, a listed certificate is revoked, and this type
// takes a listed certificate as revoked whatever they say, so both are
// processed, critical or not. Anything else critical makes the list
// unreadable: above all the certificate issuer extension, critical by
// definition, which gives its entry and the entries after it another CA
// in an indirect CRL, so serial numbers alone would misread them.
func crlEntryExtensionsReadable(entries []x509.RevocationListEntry) bool {
	for _, entry := range entries {
		for _, ext := range entry.Extensions {
			if ext.Critical && !ext.Id.Equal(oidReasonCode) && !ext.Id.Equal(oidInvalidityDate) {
				return false
			}
		}
	}
	return true
}

func (c ClientCertificateCRLs) validate() error {
	if c.Lists == nil {
		return errors.New("client certificate CRLs: lists is required")
	}
	return nil
}
