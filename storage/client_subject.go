package storage

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	fapi "github.com/idfoundry/fapigo"
)

// maxSectorLength bounds RegisteredClientConfig.Sector.
const maxSectorLength = 255

// SubjectType returns the kind of sub this client's end users get, as
// registered (see RegisteredClientConfig.SubjectType): zero means the
// server's default applies.
func (c RegisteredClient) SubjectType() fapi.SubjectType { return c.subjectType }

// Sector returns the sector this client's pairwise subjects are derived
// for: RegisteredClientConfig.Sector when set, otherwise the single host
// of the https redirect URIs of a web client neither permitted CIBA nor
// authenticating by attestation, otherwise "" (no sector, so the client
// can't have pairwise subjects).
func (c RegisteredClient) Sector() string { return c.sector }

// checkApplicationTypeAndSector runs checkApplicationType, then
// clientSector, whose sector derivation depends on the application type.
func checkApplicationTypeAndSector(cfg RegisteredClientConfig) (string, error) {
	if err := checkApplicationType(cfg); err != nil {
		return "", err
	}
	return clientSector(cfg)
}

// clientSector validates cfg's SubjectType and Sector, and returns the
// client's sector: the one set, or the one derived from its redirect
// URIs, or "". A client registered as pairwise must end up with one.
func clientSector(cfg RegisteredClientConfig) (string, error) {
	if cfg.SubjectType != 0 && !cfg.SubjectType.IsValid() {
		return "", fmt.Errorf("storage: client %q has an invalid subject type", cfg.ID)
	}
	sector := cfg.Sector
	if sector != "" {
		if err := checkSector(sector); err != nil {
			return "", fmt.Errorf("storage: client %q: %w", cfg.ID, err)
		}
		sector = strings.ToLower(sector)
	} else {
		sector = derivedSector(cfg)
	}
	if cfg.SubjectType == fapi.SubjectTypePairwise && sector == "" {
		return "", fmt.Errorf("storage: client %q is pairwise but has no sector: set Sector (a native client, one permitted CIBA, one that may authenticate by attestation, one with no redirect URIs, or one whose redirect URIs span several hosts, has none to derive)", cfg.ID)
	}
	return sector, nil
}

// checkSector refuses a set Sector that isn't a host name, as OpenID
// Connect Core §8.1's sector is ("the host component"): too long, or
// with a byte other than an ASCII letter, digit, '-', '.' or '_' (so no
// scheme, port, path, user info, query or fragment, which would make
// "https://rp.example/x" a different sector from "rp.example"), or with
// an empty label. clientSector then lowercases it, as a derived sector
// is, so "RP.example" and "rp.example" are one sector.
func checkSector(sector string) error {
	if len(sector) > maxSectorLength {
		return fmt.Errorf("sector is %d bytes, more than %d", len(sector), maxSectorLength)
	}
	for i := range len(sector) {
		if c := sector[i]; !isHostByte(c) {
			return fmt.Errorf("sector has a byte (%q at %d) that can't be in a host name: set the host alone, such as \"rp.example\"", c, i)
		}
	}
	if slices.Contains(strings.Split(sector, "."), "") {
		return fmt.Errorf("sector %q has an empty label: set a host name, such as \"rp.example\"", sector)
	}
	return nil
}

// isHostByte reports whether c can appear in a host name a Sector names:
// an ASCII letter, digit, '-', '.' or '_'.
func isHostByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
}

// derivedSector returns the host every redirect URI of a web client
// shares, when they're all https (OpenID Connect Core §8.1), or "": a
// native client's loopback and private-use redirect URIs have no
// meaningful host, http loopback URIs are for development, and URIs on
// several hosts need an explicit Sector.
//
// A client permitted CIBA, or one that may authenticate by attestation
// (whose tokens an embedder's own grant serves, through
// server.Server.IssueAccessToken and IssueRefreshToken), gets none
// either. The redirect-host sector is only sound because the
// authorization code goes to that host, proving the client is served
// there; CIBA and embedder grants deliver tokens without any redirect,
// so such a client could name another client's host in its redirect URIs
// and receive that client's pairwise sub values.
//
// This departs from CIBA Core 1.0's "Poll and Ping Modes with Pairwise
// Identifiers", which has the OP take a CIBA client's sector from the
// host of its jwks_uri (or a sector_identifier_uri listing it), proven
// by the client's key. Clients here are registered by the operator, not
// dynamically, so the operator states the sector instead: set Sector to
// that host for a client whose sub must match what a spec-following OP
// would give it.
func derivedSector(cfg RegisteredClientConfig) string {
	if cfg.ApplicationType != ApplicationTypeWeb || len(cfg.RedirectURIs) == 0 || cfg.BackchannelAuthenticationRequestAlgorithm != 0 || mayUseAttestation(cfg) {
		return ""
	}
	host := ""
	for _, raw := range cfg.RedirectURIs {
		u, err := url.Parse(string(raw))
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return ""
		}
		h := strings.ToLower(u.Hostname())
		if host != "" && h != host {
			return ""
		}
		host = h
	}
	return host
}

// mayUseAttestation reports whether cfg's client may authenticate by
// attestation (ClientAuthMethodAttestation): through ClientAuthMethods
// when that is set, otherwise ClientAuthMethod.
func mayUseAttestation(cfg RegisteredClientConfig) bool {
	if len(cfg.ClientAuthMethods) > 0 {
		return slices.Contains(cfg.ClientAuthMethods, ClientAuthMethodAttestation)
	}
	return cfg.ClientAuthMethod == ClientAuthMethodAttestation
}
