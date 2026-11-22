package server

import "slices"

// clone returns c with a copy of every slice it holds, so the Server New
// builds from it shares no backing array with the caller's Config:
// assigning to an element afterwards, sorting or deleting in place, or
// decoding JSON into the same value changes nothing in the Server, and
// doesn't race with the requests it serves. A nil slice stays nil.
//
// Config's two pointers are kept as they are: Extensions and RAR are
// registries that can't change once built. So is
// AutomaticRegistration.OnResolutionFailure, a function.
func (c Config) clone() Config {
	c.Algorithms = c.Algorithms.clone()
	c.AdditionalGrantTypes = slices.Clone(c.AdditionalGrantTypes)
	c.Resources = slices.Clone(c.Resources)
	c.Federation.AuthorityHints = slices.Clone(c.Federation.AuthorityHints)
	c.AutomaticRegistration = c.AutomaticRegistration.clone()
	return c
}

// clone returns p with a copy of each of its algorithm sets.
func (p AlgorithmPolicy) clone() AlgorithmPolicy {
	p.ClientAssertion = slices.Clone(p.ClientAssertion)
	p.RequestObject = slices.Clone(p.RequestObject)
	p.IDTokenEncryptionKeyManagement = slices.Clone(p.IDTokenEncryptionKeyManagement)
	p.IDTokenEncryptionContentEncryption = slices.Clone(p.IDTokenEncryptionContentEncryption)
	p.UserInfoEncryptionKeyManagement = slices.Clone(p.UserInfoEncryptionKeyManagement)
	p.UserInfoEncryptionContentEncryption = slices.Clone(p.UserInfoEncryptionContentEncryption)
	p.BackchannelAuthenticationRequest = slices.Clone(p.BackchannelAuthenticationRequest)
	p.ClientAttestation = slices.Clone(p.ClientAttestation)
	p.ClientAttestationPoP = slices.Clone(p.ClientAttestationPoP)
	return p
}

// clone returns c with a copy of each of its lists, and of each Trust
// Anchor's JWKS.
func (c AutomaticRegistrationConfig) clone() AutomaticRegistrationConfig {
	c.TrustAnchors = slices.Clone(c.TrustAnchors)
	for i := range c.TrustAnchors {
		c.TrustAnchors[i].JWKS = slices.Clone(c.TrustAnchors[i].JWKS)
	}
	c.AllowedScopes = slices.Clone(c.AllowedScopes)
	c.AuthorizationDetailsTypes = slices.Clone(c.AuthorizationDetailsTypes)
	c.AllowedResources = slices.Clone(c.AllowedResources)
	c.AllowedClientAuthMethods = slices.Clone(c.AllowedClientAuthMethods)
	c.SubjectTypes = slices.Clone(c.SubjectTypes)
	return c
}
