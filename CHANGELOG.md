# Changelog

## [0.10.0](https://github.com/IDFoundry/FAPIgo/compare/v0.9.2...v0.10.0) (2026-08-25)


### Features

* accept the registered JWK Set media type alongside application/json ([#136](https://github.com/IDFoundry/FAPIgo/issues/136)) ([9213afc](https://github.com/IDFoundry/FAPIgo/commit/9213afc741b80274d52a98452d0b9f93ab17c45d))
* add opt-in tolerance for a UserInfo sub-equals-client_id defect ([#139](https://github.com/IDFoundry/FAPIgo/issues/139)) ([1cdcdc3](https://github.com/IDFoundry/FAPIgo/commit/1cdcdc3ec43b6ab127de23260be5230f000d8704))
* allow multi-valued access-token aud, trusted ID-token audiences, and azp checks ([e6612a5](https://github.com/IDFoundry/FAPIgo/commit/e6612a59e35645731cbde1f65bcfe3b1c32156a2))
* implement crit-based ignore-unknown for JWS/JWE header parsing ([f7bd537](https://github.com/IDFoundry/FAPIgo/commit/f7bd5373097f37b9123c39ecb0d939521a96b3ac))
* tolerate unrecognized members in AS-originated JSON documents ([ce16852](https://github.com/IDFoundry/FAPIgo/commit/ce168524c3b90d94bad310ebe4735ba99bd90842))


### Bug Fixes

* accept a nested JWT payload with a missing (not just correct) cty ([#137](https://github.com/IDFoundry/FAPIgo/issues/137)) ([f506385](https://github.com/IDFoundry/FAPIgo/commit/f506385b19ba95317ebbd1608ef32a4df017927d))
* exclude internal/jose|jwe header.go from copy-paste detection ([a8d41b2](https://github.com/IDFoundry/FAPIgo/commit/a8d41b247d8ca9213ac7e6b9e5ca1ced40555a90))
* extract the shared crit-check loop into internal/critical ([1a9fdfa](https://github.com/IDFoundry/FAPIgo/commit/1a9fdfa96cf96507bb83340ca105db8c4bf1a565))
* use a live clock in client test setup, not one frozen before token issuance ([299f81b](https://github.com/IDFoundry/FAPIgo/commit/299f81bce7066115c6692b19d046b3e99cd944c4))

## [0.9.2](https://github.com/IDFoundry/FAPIgo/compare/v0.9.1...v0.9.2) (2026-08-24)


### Bug Fixes

* resolve remaining SonarCloud findings (empty-function comments, param grouping, duplicate literals) ([61a0ad3](https://github.com/IDFoundry/FAPIgo/commit/61a0ad3b7130b1d5cbcc839a394d1d4d0e202e3e))
* resolve the new_coverage regression from the S1186/S107/S1192 fixes ([85139c1](https://github.com/IDFoundry/FAPIgo/commit/85139c1ec45c6c3d7fc8bb9bfc17985e73e1e72e))
* revert the go:S1186 marker-method changes entirely ([b90c7c1](https://github.com/IDFoundry/FAPIgo/commit/b90c7c1b73e8b855d45eaae9e87f60d9e3903454))
* switch the go:S1186 marker-method fix to NOSONAR, resolving the coverage gate for good ([92f7149](https://github.com/IDFoundry/FAPIgo/commit/92f7149fd318956bcfe4749956c97331416f0bd0))

## [0.9.1](https://github.com/IDFoundry/FAPIgo/compare/v0.9.0...v0.9.1) (2026-08-24)


### Bug Fixes

* correct NOSONAR comment syntax for python:S4830/S5527 ([14f8643](https://github.com/IDFoundry/FAPIgo/commit/14f86434262fa0d9843a2f5a22785f63f517e42f))
* pin TLS 1.2 minimum, deduplicate the SSL-context helper, exclude conformance/ Python from coverage gate ([229d8e5](https://github.com/IDFoundry/FAPIgo/commit/229d8e5c916bf730f678bb8b08e97c083861e5c1))
* populate Endpoints.UserInfo from Discover, remove the redundant field ([589b1c1](https://github.com/IDFoundry/FAPIgo/commit/589b1c163ca236c1277d5dd3e671219c2a43295c))
* resolve SonarCloud's 14 security-impact findings ([c1b0518](https://github.com/IDFoundry/FAPIgo/commit/c1b05188a0996f09a0c9671ccef94b78699d4dff))
* suppress python:S5527 on the loopback-only unverified context ([f8a38fe](https://github.com/IDFoundry/FAPIgo/commit/f8a38fe7abbaa8b9986a94a9ae6214616cb7dbb7))

## [0.9.0](https://github.com/IDFoundry/FAPIgo/compare/v0.8.0...v0.9.0) (2026-08-24)


### Features

* add FetchUserInfo for validated OIDC UserInfo claims ([f2b0177](https://github.com/IDFoundry/FAPIgo/commit/f2b0177352f6d5ad22a374bda028e20d64985f87))
* add ProtectedResource for DPoP-bound protected-resource calls ([d0b5569](https://github.com/IDFoundry/FAPIgo/commit/d0b556926617177b792197bb86e4d3432b0838ec))
* add VerifyIssuerJWS for issuer-signed artifacts beyond the ID token ([#123](https://github.com/IDFoundry/FAPIgo/issues/123)) ([fcd1ae1](https://github.com/IDFoundry/FAPIgo/commit/fcd1ae169224839836df98228fecbe724c279846))

## [0.8.0](https://github.com/IDFoundry/FAPIgo/compare/v0.7.0...v0.8.0) (2026-08-23)


### Features

* expose the full validated ID token, not just Subject ([2ae6511](https://github.com/IDFoundry/FAPIgo/commit/2ae6511551c7197a5e74e31fc403f3ce9b6d0e40))
* expose the full validated ID token, not just Subject ([da163a1](https://github.com/IDFoundry/FAPIgo/commit/da163a17736842c4edaa40ed8983bae09e3edecd))


### Bug Fixes

* extract populateIDToken helper and add missing ID token error-path coverage ([dae4480](https://github.com/IDFoundry/FAPIgo/commit/dae4480201462672f6dbc16e5665195369cd85a2))

## [0.7.0](https://github.com/IDFoundry/FAPIgo/compare/v0.6.0...v0.7.0) (2026-08-23)


### Features

* parse userinfo_endpoint from OIDC discovery ([d54a5e6](https://github.com/IDFoundry/FAPIgo/commit/d54a5e60c88c040eda31e64bbda4a12e973bd3e3))

## [0.6.0](https://github.com/IDFoundry/FAPIgo/compare/v0.5.0...v0.6.0) (2026-08-23)


### Features

* add EdDSA (Ed25519) signature algorithm support ([c71e121](https://github.com/IDFoundry/FAPIgo/commit/c71e12156cbe6eeaba7bdfec4f13f0b1875fad4c))
* include EdDSA in recommended client algorithms and DPoP discovery ([b90907d](https://github.com/IDFoundry/FAPIgo/commit/b90907d7a243fa044a3b986daa1f354232fa5f79))
* wire EdDSA into keys.KeyManager and its signer adapters ([ea4bde8](https://github.com/IDFoundry/FAPIgo/commit/ea4bde8121253b6bfbf6f2fa3d0deec1a7210b53))


### Bug Fixes

* de-duplicate signer routing tests to satisfy SonarCloud gate ([5e4457c](https://github.com/IDFoundry/FAPIgo/commit/5e4457c9e9fc7504488eeaf0c811af22165fc6d8))

## [0.5.0](https://github.com/IDFoundry/FAPIgo/compare/v0.4.0...v0.5.0) (2026-08-23)


### Features

* add A256CBC-HS512 content encryption algorithm type ([a0fc943](https://github.com/IDFoundry/FAPIgo/commit/a0fc94304cf9864cec3b90cfedead8b1dbce4ba6))
* implement AES_256_CBC_HMAC_SHA_512 content encryption ([1c8884c](https://github.com/IDFoundry/FAPIgo/commit/1c8884cd8ca6e6666948f04c9ef37b9bc1c90d75))


### Bug Fixes

* suppress SonarCloud false positive on CBC-HMAC's raw CBC mode ([4e1a75b](https://github.com/IDFoundry/FAPIgo/commit/4e1a75b108da3b691106051b09d017de7a335e65))

## [0.4.0](https://github.com/IDFoundry/FAPIgo/compare/v0.3.0...v0.4.0) (2026-08-23)


### Features

* add client config and discovery surface for encrypted ID tokens ([c66394b](https://github.com/IDFoundry/FAPIgo/commit/c66394b769e9813260f78d6ad1f1c10508365924))
* add closed KeyManagementAlgorithm/ContentEncryptionAlgorithm types ([fc3f2b7](https://github.com/IDFoundry/FAPIgo/commit/fc3f2b7693e60a5f7cb016c3d72f8acce76c9482))
* add closed KeyManagementAlgorithm/ContentEncryptionAlgorithm types ([f16b8a0](https://github.com/IDFoundry/FAPIgo/commit/f16b8a03a9e1c0cfc80db4b98e2907a9f757b42d))
* add internal/jwe package for JWE encrypt/decrypt ([8d945a8](https://github.com/IDFoundry/FAPIgo/commit/8d945a8df55e189ab1568ce15466764c412fa2f1))
* add keys.Decrypter for opaque ID-token decryption key management ([e3fc80c](https://github.com/IDFoundry/FAPIgo/commit/e3fc80c28d7cbc047ee068f8052ede69e4194878))
* add server-side config, storage and key-resolution for encrypted ID tokens ([cd0443f](https://github.com/IDFoundry/FAPIgo/commit/cd0443f693bf658439f9c1a86e00d7db0242de39))
* decrypt encrypted ID tokens in validateIDToken ([12ab883](https://github.com/IDFoundry/FAPIgo/commit/12ab883d7c3152b8ecf5a96235d1e1bcd24265a3))
* encrypt ID tokens at issuance when client and server agree ([#108](https://github.com/IDFoundry/FAPIgo/issues/108)) ([36de247](https://github.com/IDFoundry/FAPIgo/commit/36de2477b963a962b663450690d5f365f2eb6bb8))
* support both RSA-OAEP-256 and ECDH-ES+A256KW for JWE key management ([e3dc3d9](https://github.com/IDFoundry/FAPIgo/commit/e3dc3d92c8d99d0e627516561b25ff4b0aebd3eb))


### Bug Fixes

* satisfy CI lint/Sonar findings in internal/jwe ([1c07120](https://github.com/IDFoundry/FAPIgo/commit/1c0712032f7af81b0636aa834027389c13074976))

## [0.3.0](https://github.com/IDFoundry/FAPIgo/compare/v0.2.4...v0.3.0) (2026-08-23)


### Features

* send client_id and dpop_jkt on PAR, allow string extensions on the plain path ([0a386e7](https://github.com/IDFoundry/FAPIgo/commit/0a386e75f84305b802a2d69b703ca11808b5e084))
* send client_id and dpop_jkt on PAR, allow string extensions on the plain path ([34fbb0e](https://github.com/IDFoundry/FAPIgo/commit/34fbb0e49c1f7af9ccfa4aec0439e6cdef50c4e3))

## [0.2.4](https://github.com/IDFoundry/FAPIgo/compare/v0.2.3...v0.2.4) (2026-08-23)


### Bug Fixes

* re-assert key parameters in JOSE verify; make identity claims win over extension-claim collisions ([9644d64](https://github.com/IDFoundry/FAPIgo/commit/9644d6494a8d9a08519c689867a7143a3029c06d))

## [0.2.3](https://github.com/IDFoundry/FAPIgo/compare/v0.2.2...v0.2.3) (2026-08-22)


### Bug Fixes

* harden SSRF transition-address coverage; close latent fail-open pattern in JARM key resolution ([9a09b2c](https://github.com/IDFoundry/FAPIgo/commit/9a09b2c4851595eceafd1df63750b036c195a82f))
* harden SSRF transition-address coverage; close latent fail-open pattern in JARM key resolution ([80b0879](https://github.com/IDFoundry/FAPIgo/commit/80b087905f0302213c8834e3e890a0ba7c7636d1))

## [0.2.2](https://github.com/IDFoundry/FAPIgo/compare/v0.2.1...v0.2.2) (2026-08-22)


### Bug Fixes

* close two residual JWKS single-flight gaps (L-A, L-B) ([6d8d877](https://github.com/IDFoundry/FAPIgo/commit/6d8d877eabfe2c7b8c6df602f8ea4ebee842836e))
* close two residual JWKS single-flight gaps (L-A, L-B) ([e888b9b](https://github.com/IDFoundry/FAPIgo/commit/e888b9bd26e5bf404690b0068b65ac1b324b1830))
* unwrap IPv6 transition addresses in SSRF checks; fix replay TTL skew gap ([c26ca4d](https://github.com/IDFoundry/FAPIgo/commit/c26ca4da652a759fa0696b4095b1fd974d543695))
* unwrap IPv6 transition addresses in SSRF checks; fix replay TTL skew gap ([9ad76f6](https://github.com/IDFoundry/FAPIgo/commit/9ad76f60eeace4c0816334b61da55c03b33bd493))

## [0.2.1](https://github.com/IDFoundry/FAPIgo/compare/v0.2.0...v0.2.1) (2026-08-22)


### Bug Fixes

* allow loopback in cmd/conformance-client's fapihttp.Config ([2d5de00](https://github.com/IDFoundry/FAPIgo/commit/2d5de00fc338ece2494e6f34fe8b516a353a5e31))

## [0.2.0](https://github.com/IDFoundry/FAPIgo/compare/v0.1.1...v0.2.0) (2026-08-22)


### ⚠ BREAKING CHANGES

* BuildAuthorizationErrorRedirect's second parameter is now storage.RegisteredClient instead of fapi.ClientID. A caller must resolve the client (e.g. via ClientRepository.ResolveClient) before calling this method, rather than passing the bare client ID.

### Bug Fixes

* check redirect_uri against the registered client in BuildAuthorizationErrorRedirect (L-3) ([ce7fe0f](https://github.com/IDFoundry/FAPIgo/commit/ce7fe0fdc67a75ffd3faa77a5d7dd5a8e97107aa))
* satisfy staticcheck QF1008 on embedded PublicKey selectors ([ae8c4e4](https://github.com/IDFoundry/FAPIgo/commit/ae8c4e4710286158bfb8fee6a4861ff6109ab6dc))

## [0.1.1](https://github.com/IDFoundry/FAPIgo/compare/v0.1.0...v0.1.1) (2026-08-20)


### Bug Fixes

* address real findings from Sonar security review ([0c4113e](https://github.com/IDFoundry/FAPIgo/commit/0c4113e5569280a796dc7cc7cb7f0e18c9ed9013))
* exclude _test.go from Sonar's coverage denominator ([7d31b21](https://github.com/IDFoundry/FAPIgo/commit/7d31b21a169c5e8dc4784c7f135394eae3932e6b))
* pin SonarQube scan action to a commit SHA ([#72](https://github.com/IDFoundry/FAPIgo/issues/72)) ([852206a](https://github.com/IDFoundry/FAPIgo/commit/852206abddf5307f77028f80cb3fb29d5aacbaf4))
* use [[ instead of [ for conditional tests in run-all.sh ([3bc1ee7](https://github.com/IDFoundry/FAPIgo/commit/3bc1ee79bbfb27cb3742dd9b0e408741f62947ac))
