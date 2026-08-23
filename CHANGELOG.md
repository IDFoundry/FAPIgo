# Changelog

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
