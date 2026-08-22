# Changelog

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
