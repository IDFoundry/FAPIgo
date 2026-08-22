# Changelog

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
