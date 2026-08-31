# Changelog

## [0.23.0](https://github.com/IDFoundry/FAPIgo/compare/v0.22.2...v0.23.0) (2026-08-31)


### Features

* add canonical String/Parse pairs for storage's enum types ([c3ae0e1](https://github.com/IDFoundry/FAPIgo/commit/c3ae0e1f41e0807d454e02de72201c960aea6c55))
* export server.Error.WriteJSON and NewError ([79fe156](https://github.com/IDFoundry/FAPIgo/commit/79fe156eb11058255ccecb748faa49af4e950d8a))


### Bug Fixes

* reject multiple DPoP header values instead of trusting adapters ([c958b5c](https://github.com/IDFoundry/FAPIgo/commit/c958b5cdbb02b5163ef608a8c8ad89602fac1abd))

## [0.22.2](https://github.com/IDFoundry/FAPIgo/compare/v0.22.1...v0.22.2) (2026-08-31)


### Bug Fixes

* regenerate client_credentials plan configs on a fresh checkout ([#230](https://github.com/IDFoundry/FAPIgo/issues/230)) ([712845d](https://github.com/IDFoundry/FAPIgo/commit/712845d8f3064ea7a166e84c10792bbec2ff8283))

## [0.22.1](https://github.com/IDFoundry/FAPIgo/compare/v0.22.0...v0.22.1) (2026-08-30)


### Bug Fixes

* relax setup-config's stale exact client-count checks ([#228](https://github.com/IDFoundry/FAPIgo/issues/228)) ([848f997](https://github.com/IDFoundry/FAPIgo/commit/848f997f23bed169cdbeee30613b723b7a191755))

## [0.22.0](https://github.com/IDFoundry/FAPIgo/compare/v0.21.0...v0.22.0) (2026-08-30)


### Features

* add request-time RAR entitlement gate for PAR and CIBA ([d2d8b5e](https://github.com/IDFoundry/FAPIgo/commit/d2d8b5e460e7e58af6b415296d811d17f6a7531d))
* add RFC 6749 §4.4 client_credentials grant support ([aaeb9f6](https://github.com/IDFoundry/FAPIgo/commit/aaeb9f60da6ddc50d0f43bf10e7ef45a7e91665b))
* close AS MTLS+MTLS and CIBA client-auth-mTLS conformance gaps ([c399e26](https://github.com/IDFoundry/FAPIgo/commit/c399e26c88ad84d30a8c857453bab29f8d6c8b96))
* close RP mTLS sender-constrain gap, add per-test evidence output ([#219](https://github.com/IDFoundry/FAPIgo/issues/219)) ([be6e2ef](https://github.com/IDFoundry/FAPIgo/commit/be6e2efa55087c091eb9567134e1efa9e72f102b))
* support Rich Authorization Requests on the client_credentials grant ([f5b6604](https://github.com/IDFoundry/FAPIgo/commit/f5b66044f26d536e59a61c8192d98f1845d58cce))


### Bug Fixes

* rename PARRARPolicy to AuthorizationCodeRARPolicy ([6744eb8](https://github.com/IDFoundry/FAPIgo/commit/6744eb8ab98def1697c4656dd8eeed909966e66f))
* require an explicit client policy for client_credentials RAR grants ([256aa13](https://github.com/IDFoundry/FAPIgo/commit/256aa1387562cf369079242349d87a31d1689868))
* split RARRequestPolicy into independent PAR/CIBA policies ([1491ea2](https://github.com/IDFoundry/FAPIgo/commit/1491ea2cb87334d2278583be1436a6d488bd7116))
* stop silently dropping 9 legs from the conformance summary ([c234c95](https://github.com/IDFoundry/FAPIgo/commit/c234c956ad1f3f3b3187674e6dc8cf421562de83))

## [0.21.0](https://github.com/IDFoundry/FAPIgo/compare/v0.20.0...v0.21.0) (2026-08-30)


### Features

* add SAN-based mTLS client authentication bindings (RFC 8705 §2.1) ([#216](https://github.com/IDFoundry/FAPIgo/issues/216)) ([7655ed2](https://github.com/IDFoundry/FAPIgo/commit/7655ed22a4c98bfe39b7baa858889c03eafb97c0))


### Bug Fixes

* address staticcheck ST1023 lint failure ([2eecffa](https://github.com/IDFoundry/FAPIgo/commit/2eecffa5883101231327c196f871ccf18523e1bc))
* bound resource.JWTAccessTokens' key-candidate loop ([a2c98be](https://github.com/IDFoundry/FAPIgo/commit/a2c98be0ee5f04a684891b7921455c16659fa9f5))

## [0.20.0](https://github.com/IDFoundry/FAPIgo/compare/v0.19.0...v0.20.0) (2026-08-30)


### Features

* add first-class Rich Authorization Requests (RFC 9396) support ([#206](https://github.com/IDFoundry/FAPIgo/issues/206)) ([9408d3f](https://github.com/IDFoundry/FAPIgo/commit/9408d3f49792cac99a87f7b613abd3bf6fd797bf))
* add per-type narrowing to RAR authorization_details grants ([c144c2e](https://github.com/IDFoundry/FAPIgo/commit/c144c2e73e142a7fc030173e01d59e8120e8a8e6))
* add RARSet, the write-side counterpart to RARGet ([#209](https://github.com/IDFoundry/FAPIgo/issues/209)) ([7a25f44](https://github.com/IDFoundry/FAPIgo/commit/7a25f44f7cc12a214864a149062b3911318f8cca))
* add Rich Authorization Requests support to the client package ([c7c2f4c](https://github.com/IDFoundry/FAPIgo/commit/c7c2f4c4dae5597bc8b02c723d95851f73ae8634))
* thread Rich Authorization Requests through PAR and CIBA ([2400747](https://github.com/IDFoundry/FAPIgo/commit/2400747d87b1aa54c35f3a27b2e2b1156d0487c1))
* wire Rich Authorization Requests into the reference AS and fapitest ([8fd28b8](https://github.com/IDFoundry/FAPIgo/commit/8fd28b86ec74f38a24e77c1efec0e1dba899a767))


### Bug Fixes

* validate granted scope against requested scope in CIBA ([#208](https://github.com/IDFoundry/FAPIgo/issues/208)) ([2445c3c](https://github.com/IDFoundry/FAPIgo/commit/2445c3cb610a7090f8581069dc9bcce393d4e552))


### Reverts

* undo direct-to-main RAR commits, pending PR ([2e5f1b9](https://github.com/IDFoundry/FAPIgo/commit/2e5f1b9791600d674d1720bff57f81c1e198ba7d))

## [0.19.0](https://github.com/IDFoundry/FAPIgo/compare/v0.18.2...v0.19.0) (2026-08-29)


### Features

* add mTLS sender-constrain conformance for baseline and message-signing ([a542f8a](https://github.com/IDFoundry/FAPIgo/commit/a542f8a1042a068ca4f74aba1e60d33ea821392e))
* add mTLS sender-constrain conformance for baseline and message-signing ([135f2e5](https://github.com/IDFoundry/FAPIgo/commit/135f2e51a596aaf49b265016dca5e39864bc13ee))

## [0.18.2](https://github.com/IDFoundry/FAPIgo/compare/v0.18.1...v0.18.2) (2026-08-29)


### Bug Fixes

* keep ciba-ping client jwks in sync with freshly generated plan ([74b4c60](https://github.com/IDFoundry/FAPIgo/commit/74b4c6013cd5d5898c124fdd8d5ef7422218e087))

## [0.18.1](https://github.com/IDFoundry/FAPIgo/compare/v0.18.0...v0.18.1) (2026-08-29)


### Bug Fixes

* allow ciba-mtls setup-config to tolerate appended ciba-ping clients ([#193](https://github.com/IDFoundry/FAPIgo/issues/193)) ([cd7a1b1](https://github.com/IDFoundry/FAPIgo/commit/cd7a1b10a6fc3abb85331854afc097ac6d2e831e))

## [0.18.0](https://github.com/IDFoundry/FAPIgo/compare/v0.17.0...v0.18.0) (2026-08-29)


### Features

* add CIBA backchannel authentication (poll mode) ([bb6b447](https://github.com/IDFoundry/FAPIgo/commit/bb6b447afe5779f23fa7f0f33745c1e67200b6e6))
* add CIBA client-side support (BeginBackchannelAuthentication/PollBackchannelAuthentication) ([929dd7d](https://github.com/IDFoundry/FAPIgo/commit/929dd7d4479f4556a86e7406f51f7d620376ab45))
* add CIBA ping-mode delivery (OIDC CIBA Core 1.0 §7-§10) ([8885be0](https://github.com/IDFoundry/FAPIgo/commit/8885be05da3577690156c39dbec1bf718f4762fc))
* add live conformance coverage for RFC 8705 client-auth mTLS ([#186](https://github.com/IDFoundry/FAPIgo/issues/186)) ([1d66ea2](https://github.com/IDFoundry/FAPIgo/commit/1d66ea23325675286e5267d0e44cc0a8de82e99c))
* add mTLS-bound access tokens (RFC 8705 §3) as an alternative to DPoP ([77b0cd9](https://github.com/IDFoundry/FAPIgo/commit/77b0cd9557eb473aa374bf71ea50af125efd8504))
* add RP-side conformance coverage for RFC 8705 client-auth mTLS ([01aaaf6](https://github.com/IDFoundry/FAPIgo/commit/01aaaf6e93095310710eb6da2ddd5e2a1bc09b56))
* add tls_client_auth and self_signed_tls_client_auth client authentication ([edd7c6c](https://github.com/IDFoundry/FAPIgo/commit/edd7c6cc58c917decf4547009fb233be4854b65d))
* wire CIBA ping delivery mode into AS conformance suite ([96759e4](https://github.com/IDFoundry/FAPIgo/commit/96759e4b281ae204280d674d29060fa64a0d1a6a))
* wire CIBA-mTLS conformance into run-all.sh and the daily CI job ([e102805](https://github.com/IDFoundry/FAPIgo/commit/e1028050319a7c75f1d259722ff9458bfa2f5f0d))
* wire mTLS into the conformance binaries and re-attempt CIBA live ([8e8b473](https://github.com/IDFoundry/FAPIgo/commit/8e8b4730dc7c2feb9150db5f8d5dfcddc5214918))


### Bug Fixes

* avoid comparing identical expressions in mTLS thumbprint determinism test ([28529fa](https://github.com/IDFoundry/FAPIgo/commit/28529fad7790dfe3643cdd9434b18ee1f65fcefe))
* dedupe InsecureSkipVerify site and add unit coverage for mTLS AS config/endpoints ([998c4f1](https://github.com/IDFoundry/FAPIgo/commit/998c4f1cf646310f64c16d9749e5c989946b4b26))
* include auth_req_id in CIBA ping notifications (CIBA Core 1.0 §10.2) ([#189](https://github.com/IDFoundry/FAPIgo/issues/189)) ([dcd24e7](https://github.com/IDFoundry/FAPIgo/commit/dcd24e715d0ec09aabbf88a5f25fd4365364c82c))
* reject unacceptable binding_message with invalid_binding_message ([9b51d9e](https://github.com/IDFoundry/FAPIgo/commit/9b51d9e9d9f2e76ce5e393bf53f1b872f33508f9))
* resolve CIBA client conformance driver bugs and iat validation gap ([f12999d](https://github.com/IDFoundry/FAPIgo/commit/f12999db59ca10e311d4b603cd3718a93afefa68))
* resolve CIBA mTLS conformance findings (cipher/cert, interaction-id, error codes) ([#181](https://github.com/IDFoundry/FAPIgo/issues/181)) ([deaaa81](https://github.com/IDFoundry/FAPIgo/commit/deaaa818bd9ce2eb59c4311ff4ca3b1234bfe828))
* scope client-assertion audience acceptance per endpoint ([d30c46c](https://github.com/IDFoundry/FAPIgo/commit/d30c46ccad06c4d4303675db83e700f2f058ce98))
* suppress CodeQL disabled-certificate-check on the ping notifier ([6eaf402](https://github.com/IDFoundry/FAPIgo/commit/6eaf402c51d7ec05114db04a10754c33a1c5b92a))

## [0.17.0](https://github.com/IDFoundry/FAPIgo/compare/v0.16.0...v0.17.0) (2026-08-28)


### Features

* make server.Metadata directly JSON-marshalable ([#172](https://github.com/IDFoundry/FAPIgo/issues/172)) ([e99bf74](https://github.com/IDFoundry/FAPIgo/commit/e99bf74b6774087e738c32749628ba98d86726ff))
* server-side signed and encrypted UserInfo response production ([#174](https://github.com/IDFoundry/FAPIgo/issues/174)) ([2486974](https://github.com/IDFoundry/FAPIgo/commit/2486974024a98cd9af9399d6049cac521604a275))


### Bug Fixes

* avoid arithmetic in withIdentityClaims map size hint ([#175](https://github.com/IDFoundry/FAPIgo/issues/175)) ([11ff67a](https://github.com/IDFoundry/FAPIgo/commit/11ff67a4ed42bbf80f02d93b97ca8e65d63cc7d3))

## [0.16.0](https://github.com/IDFoundry/FAPIgo/compare/v0.15.0...v0.16.0) (2026-08-27)


### Features

* DPoP nonce-challenge support for PAR and the token endpoint ([#168](https://github.com/IDFoundry/FAPIgo/issues/168)) ([88b45df](https://github.com/IDFoundry/FAPIgo/commit/88b45df5789d6fbc0b57097005035af0e32991ac))
* DPoP nonce-challenge support for the resource server ([#166](https://github.com/IDFoundry/FAPIgo/issues/166)) ([b2c3bf8](https://github.com/IDFoundry/FAPIgo/commit/b2c3bf8f9257e4b7265e99e355f9e562887d6723))
* reuse a cached DPoP nonce across calls instead of always challenging ([#170](https://github.com/IDFoundry/FAPIgo/issues/170)) ([5c37f06](https://github.com/IDFoundry/FAPIgo/commit/5c37f0658d6c09ceb6f9f8d6f662a484d7cc1e55))
* send a DPoP proof at PAR by default, per RFC 9449 §10.1 ([a3a052a](https://github.com/IDFoundry/FAPIgo/commit/a3a052a0773beabd0f08220ced3637e216d4b5ed))

## [0.15.0](https://github.com/IDFoundry/FAPIgo/compare/v0.14.0...v0.15.0) (2026-08-26)


### Features

* add IDTokenClaims.AsMap and UserInfo.AsMap ([cd9a000](https://github.com/IDFoundry/FAPIgo/commit/cd9a0001561829cf1cfff82b09a2e348b7633cbc))
* discover and validate UserInfo signing/encryption algorithms ([66202c4](https://github.com/IDFoundry/FAPIgo/commit/66202c417f6c6b2e57c8c7249f8a217e87cf3d0c))

## [0.14.0](https://github.com/IDFoundry/FAPIgo/compare/v0.13.0...v0.14.0) (2026-08-26)


### Features

* add client.Limits.MaxJOSECompactBytes for ID token/UserInfo size caps ([26228b6](https://github.com/IDFoundry/FAPIgo/commit/26228b6f3ae7f0208c05af9794481e9ee582c580))

## [0.13.0](https://github.com/IDFoundry/FAPIgo/compare/v0.12.0...v0.13.0) (2026-08-26)


### Features

* add client.RecommendedLimits/RecommendedAlgorithms ([839a95d](https://github.com/IDFoundry/FAPIgo/commit/839a95d76927637b5fffcd3e26482fa4b355390a))
* add DiscoveredMetadata.IssuerKeySource ([43afb73](https://github.com/IDFoundry/FAPIgo/commit/43afb731415f1c4f9bac87614b4f936b3e964588))
* add DiscoveredMetadata.SupportsAlgorithms ([abccccf](https://github.com/IDFoundry/FAPIgo/commit/abccccf595f263568e3b4af068154cd2574c1fc6))
* add keys.PublicJWKS, a shared core for client/server.PublicJWKS ([7d04816](https://github.com/IDFoundry/FAPIgo/commit/7d04816541184033601a79c569176a319c1ff6fe))
* expose IssuedAt on client.IDTokenClaims ([2058520](https://github.com/IDFoundry/FAPIgo/commit/2058520d4c0a6dac7463518b0b73468bb2410f57))

## [0.12.0](https://github.com/IDFoundry/FAPIgo/compare/v0.11.0...v0.12.0) (2026-08-26)


### Features

* publish this client's own JWKS ([cecc67e](https://github.com/IDFoundry/FAPIgo/commit/cecc67eae60c54e18fe11b47b30de3b5455f6356))

## [0.11.0](https://github.com/IDFoundry/FAPIgo/compare/v0.10.0...v0.11.0) (2026-08-25)


### ⚠ BREAKING CHANGES

* keys.ECDHAgreer.AgreeSharedSecret and keys.KeyDecrypter.DecryptKey (added in #141, unreleased) each gain a keyID string parameter as their second argument. An existing implementation that doesn't need multi-key support can add the parameter and ignore it.

### Features

* adapt any crypto.Signer into a keys.KeyManager ([3c4f30c](https://github.com/IDFoundry/FAPIgo/commit/3c4f30cd1fedac1a71495726cf4fd4d783b1a0ff))
* add a capability-based, KMS/HSM-friendly keys.Decrypter ([#141](https://github.com/IDFoundry/FAPIgo/issues/141)) ([c2dc847](https://github.com/IDFoundry/FAPIgo/commit/c2dc84736bae12fe03d403687966f06235128d4f))
* support graceful key rotation — multi-key JWKS publishing, kid-aware decryption ([14d44e7](https://github.com/IDFoundry/FAPIgo/commit/14d44e7c91d269a263f514fb4f58ff738b8da2d8))

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
