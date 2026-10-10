# Changelog

## [0.53.0](https://github.com/IDFoundry/FAPIgo/compare/v0.52.1...v0.53.0) (2026-10-10)


### ⚠ BREAKING CHANGES

* **server:** server.NewSubjectID refuses a value longer than 255 bytes or containing a byte outside printable ASCII (0x20 to 0x7E). Use a stable identifier of your own as the subject and return names and email addresses as claims. See UPGRADING.md for v0.53.0.
* **server:** harden replay windows, CIBA requests, signing keys and production limits ([#629](https://github.com/IDFoundry/FAPIgo/issues/629))
* **server:** enforce the subject a request names ([#628](https://github.com/IDFoundry/FAPIgo/issues/628))

### Features

* **client:** require an essential acr, and refuse weak sealer keys ([575e257](https://github.com/IDFoundry/FAPIgo/commit/575e257a6b267cfbb916cdf2232fb9d85d3e1792))
* **server:** add Server.VerifyIDTokenHint ([016ba9d](https://github.com/IDFoundry/FAPIgo/commit/016ba9d8a246babad33904502c002946397295ea))
* **server:** Error.WriteText, plus embedder-duty docs and 303 redirects ([#626](https://github.com/IDFoundry/FAPIgo/issues/626)) ([e190d4a](https://github.com/IDFoundry/FAPIgo/commit/e190d4a3992f961ac4a04c230b5cdf2bd92462ec))
* **server:** pass ui_locales, claims_locales and display to the interaction ([ae1b05f](https://github.com/IDFoundry/FAPIgo/commit/ae1b05f68ddbf692625ff9294b12e6e384fd0915))


### Bug Fixes

* **fapihttp:** block the remaining non-global special-purpose ranges ([9fe8f5f](https://github.com/IDFoundry/FAPIgo/commit/9fe8f5f2a3e249c25b33baad81c6b1b6ebb05fbb))
* **server:** bound the cost of parsing the claims parameter ([#624](https://github.com/IDFoundry/FAPIgo/issues/624)) ([d006402](https://github.com/IDFoundry/FAPIgo/commit/d0064026aac605f50ef5fbb1fc47b1c79238e61b))
* **server:** enforce the subject a request names ([#628](https://github.com/IDFoundry/FAPIgo/issues/628)) ([4a3255b](https://github.com/IDFoundry/FAPIgo/commit/4a3255b758e5dbacba68a6c9c871f9970e874c2f))
* **server:** harden replay windows, CIBA requests, signing keys and production limits ([#629](https://github.com/IDFoundry/FAPIgo/issues/629)) ([d2bc7e7](https://github.com/IDFoundry/FAPIgo/commit/d2bc7e7fa3b6958e58d712119eb3bfc446b0c8a1))
* **server:** limit a subject ID to 255 printable ASCII characters ([dc25fd9](https://github.com/IDFoundry/FAPIgo/commit/dc25fd99cfefdcc9b96e367f9b0774b599441252))

## [0.52.1](https://github.com/IDFoundry/FAPIgo/compare/v0.52.0...v0.52.1) (2026-10-09)


### Bug Fixes

* **federation:** share the registration cache fairly between superiors ([e239dd6](https://github.com/IDFoundry/FAPIgo/commit/e239dd6be53050bfe5700736cebe6c56a7c2dcb4))

## [0.52.0](https://github.com/IDFoundry/FAPIgo/compare/v0.51.0...v0.52.0) (2026-10-09)


### ⚠ BREAKING CHANGES

* **server:** under production assurance with attestation-based client authentication, server.New refuses an X5CAttesterChain whose TrustAnchors or Anchors source does not implement keys.KeySourceAssurance declaring LiveFetchHardened. StaticAttesterTrustAnchors and StaticAttesterAnchors already do. See UPGRADING.md for v0.52.0.
* **keys:** keys.NewKeyManagerFromSigners takes a []keys.SignerSpec and options instead of separate signer, algorithm and kid maps. See UPGRADING.md for v0.52.0.
* **client:** BackchannelAuthenticationSession's MarshalText and UnmarshalText and client.ParseBackchannelAuthenticationSession are removed in favour of client.BackchannelSessionSealer, and sessions stored by earlier versions don't open. RefreshTokens refuses a TokenSet from another issuer and one recording no issuer without a matching ID token, and TokenSetSealer.Seal refuses a set from another issuer. client.New refuses an unacceptable Config.RedirectURI. client.ErrorAuthorizationDenied is removed. See UPGRADING.md for v0.52.0.
* **extension:** extension.Definition's Sensitive bool is replaced by a Sensitivity field (NotSensitive or Sensitive), and NewRegistry refuses a definition that leaves it unset. See UPGRADING.md for v0.52.0.
* server.Config.HorizontallyScaled and resource.Config.HorizontallyScaled are replaced by a Deployment field (DeploymentSingleInstance or DeploymentHorizontallyScaled), and under AssuranceProduction server.New and resource.NewVerifier refuse a configuration that leaves it unset. See UPGRADING.md for v0.52.0.
* **server:** server.New refuses an extension returning a grant_type or code_grant_id claim in tokens, and resource.Verifier refuses a token whose grant_type claim is anything other than client_credentials. A resource server serving both end-user and client credentials tokens should authorize by AuthorizationContext.SubjectKind as well as Subject. See UPGRADING.md for v0.52.0.
* **federation:** federation.Resolver.VerifyTrustMark takes the subject's ResolvedEntity, as Resolve returned it, in place of its Entity Identifier, and refuses a Trust Mark whose issuer can't be trusted through the subject's own Trust Anchor. See UPGRADING.md for v0.52.0.
* **server:** a request whose claims parameter asks for the ID token's acr as an Essential Claim with values now fails when the application completes it at another class: login_required for the redirect flow, access_denied at the CIBA poll. Authenticate at one of InteractionRequest.EssentialACRValues, or complete with AuthenticationFailed. A malformed id_token acr entry is refused as invalid_request. See UPGRADING.md for v0.52.0.

### Features

* **extension:** require each extension definition to declare its Sensitivity ([9de5ead](https://github.com/IDFoundry/FAPIgo/commit/9de5ead259f18bcd5a09e9fdcbdbcd100bbff5c1))
* **fapihttp:** RecommendedTransportConfig and RecommendedConfig ([c7354fd](https://github.com/IDFoundry/FAPIgo/commit/c7354fd7ede75ecec88785b05b60a867fe837cc1))
* **keys:** build signer key managers from one SignerSpec per purpose ([42ead83](https://github.com/IDFoundry/FAPIgo/commit/42ead839a5b6c4052d9e1375a9cefc7cdf3941cf))
* replace HorizontallyScaled with a required Deployment ([f4fefc0](https://github.com/IDFoundry/FAPIgo/commit/f4fefc0a49f60fa0e67e0868ce4f98d3592fbe18))
* **server:** Metadata.WriteJSON ([792ccd6](https://github.com/IDFoundry/FAPIgo/commit/792ccd674ebdb91264691b27dd29bf61302eac9d))
* **storage:** contract suites for the revocation store and client repository ([aa95069](https://github.com/IDFoundry/FAPIgo/commit/aa950699051d7de7b0aeb2c69e828921f82ae526))


### Bug Fixes

* bump Go toolchain to 1.26.9 for GO-2026-6617 ([6bec8b9](https://github.com/IDFoundry/FAPIgo/commit/6bec8b92fd0bd9f346b0995bddca245b902521bb))
* **client:** keep ResourceClient.Do off the caller's request ([31134b5](https://github.com/IDFoundry/FAPIgo/commit/31134b5ddcaef67faefaf05743730117d663f9cc))
* **client:** seal stored CIBA sessions, bind token sets to their issuer, check the redirect URI at New ([26552a0](https://github.com/IDFoundry/FAPIgo/commit/26552a0f92604ae4901a25ec3b6ec2150aadc778))
* **conformance:** require a bearer token for the trust-anchor admin endpoint ([c740cfb](https://github.com/IDFoundry/FAPIgo/commit/c740cfb14db7ae7a2b51cac18ffdff0ee2b1260d))
* **extension:** refuse repeated and miscased members in extension values ([5cb6eaa](https://github.com/IDFoundry/FAPIgo/commit/5cb6eaa792f9d3ff8e21e789d1da234d6b1753ea))
* **federation:** bound the automatic registration cache ([f4f344f](https://github.com/IDFoundry/FAPIgo/commit/f4f344fd5d3a9c123b25a8f6a7e380375edd7f26))
* **federation:** judge a Trust Mark by its subject's Trust Anchor ([5f16450](https://github.com/IDFoundry/FAPIgo/commit/5f164504ae8a2b2deeec314a23fd5d5c1114caa8))
* **federation:** require an ASCII host in an Entity Identifier ([01d437d](https://github.com/IDFoundry/FAPIgo/commit/01d437de08516d26055cf08f984b1e8f36457844))
* report every production assurance refusal at once ([778e6ce](https://github.com/IDFoundry/FAPIgo/commit/778e6ce959a771bc99217191895b84696a1df822))
* resolve every signing key at New, not at first use ([ac294b7](https://github.com/IDFoundry/FAPIgo/commit/ac294b789c1a3bcaaf5c81508ccd2d6fec4f5688))
* **resource:** refuse a resolved access token with no revocation key ([3aba5e2](https://github.com/IDFoundry/FAPIgo/commit/3aba5e253ed44e54547b558d3ed7904c96ffa139))
* revoke everything issued from a reused code, and mark client credentials tokens ([4c3d1d3](https://github.com/IDFoundry/FAPIgo/commit/4c3d1d3ec0458aa9e5655aadb374f46890663a28))
* **server:** audit an unverified client_id at the authorization endpoint as no client ([8e0396b](https://github.com/IDFoundry/FAPIgo/commit/8e0396b42722de169b5acb0d2ec8713c03f74953))
* **server:** enforce an essential acr request ([#609](https://github.com/IDFoundry/FAPIgo/issues/609)) ([35a44b4](https://github.com/IDFoundry/FAPIgo/commit/35a44b4489abeb04e70071b112685320ebca835a))
* **server:** honour dpop_jkt in a CIBA backchannel authentication request ([ac5429f](https://github.com/IDFoundry/FAPIgo/commit/ac5429f7f4cad259b63b463d12d20a83d20f18d0))
* **server:** re-check the client's registration at the code exchange ([a4c0407](https://github.com/IDFoundry/FAPIgo/commit/a4c04075345f4d9ae208954d467097bb83473c2b))
* **server:** refuse a malformed claims parameter instead of ignoring it ([9c0b330](https://github.com/IDFoundry/FAPIgo/commit/9c0b33062dbf6e4afb890c2f023966c487cc3a44))
* **server:** require a hardened attester trust-anchor source in production ([ac08345](https://github.com/IDFoundry/FAPIgo/commit/ac0834513cfb0950221c516a91524f4836238ac9))
* **server:** require the CIBA identity hint to be a non-empty string ([93e4045](https://github.com/IDFoundry/FAPIgo/commit/93e404574a68e41f2d5109c00c139d632d4094d8))
* **server:** reserve the grant_type and code_grant_id token claims ([52dd7e4](https://github.com/IDFoundry/FAPIgo/commit/52dd7e4e8271c2cfa5bc6a0482fbfc861a37af09))
* **server:** scope replay records to the client or DPoP key that used them ([5f4d047](https://github.com/IDFoundry/FAPIgo/commit/5f4d047eeda41ea8b927af595cd6d366b04c78fc))
* **server:** send an application's reason as error_description only when it's error text ([bd81630](https://github.com/IDFoundry/FAPIgo/commit/bd816306a25c6c1a433d73ed11e1ef7d11f9c877))

## [0.51.0](https://github.com/IDFoundry/FAPIgo/compare/v0.50.1...v0.51.0) (2026-10-08)


### Features

* **fapihttp:** TransportConfig.VerifyConnection, for checks after the TLS handshake ([3377a3f](https://github.com/IDFoundry/FAPIgo/commit/3377a3fb2418323cfbd290ceb01eb01009db72ac))


### Bug Fixes

* **jwe:** build on 32-bit platforms ([#602](https://github.com/IDFoundry/FAPIgo/issues/602)) ([40885c7](https://github.com/IDFoundry/FAPIgo/commit/40885c78070fd20814170763b05add0aec3b4437))

## [0.50.1](https://github.com/IDFoundry/FAPIgo/compare/v0.50.0...v0.50.1) (2026-10-07)


### Bug Fixes

* cite the sections RFC 8705 and OpenID Federation define ([47ae458](https://github.com/IDFoundry/FAPIgo/commit/47ae458b9248b9455d831a0114d66d5d5e9ad306))
* **conformance:** make setup-config print usage on -h instead of rewriting configs ([e338f89](https://github.com/IDFoundry/FAPIgo/commit/e338f895bb5ff874c559dcf8cd5f96ae8d2f31fa))
* **resource:** honour a resolver's wrapped *Error ([79075d5](https://github.com/IDFoundry/FAPIgo/commit/79075d502178810e8e5a2e802bc895d777783f73))
* **server:** answer a client-store outage with 500, not invalid_client ([dd84b1c](https://github.com/IDFoundry/FAPIgo/commit/dd84b1c7499c9fbd48dd8c0e9f5a3cae70d2adbd))
* **server:** leave ID token and UserInfo metadata out of an OAuthOnly server ([1d1744b](https://github.com/IDFoundry/FAPIgo/commit/1d1744b9c383e3b08554d5fa5b467e7c90c60141))

## [0.50.0](https://github.com/IDFoundry/FAPIgo/compare/v0.49.0...v0.50.0) (2026-10-05)


### ⚠ BREAKING CHANGES

* **client:** client.Config.TolerateUserInfoSubjectEqualsClientID is removed, and FetchUserInfo always requires the UserInfo response's sub to exactly match the ID token's sub. Remove the field from your client configuration. See UPGRADING.md for v0.50.0.
* **server:** a request with prompt=login that the application completes with an authentication time earlier than the request, such as an existing session's, now gets login_required instead of a code. Authenticate the user again for such a request and report when they did. See UPGRADING.md for v0.50.0.
* **resource:** resource.Config has a required Assurance field, and resource.NewVerifier refuses a Config without one. Set it to resource.AssuranceDevelopment, or to resource.AssuranceProduction with stores and key sources that declare their capabilities. Verifiers built with serverresource.NewVerifier are unaffected. See UPGRADING.md for v0.50.0.
* **server:** under production assurance with CIBA configured, server.New refuses a BackchannelNotifier that does not implement server.BackchannelNotifierAssurance declaring OutboundHardened. backchannelhttp.Notifier and NoBackchannelNotifications already do. See UPGRADING.md for v0.50.0.
* under production assurance, client.New refuses an issuer or endpoint parsed with fapi.AllowLoopbackHTTP, and server.New refuses such a URL in Config.MTLSEndpoints. See UPGRADING.md for v0.50.0.
* **server:** server.RegisteredAttesterKeys needs a keys.AttesterKeySource holding each attester's keys by issuer, and no longer reads attester keys from Dependencies.ClientKeys; keys.AttestationVerification is removed. See UPGRADING.md for v0.50.0.
* **federation:** federation.ResolveRequest has a required ExpectedIssuer field naming the resolver whose Resolve Response is trusted, typically the Trust Anchor; ResolveViaEndpoint refuses a request without it and a response issued by anyone else. See UPGRADING.md for v0.50.0.

### Features

* **resource:** require an assurance level for the resource server ([9c8f4d7](https://github.com/IDFoundry/FAPIgo/commit/9c8f4d7e8e0c2d5ba53cab74698dd3aee9981af0))
* **server:** bind attester trust anchors to the attesters they vouch for ([407a304](https://github.com/IDFoundry/FAPIgo/commit/407a30438126dcc9c019097258326af3952885f4))
* **server:** enforce prompt=login at CompleteAuthorization ([a816cfa](https://github.com/IDFoundry/FAPIgo/commit/a816cfa7f824f75dd9f3edc61ed2402175df7756))
* **serverresource:** sign a UserInfo response for the access token's own client ([979fb41](https://github.com/IDFoundry/FAPIgo/commit/979fb4137ac72a7146a90146cced264dc970e560))
* **server:** surface the authorization request's prompt, and answer prompt=none ([9b8207e](https://github.com/IDFoundry/FAPIgo/commit/9b8207e29c67b0212d975c59036be6519115eb22))
* **storage:** let a store say it couldn't answer, with ErrStoreUnavailable ([06768a4](https://github.com/IDFoundry/FAPIgo/commit/06768a4d556239190d26c8aae2ea8aeb53c0d181))


### Bug Fixes

* **client:** never let a wrapping HTTPClient resend a request body ([6dd5e06](https://github.com/IDFoundry/FAPIgo/commit/6dd5e06e949b4d206a700127dd628d2f3addbcee))
* **client:** remove the UserInfo sub-equals-client_id toleration ([ebe50d6](https://github.com/IDFoundry/FAPIgo/commit/ebe50d616a7abde169a6f29a9c8c4ad46e2dbd0e))
* declare outbound fetching hardened only without a loopback exception ([1e6f228](https://github.com/IDFoundry/FAPIgo/commit/1e6f2280e14fd1975e08f80bfd62205973801fd1))
* **federation:** remember a failed automatic registration briefly ([1c6590f](https://github.com/IDFoundry/FAPIgo/commit/1c6590f478bc026b341d573a3bab67b0e4e56932))
* **federation:** report every failed branch when no trust chain resolves ([8f93a04](https://github.com/IDFoundry/FAPIgo/commit/8f93a042d0278d1a443a48a0895f633d1330de46))
* **federation:** say that Limits.MaxPathLength counts superiors ([23a52f1](https://github.com/IDFoundry/FAPIgo/commit/23a52f1db39cbf9adca0956e28359613f700a7d3))
* **federation:** trust a Resolve Response only from the resolver the caller names ([27d52e3](https://github.com/IDFoundry/FAPIgo/commit/27d52e3d63eb739d06d82ca90c074b6b4a6f166d))
* **keys:** bound the ephemeral client key source's refetches ([a954135](https://github.com/IDFoundry/FAPIgo/commit/a95413528e13372353e41d6b0f18213a8a7f9705))
* **keys:** refuse a published JWKS kid that names two different keys ([b50159e](https://github.com/IDFoundry/FAPIgo/commit/b50159eb2400261e85d4fe6e095c3dfb8cea59c8))
* refuse loopback http issuers and endpoints under production assurance ([8f17ee3](https://github.com/IDFoundry/FAPIgo/commit/8f17ee37827225b73faf77491be887b6211bd2ed))
* **resource:** answer a client-store outage with 500, refuse incomplete resolvers, keep empty codes to 401 ([5245db0](https://github.com/IDFoundry/FAPIgo/commit/5245db073842eb54bcc4542a65b607e71ecb9dfe))
* **resource:** answer insufficient_scope in the token's scheme and validate NewError ([64a8df0](https://github.com/IDFoundry/FAPIgo/commit/64a8df021bb771fcad7a18be9fcf9c5555b119ba))
* **server:** judge outstanding grants by the current lifetimes, so revocation can't lapse ([daecd42](https://github.com/IDFoundry/FAPIgo/commit/daecd420191eff70620993e5ae381d7d37d5c845))
* **server:** keep a CIBA approval unspent when another client polls for it ([29046c1](https://github.com/IDFoundry/FAPIgo/commit/29046c1ce87c7480451c0a6c5a858acc354da490))
* **server:** keep an unused code for its own client when another presents it ([67267e0](https://github.com/IDFoundry/FAPIgo/commit/67267e0cd7fd2a6b2b733855a62824ffa8fe9d9a))
* **server:** match tls_client_auth subject DNs on the certificate's own subject ([68a6ed9](https://github.com/IDFoundry/FAPIgo/commit/68a6ed9476bcb2d20a9000cd1b3544b23bdaca4d))
* **server:** put only requested identity claims into the ID token ([5868bc2](https://github.com/IDFoundry/FAPIgo/commit/5868bc25b2cb65da903030245f5bea440bf160fa))
* **server:** refuse a CIBA decision made after the request expired ([ce8beba](https://github.com/IDFoundry/FAPIgo/commit/ce8bebab1d270e98f0fd681a99162c2e4623db0b))
* **server:** refuse openid and offline_access in the client_credentials grant ([92b0a4d](https://github.com/IDFoundry/FAPIgo/commit/92b0a4d232405537af494ea18ffc67de1dd3d2b1))
* **server:** require a hardened CIBA notifier under production assurance ([bc9a12b](https://github.com/IDFoundry/FAPIgo/commit/bc9a12b5c66d45d17ef63cdb6cc580ed2c5cb3d9))
* **server:** revoke a refresh token's grant first, and search past the token type hint ([970e087](https://github.com/IDFoundry/FAPIgo/commit/970e087b1575d467d2536cc810e9a630112c2b92))
* **server:** revoke on code reuse only for the code's own client ([d13a995](https://github.com/IDFoundry/FAPIgo/commit/d13a995f17f26c6038b3c1118a25cef1c2e5f005))
* **server:** verify registered attestations with the attester's own keys ([f0546c6](https://github.com/IDFoundry/FAPIgo/commit/f0546c689ce706dbc9ef645ade39c882d7a166c1))
* stop outbound clients following redirects, and harden ResourceClient.Do ([61fc2f4](https://github.com/IDFoundry/FAPIgo/commit/61fc2f42bd3eb50d8839c9d7ad55701a2e7d9243))
* tighten JOSE parsing — explicit typ, crit, canonical base64, Ed25519 keys ([0c3829a](https://github.com/IDFoundry/FAPIgo/commit/0c3829ab55723a1d8aa8bfb3d11d7035fbff7862))

## [0.49.0](https://github.com/IDFoundry/FAPIgo/compare/v0.48.1...v0.49.0) (2026-10-04)


### ⚠ BREAKING CHANGES

* **server:** under AssuranceProduction, a custom AccessTokenIssuer must implement server.AccessTokenIssuerAssurance, naming its signing keys or token store, or New refuses it. Development assurance, JWTAccessTokens, OpaqueAccessTokens and types embedding JWTAccessTokens are unaffected. See UPGRADING.md for v0.49.0.

### Bug Fixes

* **client:** refuse max_age without openid when the authorization begins ([6ca20ba](https://github.com/IDFoundry/FAPIgo/commit/6ca20ba99e6f9244f0376d5c1a929e55ff080994))
* **client:** reject malformed JWE lengths instead of panicking ([8d3c92f](https://github.com/IDFoundry/FAPIgo/commit/8d3c92f8999c5db64ff052d923eb90bb29df2e8a))
* **client:** require an ID token when openid was requested ([81d2cdd](https://github.com/IDFoundry/FAPIgo/commit/81d2cddfe5d3dc071510a75dd5fd1283231d1ff2))
* **federation:** keep metadata policy, expiry and naming constraints to the chain ([c26a2c8](https://github.com/IDFoundry/FAPIgo/commit/c26a2c8eac8862b6deba2905b6ed353c13425c05))
* **server:** production assurance checks every access token issuer ([a561ff6](https://github.com/IDFoundry/FAPIgo/commit/a561ff6ee1cf0e1f7aa668a7556ff39ef0ef5674))
* **server:** re-check the client's registration at refresh and CIBA token exchange ([b08e6af](https://github.com/IDFoundry/FAPIgo/commit/b08e6afc40ab9003f710b82ef5dde532e3fe9961))

## [0.48.1](https://github.com/IDFoundry/FAPIgo/compare/v0.48.0...v0.48.1) (2026-10-04)


### Bug Fixes

* **client:** a client authenticating with its TLS certificate now also uses the server's mTLS endpoint aliases for token revocation and the CIBA backchannel authentication endpoint (`MTLSEndpoints.ApplyForClientAuth`, RFC 8705 §5); `ApplyForSenderConstrain` is unchanged ([9a0e000](https://github.com/IDFoundry/FAPIgo/commit/9a0e000b0e9fb5bd075a398f6441398fee810d45))

## [0.48.0](https://github.com/IDFoundry/FAPIgo/compare/v0.47.0...v0.48.0) (2026-10-04)


### ⚠ BREAKING CHANGES

* **server:** Server.RevokeToken returns (TokenRevocationResult, error) instead of error. A handler that doesn't need the result discards it with a blank identifier. See UPGRADING.md for v0.48.0.

### Features

* **server:** RevokeToken reports the grant a revocation ended ([54f7355](https://github.com/IDFoundry/FAPIgo/commit/54f7355c8f21aa84556e447539a3e0a1d8bcab04))

## [0.47.0](https://github.com/IDFoundry/FAPIgo/compare/v0.46.0...v0.47.0) (2026-10-04)


### Features

* **client:** revoke a refresh token (RFC 7009) ([0398aa2](https://github.com/IDFoundry/FAPIgo/commit/0398aa2bf7162a89be63728f3bc96178427d33c2))
* **server:** refresh tokens for grants the embedder serves itself ([83a78e4](https://github.com/IDFoundry/FAPIgo/commit/83a78e458f065aa804a86a0b6467bf4a1e146bec))
* **server:** token revocation endpoint for refresh tokens (RFC 7009) ([2868eae](https://github.com/IDFoundry/FAPIgo/commit/2868eaee5bb02fa812c93c4b086f687d4e9d4c6d)). Revoking a refresh token also revokes its grant by GrantID, which the client can now trigger itself, so give each grant its own GrantID (to revoke everything for a user, call RevokeGrant for each of their grant IDs).


### Bug Fixes

* **client:** name the media type of a non-OAuth error response ([943e4e3](https://github.com/IDFoundry/FAPIgo/commit/943e4e397bc415bc143d6199d599efdfac21173b))
* **server:** bind attested clients' refresh tokens to the instance key ([f3a90c4](https://github.com/IDFoundry/FAPIgo/commit/f3a90c49a7144fb553bef8f77ae68f020f70f173)). Refresh tokens issued before this release carry no instance key, so they stay redeemable as before until they expire (Limits.RefreshTokenLifetime).

## [0.46.0](https://github.com/IDFoundry/FAPIgo/compare/v0.45.0...v0.46.0) (2026-10-03)


### Features

* **client:** complete an authorization from the callback alone in a native app whose session store is its own (Config.CallbackBinding: CallbackBindingDeviceLocalStore) ([c663cac](https://github.com/IDFoundry/FAPIgo/commit/c663cacacb84874430a884a9de42d91d0680f844))


### Bug Fixes

* **client:** cut a malformed error code to 64 bytes in Error() ([676ae3e](https://github.com/IDFoundry/FAPIgo/commit/676ae3e44a1d29f40d2011134591eefb4fc4243b))
* **client:** keep an error response's body out of Error() ([d6644ee](https://github.com/IDFoundry/FAPIgo/commit/d6644ee050adf6d8c71475fa546777296f087887))

## [0.45.0](https://github.com/IDFoundry/FAPIgo/compare/v0.44.0...v0.45.0) (2026-10-03)


### Features

* **client:** pick a loopback redirect port per authorization ([48bfaac](https://github.com/IDFoundry/FAPIgo/commit/48bfaac9263c43583b599f38b9b691089e2024ac))
* **fapitest:** Config.ApplicationType, for tests against a client registered as a native app


### Bug Fixes

* **storage:** refuse a native loopback redirect URI with an unusable port ([541cde2](https://github.com/IDFoundry/FAPIgo/commit/541cde25d037413a393dd64fc2e2b502f5fbe878))

## [0.44.0](https://github.com/IDFoundry/FAPIgo/compare/v0.43.0...v0.44.0) (2026-10-03)


### Features

* **server:** accept native-app redirect URIs for clients registered as native ([d0fae2c](https://github.com/IDFoundry/FAPIgo/commit/d0fae2c377e43c20287eac5792708c0b912339e9))
* **storage:** String, IsValid and ParseApplicationType ([cae4220](https://github.com/IDFoundry/FAPIgo/commit/cae42207065d5cbe538f20f7ee1b43b66332e605))

## [0.43.0](https://github.com/IDFoundry/FAPIgo/compare/v0.42.0...v0.43.0) (2026-10-02)


### ⚠ BREAKING CHANGES

* a client that sends authorization_details must now be registered with every type it requests in storage.RegisteredClientConfig.AuthorizationDetailsTypes (or, for clients registered automatically through OpenID Federation, server.Config.AutomaticRegistration.AuthorizationDetailsTypes), or the request is refused with invalid_authorization_details. An empty list allows no type. See UPGRADING.md for v0.43.0.
* **client:** custom storage.SessionStore implementations must persist NewSession.Record and return it as ConsumedSession.Record, in place of the Nonce, PKCEVerifier, ExpectedIssuer, ExpectedRedirectURI and ExpectedResponseMode fields, which are removed. A client requesting max_age now refuses an ID token without auth_time, or one older than max_age allows. See UPGRADING.md for v0.43.0.

### Features

* **client:** bind the session handle to the browser in an encrypted cookie ([6259639](https://github.com/IDFoundry/FAPIgo/commit/625963966ff659bfb699cc8584f0e29861bbe215))
* **client:** check auth_time against max_age, with an opaque session record ([33d1a03](https://github.com/IDFoundry/FAPIgo/commit/33d1a035b97f6b6ec4e2f34fda4f4f3c1f3caaa5))
* **client:** seal token sets with a TokenSetSealer bound to their owner ([6686ba5](https://github.com/IDFoundry/FAPIgo/commit/6686ba50dadf5bfd49edb114b5741ba48cd658d2))
* **extension:** read the authorization details a token was granted ([fcaf31d](https://github.com/IDFoundry/FAPIgo/commit/fcaf31d7495239c5cf6c9cb940d6c9bbd85cf2c8))
* register the RAR types each client may request ([e2db87d](https://github.com/IDFoundry/FAPIgo/commit/e2db87da6bb2ee5445a067b054e204baf2e38b97))
* **resource,serverresource:** DPoP-Nonce and UserInfo response helpers ([b85f443](https://github.com/IDFoundry/FAPIgo/commit/b85f443e3c72eae38fcb8c90564e5589de6ab03d))
* **resource:** build a VerifyRequest from an http.Request ([3d0574b](https://github.com/IDFoundry/FAPIgo/commit/3d0574b90650d4b4d4178302f1917c8f79c7099b))
* **server:** carry an interaction in one encrypted cookie ([142c0b3](https://github.com/IDFoundry/FAPIgo/commit/142c0b3d1ec6c88f0cf274ce735b142776cf8068))
* **server:** catch client RAR types Config.RAR doesn't register ([9299dde](https://github.com/IDFoundry/FAPIgo/commit/9299ddee5250ee9437cdff6b3c1766b8ba173fcb))
* **server:** read the authorization endpoint's request strictly ([6ccec35](https://github.com/IDFoundry/FAPIgo/commit/6ccec35288f710672196085f36fef403cf090bf7))
* **server:** say when an interaction expires, and expire its cookie then ([5d8794b](https://github.com/IDFoundry/FAPIgo/commit/5d8794b24e70b2e07105e9681461e951bc2d8a6f))


### Bug Fixes

* **client:** refuse a max_age over 100 years when the flow begins ([687e4b4](https://github.com/IDFoundry/FAPIgo/commit/687e4b4db7a4d99e32f9ede9345c9267122da81e))
* **extension:** refuse RAR members that differ only in case ([252d5eb](https://github.com/IDFoundry/FAPIgo/commit/252d5ebf6ce4f59f322e14161c0fe1db09bd93cb))
* **extension:** refuse RAR members that differ only in case at any depth ([99cad87](https://github.com/IDFoundry/FAPIgo/commit/99cad8720ea3fc47e44322126e4b13949bef62a6))
* **resource:** refuse a request with more than one Authorization header ([17dc93b](https://github.com/IDFoundry/FAPIgo/commit/17dc93bf01528cde7d1921a35d995337585c6ce1))
* **server:** answer an unreadable form body as invalid_request ([ee2f80a](https://github.com/IDFoundry/FAPIgo/commit/ee2f80a0a5f3749bb0fbf9732a0856f5c2bd7a6a))

## [0.42.0](https://github.com/IDFoundry/FAPIgo/compare/v0.41.0...v0.42.0) (2026-10-02)


### ⚠ BREAKING CHANGES

* the server now rejects a malformed max_age at the pushed authorization request, and answers login_required when an application completes an authorization with an authentication older than the requested max_age. See UPGRADING.md for v0.42.0.
* **resource:** resource.Verifier answers a Bearer request without a client certificate with 401 invalid_token instead of 400 invalid_request. See UPGRADING.md for v0.42.0.
* **server:** server.TrustedClientCAs now requires Roots and Revocation, and checks certificate validity at Dependencies.Clock's time. See UPGRADING.md for v0.42.0.

### Features

* **client:** redeem refresh tokens with RefreshTokens ([7d07e5d](https://github.com/IDFoundry/FAPIgo/commit/7d07e5d89abf9ee93b5b8ebfd2f9181f63b65cbd))
* **client:** return attestation headers for a request the embedder sends ([90ef3cf](https://github.com/IDFoundry/FAPIgo/commit/90ef3cfc4f6ff830e54de126777c4f586ba4def7))
* **client:** serve client credentials clients that sign nothing ([03f951f](https://github.com/IDFoundry/FAPIgo/commit/03f951f6eba5f019da059de03bee53a2a152fd23))
* **keys:** resolve client encryption keys from a JWK Set in keys/ephemeral ([a608414](https://github.com/IDFoundry/FAPIgo/commit/a60841455d462c43d29b18f8faf8d5736249e64a))
* **server:** authenticate attested clients for grants the server doesn't serve ([b0f5b3f](https://github.com/IDFoundry/FAPIgo/commit/b0f5b3f058bc63e5b324c8d6c8e20f619f78beb8))
* **server:** check client certificates for revocation ([d492fdf](https://github.com/IDFoundry/FAPIgo/commit/d492fdfc0dc32fab419236c2c121769e7e895cc9))
* **server:** revoke a grant as a whole with RevokeGrant ([3eb5617](https://github.com/IDFoundry/FAPIgo/commit/3eb5617a94828d9ab77b456e0dd4e51988eba2f9))
* **server:** serve an embedder's grant at the token endpoint with the server's own checks ([15fdae5](https://github.com/IDFoundry/FAPIgo/commit/15fdae5925f5346f83184c23a181e7e608e6d481))
* surface acr_values and enforce max_age in the authorization code flow ([457532b](https://github.com/IDFoundry/FAPIgo/commit/457532b783a6d5a9aca45dd669e333d6e81db301))


### Bug Fixes

* **client,server:** close the pre-release security review's low findings ([0bfc9bc](https://github.com/IDFoundry/FAPIgo/commit/0bfc9bc3814b0290aa58a0313860e43c84cad570))
* **client:** let NewFromDiscovery build an OAuthOnly client ([2f69f57](https://github.com/IDFoundry/FAPIgo/commit/2f69f57543969d9617584222e98d75d9e691bd38))
* **resource:** answer an mTLS-bound token without a certificate with 401 invalid_token ([fbc7522](https://github.com/IDFoundry/FAPIgo/commit/fbc75223bef31a0cb30cf8f5705d895d76fc2ad4))
* **server:** ask a client_id-only request for client authentication, not a certificate ([1b8bb7a](https://github.com/IDFoundry/FAPIgo/commit/1b8bb7acec781954cc53baeb6946ee9f0225af62))
* **server:** check an intermediate CA's revocation through TrustedClientCAs.Intermediates ([4cfb6c1](https://github.com/IDFoundry/FAPIgo/commit/4cfb6c1c80305b6634fb18470cb6af509be5ed5a))

## [0.41.0](https://github.com/IDFoundry/FAPIgo/compare/v0.40.0...v0.41.0) (2026-09-30)


### ⚠ BREAKING CHANGES

* server and resource report an invalid, replayed or duplicated DPoP proof with the error code invalid_dpop_proof instead of invalid_request or invalid_token; resource answers more than one DPoP header with 401 instead of 400.
* **resource:** a resource request with no credentials, or with an unsupported authorization scheme, now fails with HTTP 401 and an empty error code instead of 400 invalid_request; errors for DPoP-scheme requests are sent in a DPoP challenge.
* **federation:** Entity Identifiers with a query, an empty query or fragment marker, or userinfo are now rejected by ValidEntityID and everywhere an Entity Identifier is resolved or issued.
* **federation:** federation metadata or Entity Statement jwks using a case-variant spelling of a known parameter name is now rejected rather than read as that parameter.
* **federation:** Entity Statements without a header kid, with jwks keys missing or sharing a kid, or with a crit claim are now rejected, where they previously resolved.
* **federation:** an entity listing both an Intermediate and a configured Trust Anchor as authority hints now resolves through the Trust Anchor directly, so the Intermediate's metadata policy no longer applies; entities whose first authority hint was a dead end now resolve instead of failing.
* **federation:** where a superior sets metadata for its subordinate, the resolved metadata now carries the superior's values instead of the subordinate's own.
* **federation:** a Trust Chain whose metadata policies combine operators in a way OpenID Federation 1.0 section 6.1.3 disallows now fails to resolve with a policy error, where it previously resolved.

### Features

* **client:** parse and authenticate CIBA ping callbacks ([3b75148](https://github.com/IDFoundry/FAPIgo/commit/3b75148053676131207fb4d5ac783bdfa35d6c63))
* **client:** store and restore a CIBA session ([f460b72](https://github.com/IDFoundry/FAPIgo/commit/f460b72839edf98998ffcaced98061497b776c3c))
* **federation:** let a SubordinateIssuer parse fetch requests itself ([e28e4ac](https://github.com/IDFoundry/FAPIgo/commit/e28e4aca8f946ddf1c1c3085ea71d7fd3c5071c7))
* **federation:** register every client authentication method an RP supports ([64c8291](https://github.com/IDFoundry/FAPIgo/commit/64c8291debefa51a950f9673c9cf04550264f4bc))
* let CIBA and client-credentials clients omit redirect URIs ([988ef93](https://github.com/IDFoundry/FAPIgo/commit/988ef93af7bc488b4191196cc944fc0b69d98d75))
* **resource:** add ErrorInsufficientScope ([458ddca](https://github.com/IDFoundry/FAPIgo/commit/458ddca56c2f4a3402b94dbe30624d00da198131))
* **server:** look up a pending CIBA request's interaction by handle ([4a9774d](https://github.com/IDFoundry/FAPIgo/commit/4a9774d81309805a4b2a82ec128b3d619b7ebd48))
* **server:** refuse unknown CIBA login hints with unknown_user_id ([7133e72](https://github.com/IDFoundry/FAPIgo/commit/7133e72bf1bb1ae3745dace09392dd1db91e26fb))
* **serverresource:** build a resource verifier from a server's own configuration ([bfca87a](https://github.com/IDFoundry/FAPIgo/commit/bfca87a6eb31f6609ead519b0bf6f8437e325357))
* **server:** store and restore an InteractionRequest ([2da178a](https://github.com/IDFoundry/FAPIgo/commit/2da178a1a232336d5e572a2e194d12bb3738d33c))


### Bug Fixes

* **extension:** accept RARSet's own type member when parsing authorization details ([5545700](https://github.com/IDFoundry/FAPIgo/commit/5545700f1310d9bef03adfad46da4cf68cbdecc5))
* **extension:** accept RARSet's own type member when parsing authorization details ([0f03f00](https://github.com/IDFoundry/FAPIgo/commit/0f03f003b7182a9dab5596f9ce583f1158fbc1ab))
* **federation:** apply a superior's metadata for its subordinate before policy ([5a79bea](https://github.com/IDFoundry/FAPIgo/commit/5a79bea2da33845add579fe267fb8bc1a6845875))
* **federation:** compare metadata policy values in linear time ([78d3393](https://github.com/IDFoundry/FAPIgo/commit/78d339349ab61cd4957f9dd41fd50f56badecb50))
* **federation:** decode federation metadata with case-sensitive member names ([441cca7](https://github.com/IDFoundry/FAPIgo/commit/441cca722d573f6babb8808d107cf0b6befb40a7))
* **federation:** enforce every metadata policy operator combination rule ([cf29c68](https://github.com/IDFoundry/FAPIgo/commit/cf29c680749c3a3f957383953907848dfcd8b88a))
* **federation:** reject Entity Identifiers with a query, fragment or userinfo ([cb4dc27](https://github.com/IDFoundry/FAPIgo/commit/cb4dc27abb302498a6aa047dee8586d5daf81107))
* **federation:** require kid and unique key IDs, reject crit, in Entity Statements ([55144fe](https://github.com/IDFoundry/FAPIgo/commit/55144fe98b7f243840284838a80644af9c29f65d))
* **federation:** try every authority hint when resolving a Trust Chain ([6ffa6ca](https://github.com/IDFoundry/FAPIgo/commit/6ffa6ca5d2e09a7182a2f08259590fa155145de5))
* report an invalid DPoP proof as invalid_dpop_proof ([94586bf](https://github.com/IDFoundry/FAPIgo/commit/94586bf4e680679b92d3bb1295fd82561e0b8c9b))
* **resource:** answer a request without credentials with 401 and no error code ([9f6328a](https://github.com/IDFoundry/FAPIgo/commit/9f6328ae8dd91851e2279ec6c263913a9616590c))
* **serverresource:** don't panic comparing an uncomparable nonce store ([63f7fc3](https://github.com/IDFoundry/FAPIgo/commit/63f7fc30443c1782cbba7dbf439523c77cf5eae7))

## [0.40.0](https://github.com/IDFoundry/FAPIgo/compare/v0.39.0...v0.40.0) (2026-09-30)


### ⚠ BREAKING CHANGES

* **fapihttp:** fapihttp's AllowLoopbackHTTP no longer lets a hostname that merely resolves to a loopback address through; list such names in the new AllowedLoopbackHosts. For https-only local setups use the new AllowLoopbackHosts.

### Features

* **client:** keep the Trust Chain DiscoverViaFederation resolved ([7e987f6](https://github.com/IDFoundry/FAPIgo/commit/7e987f6c07aa56c4be54660e07d4caa6a0351eb2))
* **client:** let NewFromDiscovery fill and check Issuer and Endpoints ([2584377](https://github.com/IDFoundry/FAPIgo/commit/2584377d688f19e4319a2f1cec64c1a639bb27bd))
* **client:** request identity claims with the OIDC claims parameter ([75151b7](https://github.com/IDFoundry/FAPIgo/commit/75151b7fcdfbaed8d1c47a0460b25062b8ca3429))
* **fapihttp:** limit loopback access to literal hosts, split from plain http ([7615576](https://github.com/IDFoundry/FAPIgo/commit/761557690e5d8db6796438351729eaee0582199e))
* **federation:** name the federation types in the public API ([e08e329](https://github.com/IDFoundry/FAPIgo/commit/e08e3291d8bb013bc4a13a962c31e5cbd1515470))
* **federation:** publish Trust Marks in an Entity Configuration ([4954e4c](https://github.com/IDFoundry/FAPIgo/commit/4954e4cff2ee3b7a6d177bedb9ce69b3b5a7c548))
* **federation:** report why automatic registration refused a client ([645c8f5](https://github.com/IDFoundry/FAPIgo/commit/645c8f53b83b6c3b5a87ede1415961e801b8263f))
* **keys:** write a published key set as a JWKS response ([20febaa](https://github.com/IDFoundry/FAPIgo/commit/20febaa29cd1c235271c00ff9421ccb8b83958d2))
* **server:** advertise automatic registration and claims parameter support ([ef96cb4](https://github.com/IDFoundry/FAPIgo/commit/ef96cb4133d8c1dafe342537405f0b9f9056e5ae))
* **server:** build whole PAR, CIBA and token requests from an *http.Request ([b8d8c91](https://github.com/IDFoundry/FAPIgo/commit/b8d8c91f243191957b426a73845eea65b40e4e02))
* **server:** tell the consent screen who the client is ([52b818d](https://github.com/IDFoundry/FAPIgo/commit/52b818d8737dc97133791cb904ca60de0cb28407))


### Bug Fixes

* **client:** reject a callback completed by another issuer's client ([572f7dc](https://github.com/IDFoundry/FAPIgo/commit/572f7dcde0e87c4171bec92982696341573b4957))
* **ephemeral:** reject client key specs NewClientKeySource can't serve ([29f5331](https://github.com/IDFoundry/FAPIgo/commit/29f53318acf14317bdde3c3331fe67a2cf98df76))
* **ephemeral:** treat a key spec with no keys as a client with no keys ([f2391a8](https://github.com/IDFoundry/FAPIgo/commit/f2391a8bb6737c53b3fa71712225917658ad161d))
* **examples:** harden federated-union's consent and scenes, use library presets ([a1f3905](https://github.com/IDFoundry/FAPIgo/commit/a1f390504cb3a069626cd60e295250f0fe408ae0))

## [0.39.0](https://github.com/IDFoundry/FAPIgo/compare/v0.38.0...v0.39.0) (2026-09-28)


### ⚠ BREAKING CHANGES

* **federation:** federation.Resolver.VerifyTrustMark takes a fourth argument, a TrustMarkAccreditation. Pass RequireFederationAccreditation to require the Trust Anchor's accreditation of the issuer, or AcceptAnyFederationIssuer to keep the previous behaviour. Trust Marks without a kid header are rejected.
* **server:** server.New rejects a Config.Extensions registry with a ReturnInTokenClaims definition named like a server-managed claim or an OIDC standard identity claim (for example email, acr or sub). Rename the extension, or drop ReturnInTokenClaims if the value only needs to reach the interaction step.
* **server:** identity claims requested with the OIDC claims parameter are no longer released unless the application approves them. Show InteractionRequest.RequestedClaims (or the backchannel equivalent) to the user and set GrantedAuthorization.ApprovedIdentityClaims to the approved names; nil releases none.
* **backchannelhttp:** backchannelhttp.New takes only a Config; pass the transport settings (dial and TLS handshake timeouts, and any loopback or private-host exceptions) in Config.Transport instead of an HTTP client.
* **federation:** federation.Limits.MaxAuthorityHints (and server.AutomaticRegistrationConfig.MaxAuthorityHints when automatic registration is configured) is required, and NewResolver rejects zero. Set it to a small positive number such as 5.

### Features

* **federation:** bound authority_hints fetched per Trust Chain resolution ([efe31b4](https://github.com/IDFoundry/FAPIgo/commit/efe31b4b83cfa4578aa31826264c7d672f9284a9))
* **federation:** let VerifyTrustMark require the federation's accreditation of the issuer ([85e4aa3](https://github.com/IDFoundry/FAPIgo/commit/85e4aa32019ea79aaa7f4f84f3c457e76ba56549))
* **server:** release requested identity claims only once the user approves them ([a53a820](https://github.com/IDFoundry/FAPIgo/commit/a53a8201c71e969fb74218dfd765f0fd03235f9a))


### Bug Fixes

* **backchannelhttp:** always send CIBA ping notifications through a guarded client ([ec7b924](https://github.com/IDFoundry/FAPIgo/commit/ec7b924f2bd7ac799c5b0d636e3379d7e412a17b))
* **fapihttp:** block the RFC 8215 local-use NAT64 prefix ([00a13ed](https://github.com/IDFoundry/FAPIgo/commit/00a13edb4d638e8d7e012e6afc9ea0ac4cbdde46))
* **resource:** record DPoP nonces and jtis only for a valid access token ([f4aeae6](https://github.com/IDFoundry/FAPIgo/commit/f4aeae6ed75fcf378c9e3249d9cea84b130eb190))
* **server:** bound request parameter count and size for hand-built forms ([5be5256](https://github.com/IDFoundry/FAPIgo/commit/5be52565c0bca611cfc78390c82ee6344b83dd79))
* **server:** clamp requested_expiry before converting it to a duration ([b4e97a5](https://github.com/IDFoundry/FAPIgo/commit/b4e97a50379817f0346415a839e0f161b84b41fa))
* **server:** reject a client_id that doesn't match the client assertion ([5a01223](https://github.com/IDFoundry/FAPIgo/commit/5a0122387d82d05a8f58b43aeb47f242bf9a279a))
* **server:** reject token-claim extensions named like managed claims ([2efd2d9](https://github.com/IDFoundry/FAPIgo/commit/2efd2d963a33c4a22047eb6006cf39db549c4733))

## [0.38.0](https://github.com/IDFoundry/FAPIgo/compare/v0.37.0...v0.38.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* under AssuranceProduction, server.New and client.New now reject any Dependencies.Random other than crypto/rand.Reader, including a wrapper around it. Pass crypto/rand.Reader directly.

### Features

* **client:** expose the server's OAuth error response on client.Error ([c006df8](https://github.com/IDFoundry/FAPIgo/commit/c006df8a5a8149fb3c7305c3ec0be6af490d2b8c))
* require crypto/rand.Reader as Dependencies.Random under production assurance ([5c2c82e](https://github.com/IDFoundry/FAPIgo/commit/5c2c82e6869ebccb89562f41a9ca198d909579bd))


### Bug Fixes

* reject case-variant JSON member names in JOSE and metadata parsing ([707772e](https://github.com/IDFoundry/FAPIgo/commit/707772ec3bb673a838f9bba25fc8b994d6fd40db))
* **server:** return invalid_scope for a scope the client isn't allowed ([02cf7e0](https://github.com/IDFoundry/FAPIgo/commit/02cf7e0624b1c7095c17780a735277dbe1127070))

## [0.37.0](https://github.com/IDFoundry/FAPIgo/compare/v0.36.0...v0.37.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* **client:** AuthorizationCallback now requires Session, and a callback without one is rejected. Store the SessionHandle from BeginAuthorization in an HttpOnly, Secure, SameSite=Lax cookie when redirecting the browser, read it back with client.ParseSessionHandle when the callback arrives, and pass it as Session. fapitest's RunAuthorizationCodeFlowWithCallback now takes the session handle as its second argument.
* under AssuranceProduction, server and client signing keys and client decryption keys must declare durable key custody. Pass keys.DeclareCustody to keys.NewKeyManagerFromSigners, keys.NewDecrypter or keys.NewSingleKeyDecrypter, or implement keys.KeyCustodyAssurance on a custom KeyManager or Decrypter. keys/ephemeral is rejected in production.

### Features

* require declared key custody for signing and decryption keys in production ([0168303](https://github.com/IDFoundry/FAPIgo/commit/01683037d501aa7eb493bf114b83b9470e198bbe))


### Bug Fixes

* **client:** bind authorization callbacks to the user agent that began the flow ([59618e7](https://github.com/IDFoundry/FAPIgo/commit/59618e7525f156b73a4399774a6d5ab9a7199e5c))

## [0.36.0](https://github.com/IDFoundry/FAPIgo/compare/v0.35.0...v0.36.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* **server:** X5CAttesterChain now requires IssuerBinding, and New rejects the zero value. Choose AttesterIssuerInCertificate when attester certificates carry the attester identifier as a URI SAN (the signing certificate must name the client's ExpectedAttesterIssuer), or AttesterIssuerByTrustAnchors when each client's trust anchors belong to its attester alone. Without a binding, any attester certified under a shared anchor could authenticate as another attester's clients ([#393](https://github.com/IDFoundry/FAPIgo/issues/393))

### Features

* **server:** bind X5CAttesterChain certificates to the client's attester ([#393](https://github.com/IDFoundry/FAPIgo/issues/393)) ([5d7f413](https://github.com/IDFoundry/FAPIgo/commit/5d7f41391337666bf03e3bc4754f1a0f8c6528aa))


### Bug Fixes

* **server:** reserve c_hash and s_hash in application ID token claims ([a1c4e4f](https://github.com/IDFoundry/FAPIgo/commit/a1c4e4f1939014c43786fbd13440a5b190cf9529))

## [0.35.0](https://github.com/IDFoundry/FAPIgo/compare/v0.34.0...v0.35.0) (2026-09-27)


### Features

* **client:** add Config.OAuthOnly for clients that never handle ID tokens ([7456ab4](https://github.com/IDFoundry/FAPIgo/commit/7456ab4a19b0d392a58b44dd6acdf7e083d6fba1))
* **client:** add StaticAttestation for a wallet holding one attestation ([01b7d30](https://github.com/IDFoundry/FAPIgo/commit/01b7d301633e25d79cbb568a5bbf1050b79d1f67))
* **keys:** add LocalIssuerKeys for verifiers in the authorization server's process ([4190b90](https://github.com/IDFoundry/FAPIgo/commit/4190b90643dc2115882cf74f719a75da06927005))
* **server:** expose registered extension values at the interaction step ([e7baf03](https://github.com/IDFoundry/FAPIgo/commit/e7baf039ab6bd995d63a6a2ba15324d75fe25d85))


### Bug Fixes

* **client:** require Limits.MaxIDTokenLifetime only when ID tokens are possible ([e1b3e27](https://github.com/IDFoundry/FAPIgo/commit/e1b3e27377fbea4f7cd80b820f395ef2c77f0921))

## [0.34.0](https://github.com/IDFoundry/FAPIgo/compare/v0.33.0...v0.34.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* **server:** a server with Config.AttestationBasedClientAuthentication set must supply Dependencies.AttesterTrust — New rejects nil. Pass server.RegisteredAttesterKeys{} to keep the previous behaviour, or server.X5CAttesterChain{TrustAnchors: ...} to verify the attestation's x5c certificate chain (HAIP 1.0 §4.4.1).

### Features

* **server:** verify client attestations by their x5c certificate chain ([325f5ec](https://github.com/IDFoundry/FAPIgo/commit/325f5ec0dde79c5f3cc1efb40fe8a9b7682479ab))

## [0.33.0](https://github.com/IDFoundry/FAPIgo/compare/v0.32.0...v0.33.0) (2026-09-26)


### ⚠ BREAKING CHANGES

* **server:** Limits.MaxIDTokenClaimsBytes is required unless Config.OAuthOnly is set — New rejects a zero value, like every other Limits field. Configs built from RecommendedLimits() get 4096; a hand-built Limits must set it.
* **storage:** custom TransactionStore, GrantStore and BackchannelAuthenticationStore implementations must replace the removed per-field columns with a single Request or Grant value, persisted and returned unmodified. Records written by a previous version cannot be read after upgrading; they are all short-lived (pushed requests, authorization codes, CIBA requests) except refresh tokens, which clients must re-obtain.

### Features

* add client PushedRequestEncoding and fix federation RP conformance ([#371](https://github.com/IDFoundry/FAPIgo/issues/371)) ([28333c3](https://github.com/IDFoundry/FAPIgo/commit/28333c355f584c8b5aff2271c6a349c1ed54bac3))
* **server:** add Limits.MaxIDTokenClaimsBytes to bound ID token size ([dc4e077](https://github.com/IDFoundry/FAPIgo/commit/dc4e077c0e704f2b1429bf0e48d34fb03709283b))
* **server:** application-supplied ID token claims at authorization time ([a09b7cb](https://github.com/IDFoundry/FAPIgo/commit/a09b7cb8936c6fe70386de68522ee54503607e6f))
* **storage:** persist grants and requests as opaque server-owned payloads ([4c23620](https://github.com/IDFoundry/FAPIgo/commit/4c2362062703d77c75b136e8fc17fcb9c2fe95d8))


### Bug Fixes

* **server:** accept loopback http redirect URIs outside production ([fa0be87](https://github.com/IDFoundry/FAPIgo/commit/fa0be8730838b6dbcb23068f0155823ed379898e))
* **server:** reject invalid UTF-8 subject, acr/amr and ID token claim names ([26546be](https://github.com/IDFoundry/FAPIgo/commit/26546be1f949bfaa8ecea469f1ef1b25bc6a8c52))
* treat a bracketed IPv6 loopback host without a port as loopback ([4a52e60](https://github.com/IDFoundry/FAPIgo/commit/4a52e609303afd9c30755e33fd75d00e094f69cc))

## [0.32.0](https://github.com/IDFoundry/FAPIgo/compare/v0.31.0...v0.32.0) (2026-09-23)


### Features

* add AllowedClientAuthMethods to federation automatic registration ([#366](https://github.com/IDFoundry/FAPIgo/issues/366)) ([cdad8e2](https://github.com/IDFoundry/FAPIgo/commit/cdad8e29a2f06d493225ee32d8305d673993262e))


### Bug Fixes

* accept only the issuer as client assertion aud for non-CIBA clients ([#370](https://github.com/IDFoundry/FAPIgo/issues/370)) ([3f94297](https://github.com/IDFoundry/FAPIgo/commit/3f94297fa153f574ad180743ecd739bddf43cfe4))
* return unauthorized_client for clients not permitted to use CIBA ([e598c3c](https://github.com/IDFoundry/FAPIgo/commit/e598c3c5d2e479954417152532c598bc9b8ce3a5))

## [0.31.0](https://github.com/IDFoundry/FAPIgo/compare/v0.30.0...v0.31.0) (2026-09-19)


### ⚠ BREAKING CHANGES

* client.Config.RequireAuthorizationResponseIss (bool) is renamed to AuthorizationResponseIssPolicy (AuthorizationResponseIssPolicy) and is now required. Existing callers must set it explicitly: RequireAuthorizationResponseIss (matches former true) or TolerateAbsentAuthorizationResponseIss (matches former false/zero value).

### Features

* gate ClientKeySource/IssuerKeySource/ClientEncryptionKeySource behind KeySourceAssurance ([54497b9](https://github.com/IDFoundry/FAPIgo/commit/54497b959cb9b3202604dd5c374a9dd1e4e6216b))
* require explicit AuthorizationResponseIssPolicy ([ef83978](https://github.com/IDFoundry/FAPIgo/commit/ef839780c4d304378990a21d08cd1a52545f7c28))


### Bug Fixes

* bump Go toolchain to 1.26.6 for 6 stdlib CVEs ([51804e2](https://github.com/IDFoundry/FAPIgo/commit/51804e250cfc3417579ae8aae9b51cd9315b6149))

## [0.30.0](https://github.com/IDFoundry/FAPIgo/compare/v0.29.0...v0.30.0) (2026-09-18)


### ⚠ BREAKING CHANGES

* server.Dependencies.MTLSClientCAs is renamed to ClientCertificateTrust and is now required. Existing callers that left it unset must add ClientCertificateTrust: server.NoClientCertificateChainTrust{} (matching prior behavior) or server.TrustedClientCAs{Roots: ...} (enabling this package's own chain check); callers that already set MTLSClientCAs should switch to

### Features

* add DPoP claim-mismatch and PAR round-trip fuzz targets ([50259c7](https://github.com/IDFoundry/FAPIgo/commit/50259c7eb5c0999877e53b00bf0dfa83e6362371))
* add DPoP claim-mismatch and PAR round-trip fuzz targets ([ba6fc11](https://github.com/IDFoundry/FAPIgo/commit/ba6fc1147985b8c375f643c59c6320c26609eaba))
* add DPoP/client-attestation header extraction helpers ([125fbdd](https://github.com/IDFoundry/FAPIgo/commit/125fbdd0ca207fae51a426cb63e204b197af4324))
* add DPoP/client-attestation header extraction helpers ([f7b319c](https://github.com/IDFoundry/FAPIgo/commit/f7b319c86d9d1443e2a57be94affd060893cba01))
* add fuzz target for internal/jwe.Decrypt ([#347](https://github.com/IDFoundry/FAPIgo/issues/347)) ([639aebb](https://github.com/IDFoundry/FAPIgo/commit/639aebbee6fde562e9fdad0d40c1f2a0aa497af9))
* add fuzz targets for federation Entity Statement/Trust Mark parsing ([0ae76f2](https://github.com/IDFoundry/FAPIgo/commit/0ae76f2834375a3a78c86b31f7ef4719f6658533))
* add fuzz targets for JARM responses and access/ID tokens ([8ef0de0](https://github.com/IDFoundry/FAPIgo/commit/8ef0de01da63020e731fa034c105c943e1b35846))
* add fuzz targets for PAR form decoding and metadata parsing ([68c857f](https://github.com/IDFoundry/FAPIgo/commit/68c857f1dbd580ff9b6aacd8e2b420b9e4951d6d))
* add fuzz targets for RAR parsing and PAR response decoding ([#351](https://github.com/IDFoundry/FAPIgo/issues/351)) ([fff00c3](https://github.com/IDFoundry/FAPIgo/commit/fff00c3018209d1fe915489ca21065398af7e8cd))
* add fuzz targets for the remaining client-supplied compact JWTs ([4ae502b](https://github.com/IDFoundry/FAPIgo/commit/4ae502b2f4ef9532ebd5c94a7c2b1a5690ab3df9))
* add fuzz targets found in a final security-critical review ([f03085c](https://github.com/IDFoundry/FAPIgo/commit/f03085cc251b39bec8deca4c2f0181142075406f))
* add native Go fuzz targets and a daily fuzz CI job ([#344](https://github.com/IDFoundry/FAPIgo/issues/344)) ([3473b30](https://github.com/IDFoundry/FAPIgo/commit/3473b308534930ec8c67a79b14fefc1ee13e11c1))
* add tamper-detection fuzz targets for jose Sign and jwe Encrypt ([5024eac](https://github.com/IDFoundry/FAPIgo/commit/5024eac4818edda31a93a724cf953fa3a6d5452d))
* add tamper-detection fuzz targets for jose Sign and jwe Encrypt ([1318929](https://github.com/IDFoundry/FAPIgo/commit/131892946d7f0550dabf356449f733666fb3605b))
* **client,server:** defense-in-depth iss/aud/exp checks on signed UserInfo responses ([87f500f](https://github.com/IDFoundry/FAPIgo/commit/87f500f2a36ae3cecdd9a3db9855931cb4a65716))
* **client:** expose validated iss/aud/nonce/azp on IDTokenClaims ([35e7f23](https://github.com/IDFoundry/FAPIgo/commit/35e7f23e8bc98b2004b45edeaa2c4fbbcdfb6ab5))
* complete fuzz coverage for internal/federation's Parse* functions ([46b44cc](https://github.com/IDFoundry/FAPIgo/commit/46b44cc9948c3c927dd6f397f49b6ca2183c5ea7))
* require explicit ClientCertificateTrust for mTLS chain verification ([7e5dc0a](https://github.com/IDFoundry/FAPIgo/commit/7e5dc0ab1e0db3ee00710a1ec451d4b40de6c07b))
* **resource:** expose validated iss/aud/iat on resolved access tokens ([a10d37b](https://github.com/IDFoundry/FAPIgo/commit/a10d37bf2629e13ec40c278416d274bec80eccea))
* **server:** set at_hash when issuing an ID token alongside an access token ([dc81207](https://github.com/IDFoundry/FAPIgo/commit/dc81207d22250edd91f9ee0149b51ae30a817321))


### Bug Fixes

* **client:** verify at_hash when an ID token carries it ([2a7f43c](https://github.com/IDFoundry/FAPIgo/commit/2a7f43c91eb02576fae7f245de00af7fc24ab724))
* recognize a third suite-internal flake signature in retry-flaky-modules ([2929f5a](https://github.com/IDFoundry/FAPIgo/commit/2929f5a1cbca4e07ce537ef9549da1bc04efda80))
* reduce federation.Resolver.finalizeTrustChain's parameter count ([a5bb46e](https://github.com/IDFoundry/FAPIgo/commit/a5bb46e3002044825c7bbd0c2eee05ccbf5e4493))

## [0.29.0](https://github.com/IDFoundry/FAPIgo/compare/v0.28.0...v0.29.0) (2026-09-17)


### ⚠ BREAKING CHANGES

* ignore unrecognized authorization request parameters at PAR/CIBA ([#304](https://github.com/IDFoundry/FAPIgo/issues/304))

### Features

* **client:** add client-side Attestation-Based Client Authentication ([#317](https://github.com/IDFoundry/FAPIgo/issues/317)) ([ca54d10](https://github.com/IDFoundry/FAPIgo/commit/ca54d1019b0300042320f36ba2d8257fa5ff7d9a))
* **client:** add DiscoverViaFederation, the RP-side federation.Resolver consumer ([7d27b57](https://github.com/IDFoundry/FAPIgo/commit/7d27b57dad44b21e4c95df84c5525bdd6e21e619))
* **client:** support the Attestation Challenge claim client-side ([b80054b](https://github.com/IDFoundry/FAPIgo/commit/b80054b777a7e8d5841e8267b48d3dea95817b6b))
* **cmd/conformance-as:** add a runtime Trust Anchor admin endpoint ([e034aed](https://github.com/IDFoundry/FAPIgo/commit/e034aed9e74cf6851d5fdd2a9cac01ba92120ff6))
* **cmd/conformance-client:** add -profile=federation for the OIDF RP test plan ([#321](https://github.com/IDFoundry/FAPIgo/issues/321)) ([7249381](https://github.com/IDFoundry/FAPIgo/commit/7249381d9b51aa21a96e7ba65a9d82c8b6a851fa))
* **conformance:** wire -profile=federation into run-all.sh/CI ([146e44f](https://github.com/IDFoundry/FAPIgo/commit/146e44f9b6696a52e47e0761cc83a11b6e3ecd7b))
* **fapihttp,federation:** serve a live federation_resolve_endpoint ([9d8df42](https://github.com/IDFoundry/FAPIgo/commit/9d8df42693785940510763146f0354469c2b1aa2))
* **fapitest:** add PeerTLSConfig, promoted from cmd/conformance-as ([6553166](https://github.com/IDFoundry/FAPIgo/commit/655316668f296f1596df8b79f35c4b29d19f6c64))
* **fapitest:** add SelfSignedServerCert, promoted from cmd/conformance-client ([d1c7845](https://github.com/IDFoundry/FAPIgo/commit/d1c7845fd51c441cd8a62f2f73ca087b4fb7e717))
* **federation:** add Federation Historical Keys endpoint (§8.7), both sides ([7f66998](https://github.com/IDFoundry/FAPIgo/commit/7f66998b93a8f8d2851a624a8380f2100882176c))
* **federation:** add OpenIDRelyingPartyMetadata, promoted from cmd/conformance-client ([fd20e6a](https://github.com/IDFoundry/FAPIgo/commit/fd20e6a887fd5c954552e16f68a17cbbd9117deb))
* **federation:** add request-parsing support for the Trust Mark endpoint ([fa8a63e](https://github.com/IDFoundry/FAPIgo/commit/fa8a63ece7f8b7998fb5acb44c9be3d1209db883))
* **federation:** add Resolve endpoint (§8.3) support, consumer side ([ccfe4b4](https://github.com/IDFoundry/FAPIgo/commit/ccfe4b4b0f9712ee7b6b8a716df0a9c019b7a3c6))
* **federation:** add ResolveIssuer, the Resolve endpoint producer side ([8211c39](https://github.com/IDFoundry/FAPIgo/commit/8211c39cdb8b30d32978f5dcde7c5a8c97a4a7ec))
* **federation:** add WriteEntityStatement, promoted from 4 conformance binaries ([df72cca](https://github.com/IDFoundry/FAPIgo/commit/df72cca07edabf12b702b3ab6f84cce887af0738))
* **federation:** include verified Trust Marks in a Resolve Response ([6fbf72e](https://github.com/IDFoundry/FAPIgo/commit/6fbf72e808034ed6c9de62b1c2e2872ff26f5e28))
* **federation:** parse and validate Subordinate Listing filter parameters ([8974c1f](https://github.com/IDFoundry/FAPIgo/commit/8974c1f09ea0588db76b75e2fe20ecd1ae3c3d8e))
* **federation:** support every RFC 8705 mTLS method in Automatic Registration ([4012831](https://github.com/IDFoundry/FAPIgo/commit/4012831f9b663b96f478255566f7bd738d7f3e7d))
* implement attestation-based client authentication ([2707dcd](https://github.com/IDFoundry/FAPIgo/commit/2707dcd69529d72dfa752e1d01eb22b732115662))
* **server:** advertise dpop_signing_alg_values_supported and authorization_details_types_supported ([bab2c43](https://github.com/IDFoundry/FAPIgo/commit/bab2c431bf2bc8b952702871bace073c4b8e28af))


### Bug Fixes

* address SonarCloud/CodeQL findings on the trust anchor admin PR ([4d5ed42](https://github.com/IDFoundry/FAPIgo/commit/4d5ed420c3d2d5abd3d6f66bf9ba1fc08a7d537f))
* **client:** stop buildPushedRequestForm mutating its caller's params map ([4756502](https://github.com/IDFoundry/FAPIgo/commit/4756502ed1bc8ee9081f83921225ce8f94935994))
* **cmd/conformance-as:** give the federation resolver its own peer-trusting fetcher ([1cd45be](https://github.com/IDFoundry/FAPIgo/commit/1cd45be98227622ed5f44fbe826e784e91ba85cb))
* **conformance:** detect a silently SKIPPED federation module as unexpected ([#314](https://github.com/IDFoundry/FAPIgo/issues/314)) ([9c58852](https://github.com/IDFoundry/FAPIgo/commit/9c588526deb922c2b04d9e7cc4c4a8725a9da08f))
* deduplicate SelfSignedClientCert/SelfSignedServerCert ([f50594c](https://github.com/IDFoundry/FAPIgo/commit/f50594cf4a71a13d277ec24ceb52ea8e388a27ac))
* **docs:** badge follow-ups from the README refresh ([dcb8a9b](https://github.com/IDFoundry/FAPIgo/commit/dcb8a9be1ce6763155ca4f76bdd85d6de810139e))
* **docs:** drop the retired Go Report Card badge ([61b1a0a](https://github.com/IDFoundry/FAPIgo/commit/61b1a0a9d46f1553654d4be2782c985b258adc98))
* **docs:** serve the OpenID Certified badge with a white background baked in ([ba8d789](https://github.com/IDFoundry/FAPIgo/commit/ba8d789c59269aa084cd613b54cb29f0275f05b3))
* ignore unrecognized authorization request parameters at PAR/CIBA ([#304](https://github.com/IDFoundry/FAPIgo/issues/304)) ([597f2a7](https://github.com/IDFoundry/FAPIgo/commit/597f2a785ed0196b1b1a90e200b4e601f58e6e47))
* move NOSONAR go:S4830 suppression to the line SonarCloud actually reports ([7494381](https://github.com/IDFoundry/FAPIgo/commit/749438105bb40a5fe20928f8b7f23d591480e562))
* place codeql suppression comment on its own line before the alert ([1f0df77](https://github.com/IDFoundry/FAPIgo/commit/1f0df774b41a0a681d1f78ead7db25d417cd04e8))
* **server:** reject a bare request_uri PAR form parameter ([3a3b4df](https://github.com/IDFoundry/FAPIgo/commit/3a3b4dfe252f0ce2fe77d4919e80967fdd9a275d))
* suppress CodeQL's disabled-certificate-check alert on peerTLSConfig ([6ac2903](https://github.com/IDFoundry/FAPIgo/commit/6ac29037d17be703be7bc894bf37ba63b5c487e8))

## [0.28.0](https://github.com/IDFoundry/FAPIgo/compare/v0.27.0...v0.28.0) (2026-09-14)


### ⚠ BREAKING CHANGES

* **client:** add session-store assurance gate mirroring server ([#294](https://github.com/IDFoundry/FAPIgo/issues/294))

### Features

* **backchannelhttp:** add hardened CIBA ping-notification sender ([1cbecc0](https://github.com/IDFoundry/FAPIgo/commit/1cbecc0d421c50b17d27519a759dace17215e2f8))
* **client:** add session-store assurance gate mirroring server ([#294](https://github.com/IDFoundry/FAPIgo/issues/294)) ([ec91ae5](https://github.com/IDFoundry/FAPIgo/commit/ec91ae5745ffa78c48ddf4ad0ae5fd89c7396528))
* **client:** auto-enable RFC 9207 iss enforcement via NewFromDiscovery ([0a2ff9f](https://github.com/IDFoundry/FAPIgo/commit/0a2ff9f9ad4f6a6e490de599c42c1a5b579dbf70))
* **client:** validate declared config against discovery at construction ([ea77381](https://github.com/IDFoundry/FAPIgo/commit/ea77381c50cda9670cecb134388c0efd35df8cd1))
* **fapitest:** export SelfSignedClientCert ([832be68](https://github.com/IDFoundry/FAPIgo/commit/832be6892ab777eb4005146a1d6c9b31bcc5ca27))
* **server:** add AlgorithmSet/KeyManagementAlgorithmSet/ContentEncryptionAlgorithmSet.Strings ([32a346d](https://github.com/IDFoundry/FAPIgo/commit/32a346da4d9bed7c5a008ca8ac431e2a27c479dd))
* **server:** add BackchannelInteractionRequired.WriteJSON ([eadc09c](https://github.com/IDFoundry/FAPIgo/commit/eadc09cd2d81cfdd38c61d8adff66449391566d7))
* **server:** add NewBackchannelNotificationRequest ([77bd584](https://github.com/IDFoundry/FAPIgo/commit/77bd584dff4cff7862ae45f129c44391ea44d991))
* **server:** add optional chain-trust gate for PKI mTLS client auth ([#296](https://github.com/IDFoundry/FAPIgo/issues/296)) ([57d167d](https://github.com/IDFoundry/FAPIgo/commit/57d167dcf84cc4342015936890b23093fccada5c))
* **server:** add ParseInteractionHandle/ParseBackchannelAuthenticationHandle ([#290](https://github.com/IDFoundry/FAPIgo/issues/290)) ([5e2eb37](https://github.com/IDFoundry/FAPIgo/commit/5e2eb37f242cf7ef22da5126a38a05e64b5b72f7))
* **server:** add PushAuthorizationResult.WriteJSON ([1864457](https://github.com/IDFoundry/FAPIgo/commit/1864457af9df76e937cbfff8c62b31357f093a0c))
* **server:** complete AssuranceProduction store-assurance gate ([#295](https://github.com/IDFoundry/FAPIgo/issues/295)) ([f0bd7d9](https://github.com/IDFoundry/FAPIgo/commit/f0bd7d9d9738e48f5904209c348bc71ac031b768))


### Bug Fixes

* **backchannelhttp:** check res.Body.Close error per repo convention ([3c804da](https://github.com/IDFoundry/FAPIgo/commit/3c804da0f57da9856c805325691ebf6476261f29))
* **client:** assert TLS on the PAR/token POST path ([#292](https://github.com/IDFoundry/FAPIgo/issues/292)) ([d5f9c58](https://github.com/IDFoundry/FAPIgo/commit/d5f9c589da3ea01438057ccace94420c03772ace))
* **conformance:** make setup-config self-healing, not a one-time skip ([fa8d898](https://github.com/IDFoundry/FAPIgo/commit/fa8d898b2469fa50e74d88a93c02ea774cdd4b14))
* **conformance:** resync AS test-client public keys with local plan configs ([e9361e4](https://github.com/IDFoundry/FAPIgo/commit/e9361e45010af21b732ea6d5457ce01de4db30b9))
* **jose:** reject RSA keys above a maximum modulus size ([#297](https://github.com/IDFoundry/FAPIgo/issues/297)) ([67afd6f](https://github.com/IDFoundry/FAPIgo/commit/67afd6fad843b85c3862c9772efc77fce524055f))
* **server:** close codecov coverage gap in NewBackchannelNotificationRequest ([79e1c76](https://github.com/IDFoundry/FAPIgo/commit/79e1c7621c6bb526ce355ae340cb8904c59e6f71))

## [0.27.0](https://github.com/IDFoundry/FAPIgo/compare/v0.26.0...v0.27.0) (2026-09-12)


### ⚠ BREAKING CHANGES

* **server:** server.Metadata.BackchannelAuthenticationEndpoint and every field of server.MTLSEndpointAliases are now *fapi.URL, not fapi.URL.

### Features

* **client:** add MTLSEndpoints.ApplyForSenderConstrain/ApplyForClientAuth ([5b1b91f](https://github.com/IDFoundry/FAPIgo/commit/5b1b91faed5e56cacfdc2f84baedf92ed7718e3c))
* **client:** wire OpenID Federation self-issuance into client.Config ([#257](https://github.com/IDFoundry/FAPIgo/issues/257)) ([d01a08c](https://github.com/IDFoundry/FAPIgo/commit/d01a08caa62858ddc4d7e128a3c3c79f9ca1fcf5))
* **conformance-as:** add OpenID Federation self-issuance support ([#261](https://github.com/IDFoundry/FAPIgo/issues/261)) ([e1ccc23](https://github.com/IDFoundry/FAPIgo/commit/e1ccc239a6ffdcc3c0aa6c6f8f7cd2997eda033f))
* **conformance:** add a standing OpenID Federation Trust Anchor ([#263](https://github.com/IDFoundry/FAPIgo/issues/263)) ([61013f0](https://github.com/IDFoundry/FAPIgo/commit/61013f0ba1dcb627fbcc31112385ecf896ea2358))
* enforce OpenID Federation §12.1.1 request object rules for automatically-registered clients ([1b90464](https://github.com/IDFoundry/FAPIgo/commit/1b90464310a706f905c74161f19d075923032166))
* **errors:** add resource.Error.WriteJSON/NewError and WriteError helpers ([7d9574d](https://github.com/IDFoundry/FAPIgo/commit/7d9574d9c0d0adbe7a1a5310f9895febb6f57db7))
* **federation:** add automatic client registration (OpenID Federation 1.0 §12.1) ([fdba8f0](https://github.com/IDFoundry/FAPIgo/commit/fdba8f0228d41d0b92dbd2f9a4e9c38a1a29bc4b))
* **federation:** add internal Entity Statement primitives (OpenID Federation 1.0) ([25d8eca](https://github.com/IDFoundry/FAPIgo/commit/25d8ecaade1d87e834bbac59f7ee7f369bcfea38))
* **federation:** add SelfIssuer for self-issuing an Entity Configuration ([ebbba04](https://github.com/IDFoundry/FAPIgo/commit/ebbba0435a9970551569b6ec9ea42178d328fbb9))
* **federation:** add SubordinateIssuer for entities acting as a Trust Anchor/Intermediate ([#273](https://github.com/IDFoundry/FAPIgo/issues/273)) ([a79516b](https://github.com/IDFoundry/FAPIgo/commit/a79516ba2d1688e2f667f85f4441d283357ef5b5))
* **federation:** add trust chain resolver (OpenID Federation 1.0 Phase 2) ([784f1b0](https://github.com/IDFoundry/FAPIgo/commit/784f1b00802c704eb8d6488ac0c0e29e5ad9e5e7))
* **federation:** add Trust Mark Status and Trust Marked Entities Listing ([21c9409](https://github.com/IDFoundry/FAPIgo/commit/21c94098179e465c14ef51327975e39fedc2c5b9))
* **federation:** enforce naming_constraints and allowed_entity_types ([4c913e5](https://github.com/IDFoundry/FAPIgo/commit/4c913e5d60c11afcb4b2eae2c0c4023c4da5e351))
* **federation:** enforce per-statement max_path_length constraint ([c214e99](https://github.com/IDFoundry/FAPIgo/commit/c214e990a41e2b950a675779d3ee8bba272f807f))
* **federation:** support CIBA and client_credentials for automatically-registered clients ([46ec0f7](https://github.com/IDFoundry/FAPIgo/commit/46ec0f7d53190a84e5ebbec449487fad428eaa7f))
* **federation:** support jwks_uri in automatic client registration ([0b27a74](https://github.com/IDFoundry/FAPIgo/commit/0b27a7464a65b0541a4f4bc28752843df3c43ebb))
* **federation:** validate Trust Mark delegation (OpenID Federation 1.0 §7.2) ([0a14dc7](https://github.com/IDFoundry/FAPIgo/commit/0a14dc723ea27880016e2d8222e62a452f5814de))
* **federation:** verify Trust Marks (OpenID Federation 1.0 §7) ([00356a2](https://github.com/IDFoundry/FAPIgo/commit/00356a232ef02cfd5dea9eb03b75e01ee61ca8af))
* **server:** add FormRequest.Get ([#282](https://github.com/IDFoundry/FAPIgo/issues/282)) ([39be5ca](https://github.com/IDFoundry/FAPIgo/commit/39be5cad5c98e6b918079c77f01eefef5760bb1b))
* **server:** add TokenResult.WriteJSON ([5addc46](https://github.com/IDFoundry/FAPIgo/commit/5addc46393f9f9e892ea96a069c5c1662a6451d9))
* **server:** export FAPIRWTLSCipherSuites ([a3b5451](https://github.com/IDFoundry/FAPIgo/commit/a3b54518b2637faf37e0bb6db5643e966a5b9a01))
* **server:** wire automatic client registration into server.Config ([73e4633](https://github.com/IDFoundry/FAPIgo/commit/73e46335f67bbf3b7e6beb9038497aefb8493989))
* **server:** wire OpenID Federation self-issuance into server.Config ([aab3d61](https://github.com/IDFoundry/FAPIgo/commit/aab3d61d7547e6e22b4346b5613503a0cc9bccb4))


### Bug Fixes

* **conformance:** fix /api/runner call and record a second known warning ([#272](https://github.com/IDFoundry/FAPIgo/issues/272)) ([8251799](https://github.com/IDFoundry/FAPIgo/commit/825179958cf3adf53dfafa915bca5a7b27160b00))
* remove dead store flagged by staticcheck in Resolve ([6082e64](https://github.com/IDFoundry/FAPIgo/commit/6082e64aab6a57fb91846f9577ccfb9e29f7392d))
* resolve CodeQL allocation-size-overflow finding, raise test coverage ([a162603](https://github.com/IDFoundry/FAPIgo/commit/a162603c1c01ef8a26178826d23746703de96a83))
* **server:** omit optional metadata URL fields instead of empty strings ([d8584e0](https://github.com/IDFoundry/FAPIgo/commit/d8584e089e6967e49e2696014470422138070506))
* **server:** suppress gosec G117 false positive on TokenResult.WriteJSON ([e7d32f0](https://github.com/IDFoundry/FAPIgo/commit/e7d32f004af9cc511b9fe0375ac492630854dd98))

## [0.26.0](https://github.com/IDFoundry/FAPIgo/compare/v0.25.0...v0.26.0) (2026-09-10)


### Features

* add RequestClientCredentialsToken (RFC 6749 §4.4) ([#249](https://github.com/IDFoundry/FAPIgo/issues/249)) ([8c7de04](https://github.com/IDFoundry/FAPIgo/commit/8c7de0446e537f7e76690b63e43f1ea75d515188))
* **server:** add Config.OAuthOnly for a pure OAuth 2.0 + FAPI 2.0 AS ([#250](https://github.com/IDFoundry/FAPIgo/issues/250)) ([e62a392](https://github.com/IDFoundry/FAPIgo/commit/e62a3920d7af4d18c5935a393ab8d30bf152d92f))

## [0.25.0](https://github.com/IDFoundry/FAPIgo/compare/v0.24.0...v0.25.0) (2026-09-01)


### Features

* add token-gated manual CIBA approve/deny UI ([f05e5b6](https://github.com/IDFoundry/FAPIgo/commit/f05e5b6a5cea6d4e9116288bae40d46529d064ac))

## [0.24.0](https://github.com/IDFoundry/FAPIgo/compare/v0.23.0...v0.24.0) (2026-08-31)


### Features

* add memstore.SessionStore, the one storage.SessionStore gap ([dafd118](https://github.com/IDFoundry/FAPIgo/commit/dafd118e7f73f52c6718fd5c415ad596fa30733e))
* add PeerCertificateFromHTTP to server and resource ([f099dd1](https://github.com/IDFoundry/FAPIgo/commit/f099dd1077d8cf6c818e22e9db47c21361b3f878))
* add storage.RegisteredClientConfig.NeedsJWKS ([7ef35b4](https://github.com/IDFoundry/FAPIgo/commit/7ef35b44e6bf1c61d980acb541a11ed31cd65ceb))


### Bug Fixes

* derive dpop_signing_alg_values_supported from fapi.SignatureAlgorithm ([69ce782](https://github.com/IDFoundry/FAPIgo/commit/69ce7821eb4c77c4dc7a82db964dea9aa7a3c937))

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
