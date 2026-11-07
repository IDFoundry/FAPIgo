# Changelog

## [0.7.0](https://github.com/IDFoundry/FAPIgo/compare/sqlstore/v0.6.0...sqlstore/v0.7.0) (2026-11-07)


### ⚠ BREAKING CHANGES

* **sqlstore:** RevocationStore.IsAnyRevoked and GrantStore.RecordIssuedTokens are removed. Wire db.Revocation().Batching() and db.Grants().Batching() to keep the batched calls; the plain stores still work, with one IsRevoked per key and two RecordIssued* calls.

### Features

* **sqlstore:** move the batch methods onto explicit Batching adapters ([47fb10a](https://github.com/IDFoundry/FAPIgo/commit/47fb10ae0777c2b5ee02b3cccef0700d7c548392))


### Bug Fixes

* **sqlstore:** keep a late client-cache read from replacing a newer one ([944f6c5](https://github.com/IDFoundry/FAPIgo/commit/944f6c503fcd8daa1f2c673bd42604365e3f02bf))
* **sqlstore:** key the Postgres sweep lock by schema too ([3b173aa](https://github.com/IDFoundry/FAPIgo/commit/3b173aa3bd2a3fd11e46909bd7487bd8c2524660))
* **sqlstore:** never wait in Sweep's SQLite checkpoint ([9e25fc1](https://github.com/IDFoundry/FAPIgo/commit/9e25fc113290031249ede87f70764ffa143d00e7))

## [0.6.0](https://github.com/IDFoundry/FAPIgo/compare/sqlstore/v0.5.0...sqlstore/v0.6.0) (2026-11-07)


### Features

* **sqlstore:** check revocation keys and record issued tokens in one statement ([96a958e](https://github.com/IDFoundry/FAPIgo/commit/96a958ea77446aa6f46b29eeb9ca91a43b6b8d04))


### Bug Fixes

* **sqlstore:** lock a polled CIBA request with SELECT … FOR UPDATE ([d73a0b8](https://github.com/IDFoundry/FAPIgo/commit/d73a0b8c0845cc5ac8e0fdc8bc1db4d1cb47510e))
* **sqlstore:** read a returning user's pairwise subject without a write ([0f7a93c](https://github.com/IDFoundry/FAPIgo/commit/0f7a93c365af22e3bceffc60d50bf967b20aff68))
* **sqlstore:** require fapigo v0.70.0 ([d4f767c](https://github.com/IDFoundry/FAPIgo/commit/d4f767c0fc3fde8205b83b211e8da13836b75c2f))

## [0.5.0](https://github.com/IDFoundry/FAPIgo/compare/sqlstore/v0.4.0...sqlstore/v0.5.0) (2026-11-07)


### Features

* **sqlstore:** cache parsed client configuration, with optional ClientCacheTTL ([75e5b38](https://github.com/IDFoundry/FAPIgo/commit/75e5b38c244f81ad7f7148f12a39aa62b9e028a8))


### Bug Fixes

* **sqlstore:** let a waiting SQLite write give up with its context ([941eb08](https://github.com/IDFoundry/FAPIgo/commit/941eb08e48bb5fe933133d0df191524d423db442))
* **sqlstore:** page SealRecords through each table by key ([dba8a12](https://github.com/IDFoundry/FAPIgo/commit/dba8a122b0a96a82e7dccde544efd6bd3e64e9f8))
* **sqlstore:** run single-statement Postgres writes without BEGIN/COMMIT ([5b4308a](https://github.com/IDFoundry/FAPIgo/commit/5b4308a7948603ba5d335d4274d7a3e67dc33637))
* **sqlstore:** seal new records before starting their write ([5d6a9b3](https://github.com/IDFoundry/FAPIgo/commit/5d6a9b3f60037b51efd55eb9962865ed8632a63d))
* **sqlstore:** sweep expired rows in short batches ([6d4f28b](https://github.com/IDFoundry/FAPIgo/commit/6d4f28b711acecd208a38b68a20fa049336f3d46))

## [0.4.0](https://github.com/IDFoundry/FAPIgo/compare/sqlstore/v0.3.0...sqlstore/v0.4.0) (2026-11-02)


### ⚠ BREAKING CHANGES

* **sqlstore:** on SQLite, Migrate and CheckSchema return an error unless the database is in WAL mode, which v0.3 accepted. Open the file with both pragmas in its DSN, busy_timeout first, as in
* **sqlstore:** AESGCMSealer returns an error for a key that is one byte repeated or made entirely of printable text, which v0.3 accepted. Generate the key with crypto/rand and decode an encoded key before passing it. The README's Upgrading from v0.3 section shows how to keep reading the records sealed under the old key.

### Features

* **sqlstore:** add ResourceServer for a standalone resource server's stores ([0989577](https://github.com/IDFoundry/FAPIgo/commit/09895771113c9a5db855c0883afad8065e95e627))
* **sqlstore:** keep clients' keys in the clients table ([2cc26db](https://github.com/IDFoundry/FAPIgo/commit/2cc26dbb9725580c0577e0589ecc3f2f1fb8d417))
* **sqlstore:** list clients, and document CheckClientRegistration ([d4665ca](https://github.com/IDFoundry/FAPIgo/commit/d4665ca622346811f1c81647747b7979024a1b0a))


### Bug Fixes

* **sqlstore:** refuse a sealing key that isn't random ([963cfdc](https://github.com/IDFoundry/FAPIgo/commit/963cfdc815f207a68dbb804c3b3757b68d404802))
* **sqlstore:** refuse a SQLite database that isn't in WAL mode ([49c8d39](https://github.com/IDFoundry/FAPIgo/commit/49c8d3989573d1ad5206904dab5ef0b496080074))

## [0.3.0](https://github.com/IDFoundry/FAPIgo/compare/sqlstore/v0.2.0...sqlstore/v0.3.0) (2026-11-01)


### Features

* **sqlstore:** add RotatingSealer and document AESGCMSealer's key limit ([7c9b402](https://github.com/IDFoundry/FAPIgo/commit/7c9b402b244917e680f94e4c186f07475bef723a))


### Bug Fixes

* **sqlstore:** bind sealed records to their expiry and other fixed columns ([d142729](https://github.com/IDFoundry/FAPIgo/commit/d142729da92413ee4a85f279ac3d87fd19eb700f))
* **sqlstore:** keep a redeemed code until the server records its tokens ([a65ea56](https://github.com/IDFoundry/FAPIgo/commit/a65ea56fe2cc214fb24c077c9d5075c418a92a00))
* **sqlstore:** let concurrent first Migrates of a new SQLite file succeed ([448e537](https://github.com/IDFoundry/FAPIgo/commit/448e537cd4e6a4b25e80f29380e9e14188200290))
* **sqlstore:** pin READ COMMITTED for every PostgreSQL write ([a88dda8](https://github.com/IDFoundry/FAPIgo/commit/a88dda843e7783f408844407919a41d67b9b3838))
* **sqlstore:** refuse duplicate, case-variant and lossy client config members ([f7c87bd](https://github.com/IDFoundry/FAPIgo/commit/f7c87bd56030ac2bdbdbb5176660e428f2adc52c))
* **sqlstore:** require golang.org/x/text v0.41.0 and fapigo v0.67.2 ([e11145e](https://github.com/IDFoundry/FAPIgo/commit/e11145e0c5503f432033284e7294f64292c4f3b7))

## [0.2.0](https://github.com/IDFoundry/FAPIgo/compare/sqlstore/v0.1.0...sqlstore/v0.2.0) (2026-10-30)


### Features

* **sqlstore:** add the client's SessionStore ([8f98d56](https://github.com/IDFoundry/FAPIgo/commit/8f98d5682fab01ab1187934b89b44917e5ebb392))


### Bug Fixes

* **sqlstore:** keep a resource server's DPoP nonces apart from the server's ([8f98d56](https://github.com/IDFoundry/FAPIgo/commit/8f98d5682fab01ab1187934b89b44917e5ebb392))

## 0.1.0 (2026-10-30)


### Features

* **sqlstore:** add access token, CIBA and pairwise subject stores, and record sealing ([688cdca](https://github.com/IDFoundry/FAPIgo/commit/688cdca1a7bc8e7220e7c6de5929ab325f491a87))
* **sqlstore:** durable PostgreSQL and SQLite storage for the server ([b5638d9](https://github.com/IDFoundry/FAPIgo/commit/b5638d9afd6700eac7d3ea80b7fce56713e02b8a))


### Bug Fixes

* **sqlstore:** keep CIBA requests an hour past their expiry ([62b997c](https://github.com/IDFoundry/FAPIgo/commit/62b997ca0aec7b5fb65e40c893de3ca44fcc1886))
