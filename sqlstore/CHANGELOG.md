# Changelog

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
