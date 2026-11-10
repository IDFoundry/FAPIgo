//! The legs. Each mirrors the interop/openid-client leg with the same
//! number and client ID; see interop/README.md.
use huskarl::{
    core::{
        client_auth::{ClientAuthentication, NoAuth},
        dpop::{AuthorizationServerDPoP, DPoP, NoDPoP},
    },
    grant::{
        authorization_code::{
            AuthorizationCodeGrant, CompleteInput, CompleteOutput, Jar, NoJar, ResponseMode,
            StartInput,
        },
        client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
        refresh::RefreshGrantParameters,
    },
    prelude::*,
    token::AccessToken,
    userinfo::UserInfoClient,
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use huskarl_reqwest::ReqwestClient;

use crate::harness::{Result, Run, discover, ensure, get_resource};

const SCOPES: [&str; 3] = ["openid", "offline_access", "accounts"];

fn scopes() -> Vec<String> {
    SCOPES.iter().map(|scope| (*scope).to_owned()).collect()
}

fn dpop() -> Result<DPoP> {
    Ok(DPoP::builder()
        .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None)?)
        .build())
}

/// One authorization-code flow: `start` (PAR, PKCE, and with `jar` a
/// signed request object), the user's consent at conformance-as, then
/// `complete` (state, `iss`, JARM if requested, code exchange and ID-token
/// validation). Returns the grant, the authorization URL and the callback
/// for the leg's own assertions.
struct Flow {
    grant: AuthorizationCodeGrant,
    authorization_url: String,
    callback: String,
    output: CompleteOutput,
}

impl Flow {
    async fn run<Auth, D, J>(
        run: &Run,
        http_client: &ReqwestClient,
        issuer: &str,
        client_id: &str,
        setup: FlowSetup<Auth, D, J>,
    ) -> Result<Self>
    where
        Auth: ClientAuthentication + 'static,
        D: AuthorizationServerDPoP + 'static,
        J: Jar + 'static,
    {
        let metadata = discover(http_client, issuer).await?;
        let grant: AuthorizationCodeGrant =
            AuthorizationCodeGrant::builder_from_metadata(&metadata)?
                .client_id(client_id)
                .http_client(http_client.clone())
                .client_auth(setup.client_auth)
                .redirect_uri(&run.redirect_uri)
                .maybe_response_mode(setup.response_mode)
                .dpop(setup.dpop)
                .jar(setup.jar)
                .build()
                .await?;
        let start = grant.start(StartInput::scope(scopes())).await?;
        let authorization_url = start.authorization_url.to_string();
        let callback = run.approve_consent(issuer, &authorization_url).await?;
        let output = grant
            .complete(&start.pending_state, callback.parse::<CompleteInput>()?)
            .await?;
        Ok(Self {
            grant,
            authorization_url,
            callback,
            output,
        })
    }

    fn query_has(url: &str, name: &str) -> bool {
        url.split_once('?').is_some_and(|(_, query)| {
            query
                .split('&')
                .any(|pair| pair.split_once('=').map_or(pair, |(key, _)| key) == name)
        })
    }

    fn sub(&self) -> Result<String> {
        self.output
            .id_token
            .as_ref()
            .and_then(|token| token.sub.clone())
            .ok_or_else(|| "huskarl returned no validated ID token with a sub".into())
    }

    /// UserInfo through huskarl's `UserInfoClient`, which checks the
    /// response's `sub` against the ID token's (OIDC Core §5.3.2).
    async fn userinfo(&self, http_client: &ReqwestClient, issuer: &str) -> Result<()> {
        let metadata = discover(http_client, issuer).await?;
        let client = UserInfoClient::builder_from_grant(&self.grant, &metadata)?
            .build()
            .await?;
        let sub = self.sub()?;
        let userinfo = client
            .get(http_client, self.output.token_response.access_token(), &sub)
            .await?;
        ensure(userinfo.sub == sub, "UserInfo sub matches the ID token's")
    }
}

struct FlowSetup<Auth, D, J> {
    client_auth: Auth,
    dpop: D,
    jar: J,
    response_mode: Option<ResponseMode>,
}

/// Leg 1: authorization code + PAR + PKCE (S256) + `private_key_jwt` +
/// DPoP-bound tokens; UserInfo, `/accounts` and the refresh-token grant,
/// all with DPoP. huskarl answers `use_dpop_nonce` at the authorization
/// server itself; the resource call re-sends once on the challenge.
pub async fn authorization_code_dpop(run: &Run) -> Result<()> {
    const CLIENT_ID: &str = "fapigo-sp-pkjwt-dpop";
    let issuer = &run.urls.authorization_server;
    let http_client = run.http_client().await?;
    let flow = Flow::run(
        run,
        &http_client,
        issuer,
        CLIENT_ID,
        FlowSetup {
            client_auth: run.private_key_jwt(CLIENT_ID)?,
            dpop: dpop()?,
            jar: NoJar,
            response_mode: None,
        },
    )
    .await?;
    ensure(
        Flow::query_has(&flow.authorization_url, "request_uri"),
        "authorization URL carries a PAR request_uri",
    )?;
    let tokens = &flow.output.token_response;
    ensure(
        matches!(tokens.access_token(), AccessToken::DPoP(_)),
        "access token is DPoP-bound",
    )?;
    flow.userinfo(&http_client, issuer).await?;

    let accounts = format!("{issuer}/accounts");
    let status = get_resource(
        &http_client,
        flow.grant.to_refresh_grant(),
        tokens,
        &accounts,
    )
    .await?;
    ensure(
        status == 200,
        format!("resource call with the DPoP-bound token: HTTP {status}"),
    )?;

    let refresh_token = tokens
        .refresh_token()
        .ok_or("offline_access granted no refresh token")?
        .clone();
    let refresh_grant = flow.grant.to_refresh_grant();
    let refreshed = refresh_grant
        .exchange(RefreshGrantParameters::refresh_token(refresh_token))
        .await?;
    ensure(
        matches!(refreshed.access_token(), AccessToken::DPoP(_)),
        "refreshed access token is DPoP-bound",
    )?;
    let status = get_resource(&http_client, refresh_grant, &refreshed, &accounts).await?;
    ensure(
        status == 200,
        format!("resource call with the refreshed token: HTTP {status}"),
    )
}

/// Leg 2: authorization code + PAR + PKCE with `self_signed_tls_client_auth`
/// (huskarl's `NoAuth` over an mTLS HTTP client) and certificate-bound
/// tokens (RFC 8705); huskarl sends PAR, token, UserInfo and refresh to the
/// `mtls_endpoint_aliases` because the client presents a certificate.
pub async fn authorization_code_mtls(run: &Run) -> Result<()> {
    const CLIENT_ID: &str = "fapigo-sp-mtls-mtls";
    let issuer = &run.urls.authorization_server;
    let http_client = run.mtls_http_client("client-mtls").await?;
    let metadata = discover(&http_client, issuer).await?;
    ensure(
        metadata.tls_client_certificate_bound_access_tokens,
        "server advertises certificate-bound tokens",
    )?;
    ensure(
        metadata
            .mtls_endpoint_aliases
            .as_ref()
            .is_some_and(|aliases| aliases.token_endpoint.is_some()),
        "server advertises mtls_endpoint_aliases",
    )?;

    let flow = Flow::run(
        run,
        &http_client,
        issuer,
        CLIENT_ID,
        FlowSetup {
            client_auth: NoAuth,
            dpop: NoDPoP,
            jar: NoJar,
            response_mode: None,
        },
    )
    .await?;
    let tokens = &flow.output.token_response;
    ensure(
        matches!(tokens.access_token(), AccessToken::Bearer(_)),
        "certificate-bound access token has token_type Bearer",
    )?;
    flow.userinfo(&http_client, issuer).await?;

    let accounts = format!("{}/accounts", run.urls.authorization_server_mtls);
    let status = get_resource(
        &http_client,
        flow.grant.to_refresh_grant(),
        tokens,
        &accounts,
    )
    .await?;
    ensure(
        status == 200,
        format!("resource call over mTLS with the certificate-bound token: HTTP {status}"),
    )?;

    let refresh_token = tokens
        .refresh_token()
        .ok_or("offline_access granted no refresh token")?
        .clone();
    flow.grant
        .to_refresh_grant()
        .exchange(RefreshGrantParameters::refresh_token(refresh_token))
        .await?;
    Ok(())
}

/// Leg 3: FAPI 2.0 Message Signing: a signed request object (JAR, RFC 9101)
/// pushed via PAR, and a JARM response (`response_mode=jwt`) that huskarl
/// verifies, with `private_key_jwt` and DPoP-bound tokens.
pub async fn message_signing(run: &Run) -> Result<()> {
    const CLIENT_ID: &str = "fapigo-ms-pkjwt-dpop";
    let issuer = &run.urls.message_signing;
    let http_client = run.http_client().await?;
    let flow = Flow::run(
        run,
        &http_client,
        issuer,
        CLIENT_ID,
        FlowSetup {
            client_auth: run.private_key_jwt(CLIENT_ID)?,
            dpop: dpop()?,
            jar: run.signing_key(CLIENT_ID)?,
            response_mode: Some(ResponseMode::Jwt),
        },
    )
    .await?;
    ensure(
        Flow::query_has(&flow.authorization_url, "request_uri"),
        "the signed request object went via PAR",
    )?;
    ensure(
        Flow::query_has(&flow.callback, "response") && !Flow::query_has(&flow.callback, "code"),
        "authorization response is a JARM JWT with no bare code",
    )?;
    let tokens = &flow.output.token_response;
    ensure(
        matches!(tokens.access_token(), AccessToken::DPoP(_)),
        "access token is DPoP-bound",
    )?;
    flow.userinfo(&http_client, issuer).await?;

    let accounts = format!("{issuer}/accounts");
    let status = get_resource(
        &http_client,
        flow.grant.to_refresh_grant(),
        tokens,
        &accounts,
    )
    .await?;
    ensure(status == 200, format!("resource call: HTTP {status}"))
}

/// Leg 4: `client_credentials` (RFC 6749 §4.4) with `private_key_jwt` and a
/// DPoP-bound access token, then a resource call with it.
pub async fn client_credentials(run: &Run) -> Result<()> {
    const CLIENT_ID: &str = "fapigo-sp-cc-pkjwt-dpop";
    let issuer = &run.urls.authorization_server;
    let http_client = run.http_client().await?;
    let metadata = discover(&http_client, issuer).await?;
    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(CLIENT_ID)
        .http_client(http_client.clone())
        .client_auth(run.private_key_jwt(CLIENT_ID)?)
        .dpop(dpop()?)
        .build();
    let tokens = grant
        .exchange(
            ClientCredentialsGrantParameters::builder()
                .scope(vec!["accounts".to_owned()])
                .build(),
        )
        .await?;
    ensure(
        matches!(tokens.access_token(), AccessToken::DPoP(_)),
        "access token is DPoP-bound",
    )?;
    ensure(
        tokens.refresh_token().is_none(),
        "no refresh token for client_credentials",
    )?;

    let accounts = format!("{issuer}/accounts");
    let status = get_resource(&http_client, grant.to_refresh_grant(), &tokens, &accounts).await?;
    ensure(status == 200, format!("resource call: HTTP {status}"))
}
