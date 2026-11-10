//! Shared plumbing for the legs: the run's client registry and keys, HTTP
//! clients that trust only the run's test CA, and the interaction a real
//! user would perform (conformance-as's consent form), driven over HTTP the
//! same way interop/openid-client drives it.
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use http::{Method, Uri};
use huskarl::{
    authorizer::{HttpAuthorizer, dpop_resend_advised},
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, NoSource},
    core::{
        client_auth::{Audience, JwtBearer},
        http::{HttpClient, Idempotency},
        jwk::Jwk,
        secrets::{ProvidedSecret, SecretString},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::{core::TokenResponse, refresh::RefreshGrant},
};
use huskarl_crypto_native::asymmetric::signer::PrivateKey;
use huskarl_reqwest::{ReqwestClient, mtls::MtlsPem};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Ports and URLs, read from the same `INTEROP_*` variables the runner
/// exports and interop/openid-client/lib/env.mjs reads.
pub struct Urls {
    pub authorization_server: String,
    pub authorization_server_mtls: String,
    pub message_signing: String,
}

fn port(name: &str, fallback: u16) -> Result<u16> {
    match env::var(name) {
        Ok(value) => match value.parse::<u16>() {
            Ok(port) if port > 0 => Ok(port),
            _ => Err(format!("{name} must be a TCP port, got {value}").into()),
        },
        Err(_) => Ok(fallback),
    }
}

impl Urls {
    pub fn from_env() -> Result<Self> {
        let url = |port: u16| format!("https://localhost:{port}");
        Ok(Self {
            authorization_server: url(port("INTEROP_AS_PORT", 28443)?),
            authorization_server_mtls: url(port("INTEROP_AS_MTLS_PORT", 28444)?),
            message_signing: url(port("INTEROP_AS_MS_PORT", 28445)?),
        })
    }
}

/// One run's configuration: what setup.mjs and the runner's openssl step
/// wrote into the work directory.
pub struct Run {
    pub urls: Urls,
    pub redirect_uri: String,
    registry: serde_json::Value,
    certs: PathBuf,
    ca: reqwest::Certificate,
    /// A plain HTTP client for the user's side (the consent form).
    browser: reqwest::Client,
}

impl Run {
    pub fn load(work_dir: &Path) -> Result<Self> {
        let certs = work_dir.join("certs");
        let registry: serde_json::Value =
            serde_json::from_slice(&fs::read(work_dir.join("clients.json"))?)?;
        let redirect_uri = registry["redirectURI"]
            .as_str()
            .ok_or("clients.json has no redirectURI")?
            .to_owned();
        let ca = reqwest::Certificate::from_pem(&fs::read(certs.join("ca.crt"))?)?;
        let browser = reqwest::Client::builder()
            .tls_certs_only([ca.clone()])
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            urls: Urls::from_env()?,
            redirect_uri,
            registry,
            certs,
            ca,
            browser,
        })
    }

    /// An HTTP client for huskarl that trusts only the run's test CA and
    /// presents no client certificate.
    pub async fn http_client(&self) -> Result<ReqwestClient> {
        Ok(ReqwestClient::builder()
            .root_certificates(vec![self.ca.clone()])
            .build()
            .await?)
    }

    /// As [`Run::http_client`], presenting the named client certificate
    /// (`<name>.crt` / `<name>.key` from the runner's openssl step). The
    /// client then reports mTLS, so grants built from discovery use the
    /// server's `mtls_endpoint_aliases`.
    pub async fn mtls_http_client(&self, name: &str) -> Result<ReqwestClient> {
        let key = fs::read_to_string(self.certs.join(format!("{name}.key")))?;
        let cert = fs::read_to_string(self.certs.join(format!("{name}.crt")))?;
        let identity: SecretString = format!("{key}{cert}").into();
        Ok(ReqwestClient::builder()
            .root_certificates(vec![self.ca.clone()])
            .mtls(MtlsPem::new(ProvidedSecret::new(identity)))
            .build()
            .await?)
    }

    /// `private_key_jwt` client authentication with the client's key from
    /// clients.json, the assertion's audience being the issuer (FAPI 2.0
    /// Security Profile §5.3.2.1).
    pub fn private_key_jwt(&self, client_id: &str) -> Result<JwtBearer> {
        Ok(JwtBearer::builder()
            .signer(self.signing_key(client_id)?)
            .audience(Audience::Issuer)
            .build())
    }

    pub fn signing_key(&self, client_id: &str) -> Result<PrivateKey> {
        let jwk = &self.registry["clients"][client_id]["privateJwk"];
        if jwk.is_null() {
            return Err(format!("clients.json has no key for {client_id}").into());
        }
        let jwk: Jwk = serde_json::from_value(jwk.clone())?;
        let private = jwk
            .private_jwk()
            .ok_or_else(|| format!("{client_id}'s JWK has no private key"))?;
        Ok(PrivateKey::from_jwk(private.try_into()?)?)
    }

    /// Plays the user at conformance-as's consent page: opens the
    /// authorization URL, reads the form conformance-as renders, submits it
    /// with `decision=approve` and returns the redirect back to the client
    /// (the callback huskarl then completes).
    pub async fn approve_consent(&self, issuer: &str, authorization_url: &str) -> Result<String> {
        let page = self.browser.get(authorization_url).send().await?;
        let status = page.status();
        let html = page.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(format!("authorization endpoint: HTTP {status}: {}", head(&html)).into());
        }
        let mut form = vec![
            ("handle", form_value(&html, "handle")?),
            ("subject", form_value(&html, "subject")?),
            ("decision", "approve".to_owned()),
        ];
        for scope in form_values(&html, "scope") {
            form.push(("scope", scope));
        }
        let decision = self
            .browser
            .post(format!("{issuer}/authorize/decision"))
            .form(&form)
            .send()
            .await?;
        let status = decision.status();
        let location = decision
            .headers()
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        match location {
            Some(location) if status == reqwest::StatusCode::SEE_OTHER => Ok(location),
            _ => Err(format!(
                "consent decision: HTTP {status}: {}",
                head(&decision.text().await?)
            )
            .into()),
        }
    }
}

fn head(text: &str) -> &str {
    let end = text
        .char_indices()
        .nth(300)
        .map_or(text.len(), |(index, _)| index);
    &text[..end]
}

/// The `value` attributes of every input named `name`, in document order.
fn form_values(html: &str, name: &str) -> Vec<String> {
    let marker = format!("name=\"{name}\" value=\"");
    html.match_indices(&marker)
        .filter_map(|(start, _)| {
            let rest = &html[start + marker.len()..];
            rest.find('"').map(|end| unescape(&rest[..end]))
        })
        .collect()
}

fn form_value(html: &str, name: &str) -> Result<String> {
    form_values(html, name)
        .into_iter()
        .next()
        .ok_or_else(|| format!("consent page has no {name} field").into())
}

/// Undoes the escaping Go's html/template applies inside attribute values.
fn unescape(value: &str) -> String {
    value
        .replace("&#43;", "+")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// OpenID Connect discovery through `http_client`.
pub async fn discover(
    http_client: &ReqwestClient,
    issuer: &str,
) -> Result<AuthorizationServerMetadata> {
    Ok(AuthorizationServerMetadata::oidc_fetch()
        .issuer(issuer)
        .http_client(http_client)
        .call()
        .await?)
}

/// Calls a protected resource with `GET`, through huskarl's
/// `HttpAuthorizer` primed with `token_response`: it builds the
/// `Authorization` header (and a DPoP proof for a DPoP-bound token), and a
/// `use_dpop_nonce` challenge is answered with one re-send, as huskarl's
/// request-loop guide prescribes. Returns the response status.
pub async fn get_resource(
    http_client: &ReqwestClient,
    refresh_grant: RefreshGrant,
    token_response: &TokenResponse,
    uri: &str,
) -> Result<u16> {
    let uri: Uri = uri.parse()?;
    let source = Arc::new(
        GrantTokenSource::builder()
            .grant(refresh_grant)
            .grant_parameters(NoSource)
            .refresh_store(InMemoryRefreshTokenStore::default())
            .build(),
    );
    let authorizer = HttpAuthorizer::builder()
        .cache(InMemoryTokenCache::builder().source(source.clone()).build())
        .build();
    source.prime(token_response.clone()).await?;

    let mut resent = false;
    loop {
        let headers = authorizer.get_headers(&Method::GET, &uri).await?;
        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.headers = headers;
        parts.uri = uri.clone();
        let request = http::Request::from_parts(parts, Bytes::new());
        let response = http_client
            .execute(request, Idempotency::Idempotent)
            .await?;
        authorizer.process_response(&uri, &response.headers);
        if !resent && dpop_resend_advised(response.status, &response.headers) {
            resent = true;
            continue;
        }
        return Ok(response.status.as_u16());
    }
}

/// Fails the leg with `message` unless `condition` holds.
pub fn ensure(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
