//! Minimal OCI distribution client: digests, tag lists and image config labels.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Client, Method, Response, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
application/vnd.docker.distribution.manifest.list.v2+json, \
application/vnd.oci.image.manifest.v1+json, \
application/vnd.docker.distribution.manifest.v2+json";

/// Size caps for registry responses (a hostile registry must not exhaust memory).
const MANIFEST_MAX: usize = 4 << 20;
const TAGS_MAX: usize = 16 << 20;
/// Token responses are a few KB; the realm is chosen by the registry.
const TOKEN_MAX: usize = 64 << 10;

/// Reads a body up to `max` bytes.
async fn read_capped(mut resp: Response, max: usize) -> Result<Vec<u8>> {
    if resp.content_length().is_some_and(|l| l > max as u64) {
        bail!("registry response too large (> {max} bytes)");
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        out.extend_from_slice(&chunk);
        if out.len() > max {
            bail!("registry response too large (> {max} bytes)");
        }
    }
    Ok(out)
}

/// Registries may redirect (blobs to a CDN), but only to HTTPS: tag lists and
/// HEAD digests are not digest-verified, a downgrade would expose them.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|a| {
        if a.url().scheme() != "https" {
            a.error("redirect to a non-HTTPS URL refused")
        } else if a.previous().len() >= 5 {
            a.stop()
        } else {
            a.follow()
        }
    })
}

/// Bearer token from a token endpoint response (size-capped).
async fn bearer_token(resp: Response) -> Result<CachedToken> {
    let body = read_capped(resp, TOKEN_MAX).await?;
    let t: TokenResponse = serde_json::from_slice(&body).context("decoding token response")?;
    let value = t
        .token
        .or(t.access_token)
        .context("token endpoint returned no token")?;
    let ttl = t.expires_in.unwrap_or(60).max(30);
    Ok(CachedToken {
        value,
        scheme: "Bearer",
        expires: Instant::now() + Duration::from_secs(ttl.saturating_sub(10)),
    })
}

fn sha256_hex(body: &[u8]) -> String {
    Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect()
}

/// Content fetched by digest must hash to that digest.
fn verify_digest(body: &[u8], digest: &str) -> Result<()> {
    let Some(expected) = digest.strip_prefix("sha256:") else {
        bail!("unsupported digest algorithm in {digest}");
    };
    if sha256_hex(body) != expected.to_lowercase() {
        bail!("registry content does not match digest {digest}");
    }
    Ok(())
}

/// Registry host as used by the HTTP API.
pub fn api_host(host: &str) -> String {
    match host {
        "docker.io" | "index.docker.io" | "registry-1.docker.io" => "registry-1.docker.io".into(),
        h => h.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// API host (`registry-1.docker.io`, `ghcr.io`).
    pub host: String,
    /// Repository (`library/postgres`).
    pub repo: String,
    pub tag: String,
}

impl ImageRef {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let name = s.split('@').next().unwrap_or(s);
        let (host, rest) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), rest.to_string())
            }
            _ => ("docker.io".to_string(), name.to_string()),
        };
        let (repo, tag) = match rest.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r.to_string(), t.to_string()),
            _ => (rest.clone(), "latest".to_string()),
        };
        if repo.is_empty() || repo.contains('$') {
            bail!("unsupported image reference {s}");
        }
        let host = api_host(&host);
        let repo = if host == "registry-1.docker.io" && !repo.contains('/') {
            format!("library/{repo}")
        } else {
            repo
        };
        Ok(Self { host, repo, tag })
    }

    /// `true` when `other` (e.g. a RepoDigests entry) names the same repository.
    pub fn same_repo(&self, other: &ImageRef) -> bool {
        self.host == other.host && self.repo == other.repo
    }
}

#[derive(Clone)]
struct CachedToken {
    value: String,
    scheme: &'static str,
    expires: Instant,
}

pub struct Registry {
    http: Client,
    auth: HashMap<String, (String, String)>,
    /// Extra realm hosts trusted with credentials (`REGISTRY_AUTH_REALMS`).
    realms: Vec<String>,
    /// Registries Drydock may query (`REGISTRY_ALLOWLIST`, empty = all).
    allowlist: Vec<String>,
    tokens: Mutex<HashMap<String, CachedToken>>,
    /// `host/repo@digest -> labels` (verified content, immutable: cache forever).
    labels_cache: Mutex<HashMap<String, HashMap<String, String>>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct TagList {
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    #[serde(default)]
    manifests: Vec<ManifestEntry>,
    config: Option<Descriptor>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    digest: String,
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Platform {
    architecture: String,
    os: String,
    variant: Option<String>,
}

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
}

#[derive(Deserialize)]
struct ImageConfig {
    config: Option<ImageConfigInner>,
}

#[derive(Deserialize)]
struct ImageConfigInner {
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

pub struct PlatformSpec<'a> {
    pub os: &'a str,
    pub arch: &'a str,
    pub variant: Option<&'a str>,
}

fn parse_challenge(h: &str) -> (String, HashMap<String, String>) {
    let (scheme, params) = h.split_once(' ').unwrap_or((h, ""));
    let mut map = HashMap::new();
    for part in params.split(',') {
        if let Some((k, v)) = part.trim().split_once('=') {
            map.insert(k.trim().to_lowercase(), v.trim().trim_matches('"').to_string());
        }
    }
    (scheme.to_lowercase(), map)
}

/// The registry could not be reached at all (DNS, TCP, TLS: plain-HTTP or
/// self-signed registry, timeout), as opposed to an HTTP answer such as 401/404.
pub fn is_unreachable(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<reqwest::Error>())
        .any(|r| r.is_connect() || r.is_timeout())
}

/// Explains a 401 that persists after the token negotiation.
fn unauthorized_hint(img: &ImageRef, has_credentials: bool) -> String {
    // Name as users write it in REGISTRY_AUTH.
    let host = if img.host == "registry-1.docker.io" { "docker.io" } else { img.host.as_str() };
    if has_credentials {
        format!(
            "{host}/{}: accès refusé avec les identifiants de REGISTRY_AUTH \
             (jeton expiré ou sans droit de lecture sur ce dépôt ?)",
            img.repo
        )
    } else {
        format!(
            "{host}/{}: accès refusé (image privée ?) : définir REGISTRY_AUTH={host}=utilisateur:jeton",
            img.repo
        )
    }
}

/// Host part of `host[:port]`.
fn bare_host(h: &str) -> &str {
    h.rsplit_once(':').map_or(h, |(h, _)| h)
}

/// Registrable domain per the Public Suffix List (`registry-1.docker.io` →
/// `docker.io`, `reg.example.co.uk` → `example.co.uk`, `a.azurecr.io` →
/// `a.azurecr.io` via `TENANT_SUFFIXES`). None for IP addresses and bare
/// public suffixes.
fn site(h: &str) -> Option<&str> {
    if h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    // Multi-tenant registry hosts missing from the PSL: each tenant is its own site.
    if TENANT_SUFFIXES.iter().any(|s| h.strip_suffix(s).is_some_and(|p| p.ends_with('.'))) {
        return Some(h);
    }
    psl::domain_str(h)
}

/// Registry services where anyone can own a subdomain, not listed in the PSL.
const TENANT_SUFFIXES: &[&str] = &["azurecr.io"];

/// Credentials go only to the registry itself, a host of the same registrable
/// domain (`auth.docker.io` for `registry-1.docker.io`), or an explicitly
/// allowed realm. Two tenants of a shared suffix (`co.uk`, `azurecr.io`…) are
/// not the same site.
fn realm_trusted(registry: &str, realm_host: &str, extra: &[String]) -> bool {
    let registry = bare_host(registry).to_lowercase();
    let realm = realm_host.to_lowercase();
    realm == registry
        || site(&realm).is_some_and(|s| Some(s) == site(&registry))
        || extra.contains(&realm)
}

impl Registry {
    pub fn new(
        auth: HashMap<String, (String, String)>,
        realms: Vec<String>,
        allowlist: Vec<String>,
    ) -> Result<Self> {
        let http = Client::builder()
            .user_agent(concat!("drydock/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .https_only(true)
            .redirect(redirect_policy())
            .build()?;
        Ok(Self {
            http,
            auth,
            realms,
            allowlist,
            tokens: Mutex::new(HashMap::new()),
            labels_cache: Mutex::new(HashMap::new()),
        })
    }

    fn token_key(img: &ImageRef) -> String {
        format!("{}/{}", img.host, img.repo)
    }

    async fn authenticate(&self, img: &ImageRef, challenge: &str) -> Result<CachedToken> {
        let (scheme, params) = parse_challenge(challenge);
        let creds = self.auth.get(&img.host);
        if scheme == "basic" {
            let (u, p) = creds.ok_or_else(|| anyhow!("{} requires credentials", img.host))?;
            use base64::Engine;
            let v = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            return Ok(CachedToken {
                value: v,
                scheme: "Basic",
                expires: Instant::now() + Duration::from_secs(3600),
            });
        }
        let realm = params.get("realm").context("bearer challenge without realm")?;
        let realm_url = reqwest::Url::parse(realm).with_context(|| format!("{}: invalid token realm {realm}", img.host))?;
        if realm_url.scheme() != "https" {
            bail!("{}: token realm {realm} refusé (HTTPS requis)", img.host);
        }
        let realm_host = realm_url.host_str().unwrap_or_default();
        let scope = format!("repository:{}:pull", img.repo);
        let mut q: Vec<(&str, &str)> = vec![("scope", scope.as_str())];
        if let Some(svc) = params.get("service") {
            q.push(("service", svc));
        }
        let mut req = self.http.get(realm_url.clone()).query(&q);
        if let Some((u, p)) = creds {
            if realm_trusted(&img.host, realm_host, &self.realms) {
                req = req.basic_auth(u, Some(p));
            } else {
                // Anonymous token: public images still work, credentials stay home.
                tracing::warn!(
                    "{}: realm {realm_host} non reconnu, identifiants non envoyés (REGISTRY_AUTH_REALMS pour l'autoriser)",
                    img.host
                );
            }
        }
        let resp = req.send().await?.error_for_status()?;
        bearer_token(resp).await
    }

    /// Request with automatic token negotiation.
    async fn request(
        &self,
        img: &ImageRef,
        method: Method,
        path: &str,
        accept: Option<&str>,
    ) -> Result<Response> {
        if !self.allowlist.is_empty() && !self.allowlist.contains(&img.host) {
            bail!("registre {} hors de REGISTRY_ALLOWLIST, non interrogé", img.host);
        }
        let url = format!("https://{}/v2/{}/{}", img.host, img.repo, path);
        let key = Self::token_key(img);
        for attempt in 0..2 {
            let mut headers = HeaderMap::new();
            if let Some(a) = accept {
                headers.insert(ACCEPT, a.parse()?);
            }
            let cached = self.tokens.lock().await.get(&key).cloned();
            if let Some(t) = cached.filter(|t| t.expires > Instant::now()) {
                headers.insert(AUTHORIZATION, format!("{} {}", t.scheme, t.value).parse()?);
            }
            let resp = self
                .http
                .request(method.clone(), &url)
                .headers(headers)
                .send()
                .await?;
            if resp.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                let challenge = resp
                    .headers()
                    .get(WWW_AUTHENTICATE)
                    .and_then(|v| v.to_str().ok())
                    .context("401 without WWW-Authenticate")?
                    .to_string();
                let tok = self.authenticate(img, &challenge).await?;
                self.tokens.lock().await.insert(key.clone(), tok);
                continue;
            }
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                bail!("{}: rate limited by registry", img.host);
            }
            if resp.status() == StatusCode::UNAUTHORIZED {
                bail!("{}", unauthorized_hint(img, self.auth.contains_key(&img.host)));
            }
            return Ok(resp.error_for_status()?);
        }
        unreachable!()
    }

    /// Digest the tag currently points to (index digest for multi-arch images).
    pub async fn tag_digest(&self, img: &ImageRef) -> Result<String> {
        let path = format!("manifests/{}", img.tag);
        let resp = self
            .request(img, Method::HEAD, &path, Some(MANIFEST_ACCEPT))
            .await?;
        if let Some(d) = resp.headers().get("docker-content-digest") {
            return Ok(d.to_str()?.to_string());
        }
        // Some registries omit the header on HEAD: hash the manifest ourselves.
        let resp = self
            .request(img, Method::GET, &path, Some(MANIFEST_ACCEPT))
            .await?;
        let body = read_capped(resp, MANIFEST_MAX).await?;
        Ok(format!("sha256:{}", sha256_hex(&body)))
    }

    pub async fn list_tags(&self, img: &ImageRef) -> Result<Vec<String>> {
        let mut all = Vec::new();
        let mut path = "tags/list?n=1000".to_string();
        for _ in 0..50 {
            let resp = self.request(img, Method::GET, &path, None).await?;
            let next = resp
                .headers()
                .get("link")
                .and_then(|l| l.to_str().ok())
                .and_then(|l| l.split(';').next())
                .map(|l| l.trim().trim_start_matches('<').trim_end_matches('>').to_string());
            let page: TagList = serde_json::from_slice(&read_capped(resp, TAGS_MAX).await?)
                .context("decoding tag list")?;
            all.extend(page.tags.unwrap_or_default());
            match next {
                // Link is `/v2/<repo>/tags/list?...`: keep only the part after the repo.
                Some(n) => match n.split_once("/tags/list") {
                    Some((_, q)) => path = format!("tags/list{q}"),
                    None => break,
                },
                None => break,
            }
        }
        Ok(all)
    }

    /// GET a manifest or blob by digest: size-capped, then checked against the digest.
    async fn fetch_verified(
        &self,
        img: &ImageRef,
        path: &str,
        digest: &str,
        accept: Option<&str>,
    ) -> Result<Vec<u8>> {
        let resp = self.request(img, Method::GET, path, accept).await?;
        let body = read_capped(resp, MANIFEST_MAX).await?;
        verify_digest(&body, digest)?;
        Ok(body)
    }

    /// Labels of the image config behind `digest`, for the given platform.
    pub async fn labels(
        &self,
        img: &ImageRef,
        digest: &str,
        platform: &PlatformSpec<'_>,
    ) -> Result<HashMap<String, String>> {
        // Keyed by repository too: another registry cannot poison this entry.
        let key = format!("{}/{}@{digest}", img.host, img.repo);
        if let Some(l) = self.labels_cache.lock().await.get(&key) {
            return Ok(l.clone());
        }
        let body = self
            .fetch_verified(img, &format!("manifests/{digest}"), digest, Some(MANIFEST_ACCEPT))
            .await?;
        let mut manifest: Manifest = serde_json::from_slice(&body).context("decoding manifest")?;
        let is_index = !manifest.manifests.is_empty()
            || manifest
                .media_type
                .as_deref()
                .is_some_and(|m| m.contains("index") || m.contains("list"));
        if is_index {
            let entry = manifest
                .manifests
                .iter()
                .find(|m| {
                    m.platform.as_ref().is_some_and(|p| {
                        p.os == platform.os
                            && p.architecture == platform.arch
                            && (platform.variant.is_none() || p.variant.as_deref() == platform.variant)
                    })
                })
                .with_context(|| format!("no {}/{} image in index", platform.os, platform.arch))?;
            let body = self
                .fetch_verified(
                    img,
                    &format!("manifests/{}", entry.digest),
                    &entry.digest,
                    Some(MANIFEST_ACCEPT),
                )
                .await?;
            manifest = serde_json::from_slice(&body).context("decoding platform manifest")?;
        }
        let config = manifest.config.context("manifest without config")?;
        let body = self
            .fetch_verified(img, &format!("blobs/{}", config.digest), &config.digest, None)
            .await?;
        let cfg: ImageConfig = serde_json::from_slice(&body).context("decoding image config")?;
        let labels = cfg.config.and_then(|c| c.labels).unwrap_or_default();
        self.labels_cache.lock().await.insert(key, labels.clone());
        Ok(labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_refs() {
        let r = ImageRef::parse("postgres:18-alpine").unwrap();
        assert_eq!(r.host, "registry-1.docker.io");
        assert_eq!(r.repo, "library/postgres");
        assert_eq!(r.tag, "18-alpine");

        let r = ImageRef::parse("docker.io/valkey/valkey:9-alpine").unwrap();
        assert_eq!(r.repo, "valkey/valkey");

        let r = ImageRef::parse("ghcr.io/paperless-ngx/paperless-ngx").unwrap();
        assert_eq!((r.host.as_str(), r.tag.as_str()), ("ghcr.io", "latest"));

        let r = ImageRef::parse("localhost:5000/app:1.2@sha256:abc").unwrap();
        assert_eq!((r.host.as_str(), r.repo.as_str(), r.tag.as_str()), ("localhost:5000", "app", "1.2"));

        assert!(ImageRef::parse("${IMAGE}").is_err());
    }

    #[tokio::test]
    async fn unreachable_registries() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let r = Registry::new(HashMap::new(), vec![], vec![]).unwrap();
        // Nothing listening.
        let img = ImageRef::parse("127.0.0.1:1/app:1").unwrap();
        let e = r.tag_digest(&img).await.expect_err("must fail");
        assert!(is_unreachable(&e), "{e:#}");
        // Plain-HTTP registry: the TLS handshake fails.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for mut c in l.incoming().flatten() {
                let mut b = [0u8; 512];
                let _ = c.read(&mut b);
                let _ = c.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let img = ImageRef::parse(&format!("127.0.0.1:{port}/app:1")).unwrap();
        let e = r.tag_digest(&img).await.expect_err("must fail");
        assert!(is_unreachable(&e), "{e:#}");
        // An HTTP answer is not "unreachable".
        let e = anyhow::anyhow!("registry-1.docker.io/x: accès refusé");
        assert!(!is_unreachable(&e));
    }

    #[test]
    fn unauthorized_hints() {
        let img = ImageRef::parse("docker.io/kareylo/stocky:latest").unwrap();
        let h = unauthorized_hint(&img, false);
        assert!(h.contains("REGISTRY_AUTH=docker.io=utilisateur:jeton"), "{h}");
        assert!(h.starts_with("docker.io/kareylo/stocky"), "{h}");
        assert!(unauthorized_hint(&img, true).contains("identifiants de REGISTRY_AUTH"));
    }

    #[test]
    fn digest_check() {
        let body = b"hello";
        let d = format!("sha256:{}", sha256_hex(body));
        assert!(verify_digest(body, &d).is_ok());
        assert!(verify_digest(b"tampered", &d).is_err());
        assert!(verify_digest(body, "sha512:abc").is_err());
    }

    #[tokio::test]
    async fn allowlist_blocks_other_registries() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let r = Registry::new(HashMap::new(), vec![], vec!["ghcr.io".into()]).unwrap();
        let img = ImageRef::parse("internal.example:5000/app:1").unwrap();
        let err = r.list_tags(&img).await.expect_err("must be refused");
        assert!(err.to_string().contains("REGISTRY_ALLOWLIST"), "{err}");
    }

    #[test]
    fn realm_trust() {
        assert!(realm_trusted("registry-1.docker.io", "auth.docker.io", &[]));
        assert!(realm_trusted("ghcr.io", "ghcr.io", &[]));
        assert!(realm_trusted("registry.example.com:5000", "auth.example.com", &[]));
        assert!(!realm_trusted("ghcr.io", "evil.example", &[]));
        assert!(!realm_trusted("registry-1.docker.io", "docker.io.evil.example", &[]));
        assert!(!realm_trusted("lscr.io", "ghcr.io", &[]));
        assert!(realm_trusted("lscr.io", "ghcr.io", &["ghcr.io".to_string()]));
        // Shared public suffixes: other tenants are not the same site.
        assert!(!realm_trusted("reg.example.co.uk", "evil.co.uk", &[]));
        assert!(realm_trusted("reg.example.co.uk", "auth.example.co.uk", &[]));
        assert!(!realm_trusted("a.azurecr.io", "b.azurecr.io", &[]));
        assert!(realm_trusted("a.azurecr.io", "a.azurecr.io", &[]));
        assert!(!realm_trusted("user.github.io", "attacker.github.io", &[]));
        // IP registries: exact host only.
        assert!(!realm_trusted("10.0.0.5:5000", "10.0.0.6", &[]));
        assert!(realm_trusted("10.0.0.5:5000", "10.0.0.5", &[]));
    }

    /// One-shot local HTTP server answering every request with `body`.
    fn serve_once(body: Vec<u8>, chunked: bool) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Some(mut c) = l.incoming().flatten().next() {
                let mut b = [0u8; 1024];
                let _ = c.read(&mut b);
                if chunked {
                    // No Content-Length: the cap must hold while streaming.
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                    for part in body.chunks(8192) {
                        let _ = c.write_all(format!("{:x}\r\n", part.len()).as_bytes());
                        let _ = c.write_all(part);
                        let _ = c.write_all(b"\r\n");
                    }
                    let _ = c.write_all(b"0\r\n\r\n");
                } else {
                    let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
                    let _ = c.write_all(&body);
                }
            }
        });
        format!("http://{addr}/token")
    }

    /// Local HTTP server answering every request with a redirect to `to(port)`.
    fn redirect_server(to: impl Fn(u16) -> String + Send + 'static) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for mut c in l.incoming().flatten() {
                let mut b = [0u8; 1024];
                let _ = c.read(&mut b);
                let resp = format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n", to(port));
                let _ = c.write_all(resp.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}/start")
    }

    #[tokio::test]
    async fn redirects_only_to_https() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // The policy alone (the real client is also https_only, so it could
        // not even reach this plain-HTTP test server).
        let http = Client::builder().redirect(redirect_policy()).build().unwrap();
        let e = http.get(redirect_server(|p| format!("http://127.0.0.1:{p}/next"))).send().await.unwrap_err();
        assert!(e.is_redirect() && format!("{e:?}").contains("non-HTTPS"), "{e:?}");
        // An HTTPS target is followed (here it then fails to connect).
        let e = http.get(redirect_server(|_| "https://127.0.0.1:1/blob".into())).send().await.unwrap_err();
        assert!(e.is_connect(), "{e:?}");
        // The registry client refuses plain HTTP outright.
        let r = Registry::new(HashMap::new(), vec![], vec![]).unwrap();
        assert!(r.http.get("http://127.0.0.1:1/").send().await.is_err());
    }

    #[tokio::test]
    async fn token_response_is_capped() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = Client::new();
        // Normal token.
        let url = serve_once(br#"{"token":"abc","expires_in":300}"#.to_vec(), false);
        let t = bearer_token(http.get(url).send().await.unwrap()).await.unwrap();
        assert_eq!((t.value.as_str(), t.scheme), ("abc", "Bearer"));
        // 1 MiB token, announced or streamed: refused before being buffered.
        let huge = format!(r#"{{"token":"{}"}}"#, "a".repeat(1 << 20)).into_bytes();
        for chunked in [false, true] {
            let url = serve_once(huge.clone(), chunked);
            let e = bearer_token(http.get(url).send().await.unwrap()).await.err().expect("must fail");
            assert!(e.to_string().contains("too large"), "chunked={chunked}: {e}");
        }
    }

    #[tokio::test]
    async fn http_realm_refused() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut auth = HashMap::new();
        auth.insert("ghcr.io".to_string(), ("u".to_string(), "p".to_string()));
        let r = Registry::new(auth, vec![], vec![]).unwrap();
        let img = ImageRef::parse("ghcr.io/a/b:1").unwrap();
        let err = r
            .authenticate(&img, r#"Bearer realm="http://ghcr.io/token",service="ghcr.io""#)
            .await
            .err()
            .expect("http realm must be refused");
        assert!(err.to_string().contains("HTTPS requis"), "{err}");
    }
}

/// Network tests against public registries: `cargo test -- --ignored`.
#[cfg(test)]
mod live {
    use super::*;
    use crate::version::same_major_candidate;

    fn reg() -> Registry {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Registry::new(HashMap::new(), vec![], vec![]).unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn docker_hub_and_ghcr() {
        let r = reg();
        let img = ImageRef::parse("docker.io/gotenberg/gotenberg:8.34").unwrap();
        let tags = r.list_tags(&img).await.unwrap();
        let c = same_major_candidate("8.34", &tags);
        println!("gotenberg tags={} same_major={c:?}", tags.len());

        let img = ImageRef::parse("postgres:18-alpine").unwrap();
        let tags = r.list_tags(&img).await.unwrap();
        let c = same_major_candidate("18-alpine", &tags);
        assert_eq!(c, None, "postgres:18-alpine must not propose another major");
        println!("postgres tags={} same_major={c:?}", tags.len());

        for name in ["docker.io/traefik:latest", "ghcr.io/paperless-ngx/paperless-ngx:latest", "vaultwarden/server:latest-alpine"] {
            let img = ImageRef::parse(name).unwrap();
            let d = r.tag_digest(&img).await.unwrap();
            let p = PlatformSpec { os: "linux", arch: "amd64", variant: None };
            let l = r.labels(&img, &d, &p).await.unwrap();
            println!("{name} {d} version={:?}", l.get("org.opencontainers.image.version"));
        }
    }
}
