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

/// Host part of `host[:port]`.
fn bare_host(h: &str) -> &str {
    h.rsplit_once(':').map_or(h, |(h, _)| h)
}

/// Last two DNS labels (`registry-1.docker.io` → `docker.io`).
fn site(h: &str) -> String {
    let labels: Vec<&str> = h.rsplit('.').take(2).collect();
    labels.into_iter().rev().collect::<Vec<_>>().join(".")
}

/// Credentials go only to the registry itself, a host of the same site
/// (`auth.docker.io` for `registry-1.docker.io`), or an explicitly allowed realm.
fn realm_trusted(registry: &str, realm_host: &str, extra: &[String]) -> bool {
    let registry = bare_host(registry).to_lowercase();
    let realm = realm_host.to_lowercase();
    realm == registry
        || (realm.contains('.') && site(&realm) == site(&registry))
        || extra.iter().any(|e| *e == realm)
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
        let t: TokenResponse = resp.json().await?;
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
        let err = r.list_tags(&img).await.err().expect("must be refused");
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
