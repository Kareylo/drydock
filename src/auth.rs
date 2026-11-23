//! UI authentication modes: HTTP Basic, authenticating reverse proxy
//! (Pangolin SSO, Authelia forward-auth…) and native OpenID Connect.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Minimum length of the secret shared with the reverse proxy.
pub const MIN_PROXY_SECRET_CHARS: usize = 24;
/// A login must complete within this delay.
const LOGIN_TTL: Duration = Duration::from_secs(600);
/// Cap on in-memory sessions (only authorized users can open one).
const MAX_SESSIONS: usize = 1000;
/// Over HTTPS the session cookie is `__Host-` prefixed (Secure, `Path=/`, no
/// `Domain`): a sibling subdomain cannot set or overwrite it.
const SESSION_COOKIE: &str = "drydock_session";
/// Over HTTPS `__Secure-` prefixed (`Path=/auth` rules out `__Host-`).
const STATE_COOKIE: &str = "drydock_oidc_state";

#[derive(Clone)]
pub enum AuthConfig {
    /// `UI_BASIC_AUTH=user:password`.
    Basic { user: String, pass: String },
    /// Requests must come through an authenticating reverse proxy.
    Proxy(ProxyAuth),
    /// Drydock runs the OpenID Connect login itself.
    Oidc(OidcConfig),
    /// No authentication (explicit opt-out).
    None,
}

impl AuthConfig {
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Basic { .. } => "basic",
            Self::Proxy(_) => "proxy",
            Self::Oidc(_) => "oidc",
            Self::None => "none",
        }
    }
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic { user, .. } => write!(f, "Basic {{ user: {user:?}, pass: *** }}"),
            Self::Proxy(p) => write!(
                f,
                "Proxy {{ secret_header: {:?}, secret: ***, user_header: {:?}, trusted: {} range(s) }}",
                p.secret_header,
                p.user_header,
                p.trusted.len()
            ),
            Self::Oidc(o) => write!(
                f,
                "Oidc {{ issuer: {:?}, client_id: {:?}, client_secret: ***, redirect_url: {:?} }}",
                o.issuer, o.client_id, o.redirect_url
            ),
            Self::None => write!(f, "None"),
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy mode
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ProxyAuth {
    /// Header the proxy adds with the shared secret (lowercase).
    pub secret_header: String,
    pub secret: String,
    /// Header carrying the user name set by the proxy (lowercase), if required.
    pub user_header: Option<String>,
    /// Allowed proxy addresses; empty = any (the secret is then the only check).
    pub trusted: Vec<Cidr>,
}

/// Outcome of the proxy check: the user name, or why the request is refused.
pub fn check_proxy(
    p: &ProxyAuth,
    peer: Option<IpAddr>,
    secret: Option<&str>,
    user: Option<&str>,
) -> std::result::Result<String, &'static str> {
    if !p.trusted.is_empty() && !peer.is_some_and(|ip| p.trusted.iter().any(|c| c.contains(ip))) {
        return Err("adresse hors de PROXY_TRUSTED_IPS");
    }
    if !secret.is_some_and(|s| constant_time_eq(s, &p.secret)) {
        return Err("secret du proxy absent ou invalide");
    }
    match &p.user_header {
        Some(_) => match user.map(str::trim).filter(|u| !u.is_empty()) {
            Some(u) => Ok(clean_user_name(u)),
            None => Err("en-tête utilisateur absent"),
        },
        None => Ok(user.map(str::trim).filter(|u| !u.is_empty()).unwrap_or("proxy").to_string()),
    }
}

/// IPv4/IPv6 network (`10.0.0.0/8`, `172.18.0.3`, `fd00::/8`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (s, None),
        };
        let net: IpAddr = ip.parse().with_context(|| format!("invalid IP in {s}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().with_context(|| format!("invalid prefix in {s}"))?,
            None => max,
        };
        if prefix > max {
            bail!("prefix too large in {s}");
        }
        Ok(Self { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // Peers of a dual-stack socket show up as ::ffff:a.b.c.d.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// OIDC mode
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OidcConfig {
    /// Issuer URL, without trailing slash.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Registered redirect URI, ending with `/auth/callback`.
    pub redirect_url: String,
    pub scopes: String,
    /// Claim holding the user's groups.
    pub groups_claim: String,
    /// Allowed groups / users (username, email or sub); both empty = any user of the provider.
    pub allowed_groups: Vec<String>,
    pub allowed_users: Vec<String>,
    pub session_ttl: Duration,
}

impl OidcConfig {
    /// `Secure` cookies when Drydock is served over HTTPS.
    pub fn secure_cookies(&self) -> bool {
        self.redirect_url.starts_with("https://")
    }

    pub fn session_cookie(&self) -> &'static str {
        if self.secure_cookies() { "__Host-drydock_session" } else { SESSION_COOKIE }
    }

    pub fn state_cookie(&self) -> &'static str {
        if self.secure_cookies() { "__Secure-drydock_oidc_state" } else { STATE_COOKIE }
    }
}

/// `https://`, or `http://` on a loopback host (local tests only).
pub fn check_url_scheme(name: &str, url: &str) -> Result<()> {
    let u = reqwest::Url::parse(url).with_context(|| format!("{name} is not a valid URL"))?;
    let loopback = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]" | "::1"));
    match u.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => bail!("{name} must use https://"),
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Provider signing keys (required by OIDC Discovery).
    pub jwks_uri: String,
}

/// Asymmetric algorithms accepted for ID tokens: never `none`, never HMAC
/// (a provider key published in the JWKS must not double as a shared secret).
const ID_TOKEN_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];
/// Largest JWKS document read.
const JWKS_MAX: usize = 256 << 10;
/// An unknown `kid` refetches the JWKS (key rotation) at most this often.
const JWKS_REFRESH: Duration = Duration::from_secs(60);

/// A login in progress, carried by the browser in the state cookie (sealed
/// with `Oidc::key`): Drydock keeps no server-side table that anonymous
/// `/auth/login` calls could fill up.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    state: String,
    nonce: String,
    verifier: String,
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct Session {
    pub user: String,
    expires: Instant,
}

/// Server-side OIDC state: provider metadata, logins in progress, sessions.
pub struct Oidc {
    pub cfg: OidcConfig,
    http: reqwest::Client,
    discovery: Mutex<Option<Discovery>>,
    /// Provider signing keys and when they were fetched.
    jwks: Mutex<Option<(Vec<Jwk>, Instant)>>,
    /// Seals the state cookie; random per process (a restart only cancels
    /// the logins in progress).
    key: [u8; 32],
    sessions: Mutex<HashMap<String, Session>>,
}

/// Claims Drydock needs from the ID token.
#[derive(Debug)]
pub struct Identity {
    pub user: String,
}

impl Oidc {
    pub fn new(cfg: OidcConfig) -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|e| anyhow::anyhow!("OS random generator: {e}"))?;
        Ok(Self {
            key,
            cfg,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            discovery: Mutex::new(None),
            jwks: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Provider metadata, fetched once (retried on the next login if it failed).
    async fn discovery(&self) -> Result<Discovery> {
        if let Some(d) = self.discovery.lock().await.clone() {
            return Ok(d);
        }
        let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
        let resp = self.http.get(&url).send().await.with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            bail!("GET {url}: HTTP {}", resp.status());
        }
        let d: Discovery = resp.json().await.context("decoding the provider metadata")?;
        if d.issuer.trim_end_matches('/') != self.cfg.issuer {
            bail!("provider issuer {} does not match OIDC_ISSUER {}", d.issuer, self.cfg.issuer);
        }
        check_url_scheme("authorization_endpoint", &d.authorization_endpoint)?;
        check_url_scheme("token_endpoint", &d.token_endpoint)?;
        check_url_scheme("jwks_uri", &d.jwks_uri)?;
        *self.discovery.lock().await = Some(d.clone());
        Ok(d)
    }

    fn mac(&self, payload: &str) -> HmacSha256 {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key size");
        m.update(payload.as_bytes());
        m
    }

    /// `state.nonce.verifier.created.mac` (base64url tokens contain no `.`).
    fn seal(&self, p: &Pending, created: u64) -> String {
        let payload = format!("{}.{}.{}.{created}", p.state, p.nonce, p.verifier);
        let mac = URL_SAFE_NO_PAD.encode(self.mac(&payload).finalize().into_bytes());
        format!("{payload}.{mac}")
    }

    /// The login sealed in `cookie`, if authentic and not older than `LOGIN_TTL`.
    fn open(&self, cookie: &str, now: u64) -> Option<Pending> {
        let (payload, mac) = cookie.rsplit_once('.')?;
        self.mac(payload).verify_slice(&URL_SAFE_NO_PAD.decode(mac).ok()?).ok()?;
        let mut parts = payload.split('.');
        let (state, nonce, verifier, created) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let created: u64 = created.parse().ok()?;
        if created > now + 60 || now.saturating_sub(created) >= LOGIN_TTL.as_secs() {
            return None;
        }
        Some(Pending { state: state.into(), nonce: nonce.into(), verifier: verifier.into() })
    }

    /// Starts a login: returns the provider URL to redirect to and the sealed
    /// login, to set in the state cookie (binds the callback to this browser).
    pub async fn begin_login(&self) -> Result<(String, String)> {
        let d = self.discovery().await?;
        let pending = Pending { state: random_token(), nonce: random_token(), verifier: random_token() };
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
        let (state, nonce) = (&pending.state, &pending.nonce);
        let mut url = reqwest::Url::parse(&d.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.cfg.redirect_url)
            .append_pair("scope", &self.cfg.scopes)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((url.to_string(), self.seal(&pending, now_secs())))
    }

    /// Completes a login: opens the state cookie, checks `state` against it,
    /// exchanges the code and validates the ID token. Returns the new session id.
    /// A replayed cookie is harmless: the provider accepts each code only once.
    pub async fn finish_login(&self, state: &str, cookie: Option<&str>, code: &str) -> Result<(String, String)> {
        let pending = cookie
            .and_then(|c| self.open(c, now_secs()))
            .context("unknown or expired login")?;
        if !constant_time_eq(&pending.state, state) {
            bail!("state does not match this browser's login");
        }
        let d = self.discovery().await?;
        let resp = self
            .http
            .post(&d.token_endpoint)
            .basic_auth(form_encode(&self.cfg.client_id), Some(form_encode(&self.cfg.client_secret)))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.cfg.redirect_url.as_str()),
                ("code_verifier", pending.verifier.as_str()),
            ])
            .send()
            .await
            .context("token request")?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let err = body.get("error").and_then(Value::as_str).unwrap_or("");
            bail!("token endpoint: HTTP {status} {err}");
        }
        let id_token = body.get("id_token").and_then(Value::as_str).context("no id_token in the token response")?;
        // Signature checked against the provider's JWKS, on top of TLS to the
        // token endpoint: neither alone is a single point of failure.
        let claims = self.verify_id_token(&d.jwks_uri, id_token).await?;
        let identity = validate_claims(&self.cfg, &claims, &pending.nonce, now_secs())?;

        let session_id = random_token();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, s| s.expires > Instant::now());
        if sessions.len() >= MAX_SESSIONS {
            bail!("too many open sessions, retry later");
        }
        sessions.insert(
            session_id.clone(),
            Session { user: identity.user.clone(), expires: Instant::now() + self.cfg.session_ttl },
        );
        Ok((session_id, identity.user))
    }

    /// Downloads the provider's JWKS (size-capped). Keys Drydock cannot parse
    /// (other key types, encryption keys…) are skipped, not fatal.
    async fn fetch_jwks(&self, uri: &str) -> Result<Vec<Jwk>> {
        let mut resp = self.http.get(uri).send().await.with_context(|| format!("GET {uri}"))?;
        if !resp.status().is_success() {
            bail!("GET {uri}: HTTP {}", resp.status());
        }
        let mut raw = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            raw.extend_from_slice(&chunk);
            if raw.len() > JWKS_MAX {
                bail!("GET {uri}: JWKS larger than {JWKS_MAX} bytes");
            }
        }
        let set: Value = serde_json::from_slice(&raw).context("decoding the provider JWKS")?;
        let keys: Vec<Jwk> = set
            .get("keys")
            .and_then(Value::as_array)
            .context("JWKS without keys")?
            .iter()
            .filter_map(|k| serde_json::from_value(k.clone()).ok())
            .collect();
        Ok(keys)
    }

    /// Signing keys that may have produced a token with this `kid`. An
    /// unknown `kid` refetches the JWKS once per `JWKS_REFRESH` (key rotation).
    async fn signing_keys(&self, uri: &str, kid: Option<&str>) -> Result<Vec<Jwk>> {
        let mut cache = self.jwks.lock().await;
        let known = |keys: &[Jwk]| kid.is_none_or(|k| keys.iter().any(|j| j.common.key_id.as_deref() == Some(k)));
        let stale = match &*cache {
            None => true,
            Some((keys, at)) => !known(keys) && at.elapsed() >= JWKS_REFRESH,
        };
        if stale {
            *cache = Some((self.fetch_jwks(uri).await?, Instant::now()));
        }
        let keys = cache.as_ref().map(|(k, _)| k.as_slice()).unwrap_or_default();
        Ok(keys
            .iter()
            .filter(|j| kid.is_none_or(|k| j.common.key_id.as_deref() == Some(k)))
            .filter(|j| !matches!(j.common.public_key_use, Some(ref u) if *u != PublicKeyUse::Signature))
            .cloned()
            .collect())
    }

    /// Claims of an ID token whose signature one of the provider's keys
    /// verifies. Issuer, audience, expiry and nonce are checked afterwards by
    /// `validate_claims`.
    async fn verify_id_token(&self, jwks_uri: &str, id_token: &str) -> Result<Value> {
        let header = jsonwebtoken::decode_header(id_token).context("malformed ID token")?;
        if !ID_TOKEN_ALGS.contains(&header.alg) {
            bail!("ID token signed with {:?}: algorithm refused", header.alg);
        }
        let keys = self.signing_keys(jwks_uri, header.kid.as_deref()).await?;
        verify_with_keys(id_token, header.alg, &keys)
    }

    pub async fn session(&self, id: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().await;
        match sessions.get(id) {
            Some(s) if s.expires > Instant::now() => Some(s.clone()),
            Some(_) => {
                sessions.remove(id);
                None
            }
            None => None,
        }
    }

    pub async fn logout(&self, id: &str) {
        self.sessions.lock().await.remove(id);
    }
}

/// Checks the ID token claims (issuer, audience, expiry, nonce, authorization).
pub fn validate_claims(cfg: &OidcConfig, c: &Value, nonce: &str, now: u64) -> Result<Identity> {
    let s = |k: &str| c.get(k).and_then(Value::as_str);
    if s("iss").map(|i| i.trim_end_matches('/')) != Some(cfg.issuer.as_str()) {
        bail!("ID token issuer mismatch");
    }
    let aud: Vec<&str> = match c.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if !aud.contains(&cfg.client_id.as_str()) {
        bail!("ID token audience does not include OIDC_CLIENT_ID");
    }
    if aud.len() > 1 && s("azp") != Some(cfg.client_id.as_str()) {
        bail!("ID token azp mismatch");
    }
    let exp = c.get("exp").and_then(Value::as_u64).context("ID token without exp")?;
    if exp + 60 < now {
        bail!("ID token expired");
    }
    if c.get("iat").and_then(Value::as_u64).is_some_and(|iat| iat > now + 300) {
        bail!("ID token issued in the future");
    }
    if !s("nonce").is_some_and(|n| constant_time_eq(n, nonce)) {
        bail!("ID token nonce mismatch");
    }
    let sub = s("sub").context("ID token without sub")?;
    let username = s("preferred_username");
    let email = s("email");
    let user = clean_user_name(username.or(email).unwrap_or(sub));

    if !cfg.allowed_users.is_empty() || !cfg.allowed_groups.is_empty() {
        let names: Vec<String> = [Some(sub), username, email].into_iter().flatten().map(str::to_lowercase).collect();
        let user_ok = names.iter().any(|n| cfg.allowed_users.contains(n));
        let groups: Vec<&str> = match c.get(&cfg.groups_claim) {
            Some(Value::Array(g)) => g.iter().filter_map(Value::as_str).collect(),
            Some(Value::String(g)) => vec![g.as_str()],
            _ => vec![],
        };
        let group_ok = groups.iter().any(|g| cfg.allowed_groups.iter().any(|a| a == g));
        if !user_ok && !group_ok {
            bail!("user {user} is not allowed (OIDC_ALLOWED_USERS / OIDC_ALLOWED_GROUPS)");
        }
    }
    Ok(Identity { user })
}

/// Verifies the signature of `id_token` (signed with `alg`) with the first
/// matching key; returns its claims. Only the signature is checked here.
fn verify_with_keys(id_token: &str, alg: Algorithm, keys: &[Jwk]) -> Result<Value> {
    let mut v = Validation::new(alg);
    v.validate_exp = false;
    v.validate_nbf = false;
    v.validate_aud = false;
    v.required_spec_claims.clear();
    let alg_name = serde_json::to_value(alg).ok();
    for jwk in keys {
        // A key bound to another algorithm is not tried.
        if jwk.common.key_algorithm.as_ref().is_some_and(|a| serde_json::to_value(a).ok() != alg_name) {
            continue;
        }
        let Ok(key) = DecodingKey::from_jwk(jwk) else { continue };
        if let Ok(t) = jsonwebtoken::decode::<Value>(id_token, &key, &v) {
            return Ok(t.claims);
        }
    }
    bail!("ID token signature not verified by any of the provider's keys")
}

#[cfg(test)]
fn decode_jwt_payload(jwt: &str) -> Result<Value> {
    let mut parts = jwt.split('.');
    let (Some(_), Some(payload), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        bail!("malformed ID token");
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .context("ID token payload is not base64url")?;
    serde_json::from_slice(&bytes).context("ID token payload is not JSON")
}

/// `application/x-www-form-urlencoded` encoding, required for client
/// credentials in HTTP Basic (RFC 6749 §2.3.1).
fn form_encode(s: &str) -> String {
    reqwest::Url::parse_with_params("x:", &[("v", s)])
        .map(|u| u.query().unwrap_or("v=").trim_start_matches("v=").to_string())
        .unwrap_or_else(|_| s.to_string())
}

/// User name safe to log and display: no control characters (newlines would
/// forge log lines), 128 chars at most. Applied where a name enters Drydock
/// (ID token claim, proxy header), so every later use is safe.
pub fn clean_user_name(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(128).collect()
}

/// 256-bit random token, base64url.
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS random generator");
    URL_SAFE_NO_PAD.encode(b)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Constant-time comparison of fixed-length digests (no length or content leak).
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = Sha256::digest(a.as_bytes());
    let b = Sha256::digest(b.as_bytes());
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Value of one cookie from the `Cookie` header.
pub fn cookie<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    header?
        .split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// `Set-Cookie` value. `max_age = 0` deletes the cookie.
pub fn set_cookie(name: &str, value: &str, path: &str, max_age: u64, secure: bool) -> String {
    format!(
        "{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn oidc() -> OidcConfig {
        OidcConfig {
            issuer: "https://auth.example.com".into(),
            client_id: "drydock".into(),
            client_secret: "s".into(),
            redirect_url: "https://drydock.example.com/auth/callback".into(),
            scopes: "openid".into(),
            groups_claim: "groups".into(),
            allowed_groups: vec![],
            allowed_users: vec![],
            session_ttl: Duration::from_secs(3600),
        }
    }

    fn claims() -> Value {
        json!({"iss": "https://auth.example.com", "aud": "drydock", "exp": 2000, "iat": 1000,
               "nonce": "n1", "sub": "u-1", "preferred_username": "alice", "groups": ["admins"]})
    }

    #[test]
    fn claims_ok_and_identity() {
        assert_eq!(validate_claims(&oidc(), &claims(), "n1", 1500).unwrap().user, "alice");
    }

    #[test]
    fn user_names_are_cleaned() {
        let mut c = claims();
        c["preferred_username"] = json!("a\nINFO forged\r\u{1b}[31m");
        let user = validate_claims(&oidc(), &c, "n1", 1500).unwrap().user;
        assert_eq!(user, "aINFO forged[31m");
        assert_eq!(clean_user_name(&"x".repeat(500)).chars().count(), 128);
        assert_eq!(clean_user_name("élodie.dupont@example.com"), "élodie.dupont@example.com");
    }

    #[test]
    fn claims_rejected() {
        let cfg = oidc();
        let mut c = claims();
        c["iss"] = json!("https://evil.example.com");
        assert!(validate_claims(&cfg, &c, "n1", 1500).is_err(), "issuer");
        let mut c = claims();
        c["aud"] = json!("other");
        assert!(validate_claims(&cfg, &c, "n1", 1500).is_err(), "audience");
        let mut c = claims();
        c["aud"] = json!(["drydock", "other"]);
        assert!(validate_claims(&cfg, &c, "n1", 1500).is_err(), "azp missing with several audiences");
        c["azp"] = json!("drydock");
        assert!(validate_claims(&cfg, &c, "n1", 1500).is_ok(), "azp ok");
        assert!(validate_claims(&cfg, &claims(), "n1", 3000).is_err(), "expired");
        assert!(validate_claims(&cfg, &claims(), "other", 1500).is_err(), "nonce");
    }

    #[test]
    fn claims_authorization() {
        let mut cfg = oidc();
        cfg.allowed_groups = vec!["ops".into()];
        assert!(validate_claims(&cfg, &claims(), "n1", 1500).is_err(), "not in group");
        cfg.allowed_groups = vec!["admins".into()];
        assert!(validate_claims(&cfg, &claims(), "n1", 1500).is_ok(), "in group");
        cfg.allowed_groups = vec![];
        cfg.allowed_users = vec!["alice".into()];
        assert!(validate_claims(&cfg, &claims(), "n1", 1500).is_ok(), "allowed user");
    }

    #[test]
    fn proxy_checks() {
        let p = ProxyAuth {
            secret_header: "x-drydock-proxy-secret".into(),
            secret: "s".repeat(32),
            user_header: Some("remote-user".into()),
            trusted: vec![Cidr::parse("172.18.0.0/16").unwrap()],
        };
        let ok_ip = Some("172.18.0.5".parse().unwrap());
        let secret = "s".repeat(32);
        assert_eq!(check_proxy(&p, ok_ip, Some(&secret), Some("bob")), Ok("bob".into()));
        assert!(check_proxy(&p, Some("10.0.0.1".parse().unwrap()), Some(&secret), Some("bob")).is_err());
        assert!(check_proxy(&p, ok_ip, Some("wrong"), Some("bob")).is_err());
        assert!(check_proxy(&p, ok_ip, None, Some("bob")).is_err());
        assert!(check_proxy(&p, ok_ip, Some(&secret), None).is_err());
        assert!(check_proxy(&p, None, Some(&secret), Some("bob")).is_err());
    }

    #[test]
    fn cidr() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(c.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!c.contains("10.2.0.1".parse().unwrap()));
        assert!(Cidr::parse("172.18.0.3").unwrap().contains("172.18.0.3".parse().unwrap()));
        assert!(Cidr::parse("fd00::/8").unwrap().contains("fd12::1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
    }

    fn client() -> Oidc {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Oidc::new(oidc()).unwrap()
    }

    fn pending() -> Pending {
        Pending { state: random_token(), nonce: random_token(), verifier: random_token() }
    }

    #[test]
    fn sealed_login_round_trip() {
        let o = client();
        let p = pending();
        let c = o.seal(&p, 1000);
        assert_eq!(o.open(&c, 1000), Some(p.clone()));
        assert_eq!(o.open(&c, 1000 + LOGIN_TTL.as_secs() - 1), Some(p.clone()));
    }

    #[test]
    fn sealed_login_rejected() {
        let o = client();
        let c = o.seal(&pending(), 1000);
        // Expired, or dated in the future.
        assert_eq!(o.open(&c, 1000 + LOGIN_TTL.as_secs()), None);
        assert_eq!(o.open(&c, 900), None);
        // Any byte changed (payload or MAC).
        for i in [0, c.len() / 2, c.len() - 1] {
            let mut b = c.clone().into_bytes();
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            assert_eq!(o.open(&String::from_utf8(b).unwrap(), 1000), None, "byte {i}");
        }
        // Another process (key) did not seal it.
        assert_eq!(client().open(&c, 1000), None);
        // Extra or missing fields, garbage.
        assert_eq!(o.open("a.b.c", 1000), None);
        assert_eq!(o.open("", 1000), None);
    }

    // Throwaway Ed25519 test keys (PKCS#8 DER, base64) and their public `x`.
    const ED1_DER: &str = "MC4CAQAwBQYDK2VwBCIEIEgAgCtZqZ5vHJZmuczLtZt1CNxmsAJGLvf/gAZ66WfL";
    const ED1_X: &str = "1tvX28nafZ0b1szf1WipYqN-yuuG6-W8UrBVGDmMig8";
    const ED2_X: &str = "mpYao3QLtHgDwTLJQKkWEZuGM25n-jcjLxuNjnFbMqI";

    fn jwk(kid: &str, x: &str, extra: Value) -> Jwk {
        let mut j = json!({"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid});
        j.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::from_value(j).unwrap()
    }

    fn signed(kid: &str, claims: &Value) -> String {
        let der = base64::engine::general_purpose::STANDARD.decode(ED1_DER).unwrap();
        let mut h = jsonwebtoken::Header::new(Algorithm::EdDSA);
        h.kid = Some(kid.into());
        jsonwebtoken::encode(&h, claims, &jsonwebtoken::EncodingKey::from_ed_der(&der)).unwrap()
    }

    #[test]
    fn id_token_signature() {
        let t = signed("k1", &claims());
        let good = jwk("k1", ED1_X, json!({"alg": "EdDSA", "use": "sig"}));
        assert_eq!(verify_with_keys(&t, Algorithm::EdDSA, std::slice::from_ref(&good)).unwrap()["sub"], "u-1");
        // Another key, or no key at all.
        assert!(verify_with_keys(&t, Algorithm::EdDSA, &[jwk("k1", ED2_X, json!({}))]).is_err());
        assert!(verify_with_keys(&t, Algorithm::EdDSA, &[]).is_err());
        // The right key, but bound to another algorithm.
        assert!(verify_with_keys(&t, Algorithm::EdDSA, &[jwk("k1", ED1_X, json!({"alg": "RS256"}))]).is_err());
        // Payload swapped after signing (e.g. another user).
        let mut parts: Vec<&str> = t.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(json!({"sub": "admin"}).to_string());
        parts[1] = &forged;
        assert!(verify_with_keys(&parts.join("."), Algorithm::EdDSA, &[good]).is_err());
    }

    #[tokio::test]
    async fn id_token_algorithms_refused() {
        let o = client();
        // Unreachable JWKS: refused before any key is needed.
        let uri = "https://127.0.0.1:1/jwks";
        let hs = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &claims(),
            &jsonwebtoken::EncodingKey::from_secret(b"secret").unwrap(),
        )
        .unwrap();
        let e = o.verify_id_token(uri, &hs).await.unwrap_err();
        assert!(e.to_string().contains("algorithm refused"), "{e:#}");
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(claims().to_string())
        );
        assert!(o.verify_id_token(uri, &none).await.is_err());
    }

    #[tokio::test]
    async fn signing_keys_cache_and_filters() {
        let o = client();
        let keys = vec![
            jwk("k1", ED1_X, json!({"use": "sig"})),
            jwk("k2", ED2_X, json!({"use": "enc"})),
        ];
        *o.jwks.lock().await = Some((keys, Instant::now()));
        let uri = "https://127.0.0.1:1/jwks"; // must not be fetched
        assert_eq!(o.signing_keys(uri, Some("k1")).await.unwrap().len(), 1);
        // Encryption key never used to verify signatures.
        assert!(o.signing_keys(uri, Some("k2")).await.unwrap().is_empty());
        // Unknown kid on a fresh cache: no refetch storm, just no key.
        assert!(o.signing_keys(uri, Some("k9")).await.unwrap().is_empty());
        // End to end with the cached key.
        let c = o.verify_id_token(uri, &signed("k1", &claims())).await.unwrap();
        assert_eq!(c["preferred_username"], "alice");
    }

    #[tokio::test]
    async fn jwks_download() {
        let o = client();
        let serve = |body: Vec<u8>| {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                if let Some(mut c) = l.incoming().flatten().next() {
                    let mut b = [0u8; 1024];
                    let _ = c.read(&mut b);
                    let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
                    let _ = c.write_all(&body);
                }
            });
            format!("http://{addr}/jwks")
        };
        // Unparseable keys are skipped, not fatal.
        let set = json!({"keys": [{"kty": "OKP", "kid": 5}, {"kty": "OKP", "crv": "Ed25519", "x": ED1_X, "kid": "k1"}]});
        let keys = o.fetch_jwks(&serve(set.to_string().into_bytes())).await.unwrap();
        assert_eq!(keys.len(), 1);
        // Oversized JWKS refused.
        let huge = format!(r#"{{"keys":[],"pad":"{}"}}"#, "a".repeat(JWKS_MAX));
        let e = o.fetch_jwks(&serve(huge.into_bytes())).await.unwrap_err();
        assert!(e.to_string().contains("larger than"), "{e:#}");
    }

    #[test]
    fn cookies_and_encoding() {
        assert_eq!(cookie(Some("a=1; drydock_session=abc; b=2"), SESSION_COOKIE), Some("abc"));
        assert_eq!(cookie(None, SESSION_COOKIE), None);
        // HTTPS: prefixed names, and the unprefixed cookie is not accepted for them.
        let cfg = oidc();
        assert_eq!(cfg.session_cookie(), "__Host-drydock_session");
        assert_eq!(cfg.state_cookie(), "__Secure-drydock_oidc_state");
        assert_eq!(cookie(Some("drydock_session=forged"), cfg.session_cookie()), None);
        let c = set_cookie(cfg.session_cookie(), "v", "/", 60, cfg.secure_cookies());
        assert!(c.contains("; Secure") && c.contains("Path=/;") && !c.contains("Domain"), "{c}");
        // Plain HTTP on loopback (local tests): unprefixed, the browser would drop prefixed ones.
        let mut local = oidc();
        local.redirect_url = "http://localhost:8080/auth/callback".into();
        assert_eq!(local.session_cookie(), SESSION_COOKIE);
        assert_eq!(local.state_cookie(), STATE_COOKIE);
        assert_eq!(form_encode("a b:c&d"), "a+b%3Ac%26d");
        assert_eq!(decode_jwt_payload("x.eyJhIjoxfQ.y").unwrap()["a"], 1);
        assert_ne!(random_token(), random_token());
    }
}
