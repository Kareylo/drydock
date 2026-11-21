//! UI authentication modes: HTTP Basic, authenticating reverse proxy
//! (Pangolin SSO, Authelia forward-auth…) and native OpenID Connect.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
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
/// Caps on in-memory state (pending logins, sessions).
const MAX_PENDING: usize = 1000;
const MAX_SESSIONS: usize = 1000;
pub const SESSION_COOKIE: &str = "drydock_session";
pub const STATE_COOKIE: &str = "drydock_oidc_state";

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
            Some(u) => Ok(u.to_string()),
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
}

struct Pending {
    nonce: String,
    verifier: String,
    created: Instant,
}

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
    pending: Mutex<HashMap<String, Pending>>,
    sessions: Mutex<HashMap<String, Session>>,
}

/// Claims Drydock needs from the ID token.
#[derive(Debug)]
pub struct Identity {
    pub user: String,
}

impl Oidc {
    pub fn new(cfg: OidcConfig) -> Result<Self> {
        Ok(Self {
            cfg,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            discovery: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
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
        *self.discovery.lock().await = Some(d.clone());
        Ok(d)
    }

    /// Starts a login: returns the provider URL to redirect to and the `state`
    /// value, also set in a cookie to bind the callback to this browser.
    pub async fn begin_login(&self) -> Result<(String, String)> {
        let d = self.discovery().await?;
        let state = random_token();
        let nonce = random_token();
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        {
            let mut pending = self.pending.lock().await;
            pending.retain(|_, p| p.created.elapsed() < LOGIN_TTL);
            if pending.len() >= MAX_PENDING {
                bail!("too many logins in progress, retry later");
            }
            pending.insert(state.clone(), Pending { nonce: nonce.clone(), verifier, created: Instant::now() });
        }
        let mut url = reqwest::Url::parse(&d.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.cfg.redirect_url)
            .append_pair("scope", &self.cfg.scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((url.to_string(), state))
    }

    /// Completes a login: checks `state` against the cookie, exchanges the code
    /// and validates the ID token. Returns the new session id.
    pub async fn finish_login(&self, state: &str, cookie_state: Option<&str>, code: &str) -> Result<(String, String)> {
        if !cookie_state.is_some_and(|c| constant_time_eq(c, state)) {
            bail!("state does not match this browser's login");
        }
        let pending = self
            .pending
            .lock()
            .await
            .remove(state)
            .filter(|p| p.created.elapsed() < LOGIN_TTL)
            .context("unknown or expired login")?;
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
        // The ID token comes straight from the token endpoint over TLS (or
        // loopback), authenticated with the client secret: per OIDC Core
        // 3.1.3.7, TLS server validation replaces the signature check here.
        let claims = decode_jwt_payload(id_token)?;
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
    let user = username.or(email).unwrap_or(sub).to_string();

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

/// 256-bit random token, base64url.
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS random generator");
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

    #[test]
    fn cookies_and_encoding() {
        assert_eq!(cookie(Some("a=1; drydock_session=abc; b=2"), SESSION_COOKIE), Some("abc"));
        assert_eq!(cookie(None, SESSION_COOKIE), None);
        assert_eq!(form_encode("a b:c&d"), "a+b%3Ac%26d");
        assert_eq!(decode_jwt_payload("x.eyJhIjoxfQ.y").unwrap()["a"], 1);
        assert_ne!(random_token(), random_token());
    }
}
