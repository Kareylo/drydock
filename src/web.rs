use crate::auth::{self, AuthConfig, Cidr};
use crate::{jobs, scan, AppState};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use serde::Deserialize;
use serde_json::json;
use axum::http::HeaderValue;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

const INDEX: &str = include_str!("../web/index.html");

/// CSP allowing only the page's own inline `<script>` and `<style>` blocks (by hash).
static CSP: LazyLock<HeaderValue> = LazyLock::new(|| {
    let hash = |tag: &str| -> String {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let body = INDEX
            .split_once(&open)
            .and_then(|(_, rest)| rest.split_once(&close))
            .map_or("", |(b, _)| b);
        let digest = Sha256::digest(body.as_bytes());
        format!("'sha256-{}'", base64::engine::general_purpose::STANDARD.encode(digest))
    };
    let csp = format!(
        "default-src 'none'; script-src {}; style-src {}; connect-src 'self'; img-src 'self' data:; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        hash("script"),
        hash("style")
    );
    HeaderValue::from_str(&csp).expect("valid CSP header")
});

/// Basic credential checks per client: a burst, then a steady rate per second.
const PEER_BURST: f64 = 5.0;
const PEER_RATE: f64 = 1.0;
/// All clients together: bounds guessing spread over many addresses.
const GLOBAL_BURST: f64 = 20.0;
const GLOBAL_RATE: f64 = 2.0;
/// Clients tracked at once; beyond, idle ones are dropped (then only the global
/// budget applies to new clients until room is made).
const MAX_PEERS: usize = 10_000;

/// Token bucket of credential checks. A token is taken *before* the
/// comparison and given back on success, so only failures consume it: a
/// logged-in UI polling the API never drains it.
struct AuthBucket {
    tokens: f64,
    last: Option<Instant>,
    burst: f64,
    rate: f64,
}

impl AuthBucket {
    const fn new(burst: f64, rate: f64) -> Self {
        Self { tokens: burst, last: None, burst, rate }
    }

    fn refill(&mut self, now: Instant) {
        if let Some(last) = self.last {
            let refill = now.saturating_duration_since(last).as_secs_f64() * self.rate;
            self.tokens = (self.tokens + refill).min(self.burst);
        }
        self.last = Some(now);
    }

    fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refund(&mut self) {
        self.tokens = (self.tokens + 1.0).min(self.burst);
    }

    /// Full again: forgetting it changes nothing.
    fn is_idle(&self, now: Instant) -> bool {
        self.last.is_none_or(|l| now.saturating_duration_since(l).as_secs_f64() * self.rate + self.tokens >= self.burst)
    }
}

/// Per-client buckets in front of a global one. One noisy client only empties
/// its own budget, so it cannot lock everyone else out; the global budget
/// still bounds guessing from many addresses (about `GLOBAL_RATE` per second).
struct AuthLimiter {
    global: AuthBucket,
    peers: HashMap<IpAddr, AuthBucket>,
}

impl AuthLimiter {
    fn new() -> Self {
        Self { global: AuthBucket::new(GLOBAL_BURST, GLOBAL_RATE), peers: HashMap::new() }
    }

    fn take(&mut self, client: Option<IpAddr>, now: Instant) -> bool {
        let key = client.map(client_key);
        if let Some(k) = key {
            if !self.peers.contains_key(&k) && self.peers.len() >= MAX_PEERS {
                self.peers.retain(|_, b| !b.is_idle(now));
            }
            if self.peers.len() < MAX_PEERS || self.peers.contains_key(&k) {
                let peer = self.peers.entry(k).or_insert_with(|| AuthBucket::new(PEER_BURST, PEER_RATE));
                if !peer.take(now) {
                    return false; // the global budget is left untouched
                }
            }
        }
        if self.global.take(now) {
            return true;
        }
        // Not checked after all: the client keeps its token.
        if let Some(b) = key.and_then(|k| self.peers.get_mut(&k)) {
            b.refund();
        }
        false
    }

    fn refund(&mut self, client: Option<IpAddr>) {
        self.global.refund();
        if let Some(b) = client.map(client_key).and_then(|k| self.peers.get_mut(&k)) {
            b.refund();
        }
    }
}

/// Bucket key of a client: its IPv4 address, or its IPv6 /64 (one host
/// usually owns a whole /64, so per-address buckets would be free to multiply).
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        },
        v4 => v4,
    }
}

/// The client behind a request: the TCP peer, or, when that peer is one of
/// `TRUSTED_PROXIES`, the right-most `X-Forwarded-For` address that is not a
/// trusted proxy itself (entries further left are set by the client and can be
/// forged).
fn client_ip(peer: Option<IpAddr>, forwarded_for: Option<&str>, trusted: &[Cidr]) -> Option<IpAddr> {
    let peer = peer?;
    let is_trusted = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));
    if !is_trusted(peer) {
        return Some(peer);
    }
    let Some(xff) = forwarded_for else {
        return Some(peer);
    };
    for part in xff.rsplit(',') {
        match part.trim().parse::<IpAddr>() {
            Ok(ip) if is_trusted(ip) => continue,
            Ok(ip) => return Some(ip),
            Err(_) => break, // malformed: fall back to the proxy itself
        }
    }
    Some(peer)
}

static AUTH_LIMITER: LazyLock<std::sync::Mutex<AuthLimiter>> =
    LazyLock::new(|| std::sync::Mutex::new(AuthLimiter::new()));
/// Logins rejected with 429 since the last logged failure.
static AUTH_REJECTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn lock(limiter: &std::sync::Mutex<AuthLimiter>) -> std::sync::MutexGuard<'_, AuthLimiter> {
    limiter.lock().unwrap_or_else(|e| e.into_inner())
}

async fn security_headers(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    // Browsers ignore it over plain HTTP; behind the TLS proxy it pins HTTPS.
    if state.cfg.hsts {
        h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    }
    h.insert(header::CONTENT_SECURITY_POLICY, CSP.clone());
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Authenticated user name, set by `auth_guard` (empty with `AUTH_MODE=none`).
#[derive(Clone)]
pub struct AuthUser(pub String);

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/scan", post(api_scan))
        .route("/api/stacks/{id}/update", post(api_update))
        .route("/api/jobs/{id}", get(api_job))
        .layer(middleware::from_fn_with_state(state.clone(), auth_guard));
    // OIDC login flow: public, but behind the Host and cross-site checks.
    let login = Router::new()
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .route("/auth/logout", post(auth_logout));
    let guarded = protected
        .merge(login)
        // Last layer runs first: Host check, then cross-site check, then credentials.
        .layer(middleware::from_fn(same_origin_guard))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(guarded)
        .layer(middleware::from_fn_with_state(state.clone(), security_headers))
        .with_state(state)
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// `Host` without port, lowercased.
fn host_name(host: &str) -> String {
    let h = host.trim().to_lowercase();
    match h.strip_prefix('[') {
        // [::1]:8080
        Some(rest) => rest.split(']').next().unwrap_or_default().to_string(),
        None => h.split(':').next().unwrap_or_default().to_string(),
    }
}

/// DNS rebinding: with `ALLOWED_HOSTS`, only those names may be used to reach the UI.
fn host_allowed(host: Option<&str>, allowed: &[String]) -> bool {
    allowed.is_empty() || host.is_some_and(|h| allowed.contains(&host_name(h)))
}

/// CSRF: a state-changing request must come from Drydock's own page (or from a
/// non-browser client, which sends neither `Sec-Fetch-Site` nor `Origin`).
fn same_origin(method: &Method, sec_fetch_site: Option<&str>, origin: Option<&str>, host: Option<&str>) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    if let Some(site) = sec_fetch_site {
        return site == "same-origin" || site == "none";
    }
    match origin {
        None => true,
        Some(o) => {
            let o_host = o.split_once("://").map(|(_, rest)| rest.trim_end_matches('/'));
            o_host.is_some() && o_host.map(str::to_lowercase) == host.map(|h| h.trim().to_lowercase())
        }
    }
}

async fn host_guard(State(state): State<Arc<AppState>>, headers: HeaderMap, req: Request, next: Next) -> Response {
    if host_allowed(header_str(&headers, header::HOST), &state.cfg.allowed_hosts) {
        next.run(req).await
    } else {
        (StatusCode::MISDIRECTED_REQUEST, "host not allowed").into_response()
    }
}

async fn same_origin_guard(headers: HeaderMap, req: Request, next: Next) -> Response {
    let ok = same_origin(
        req.method(),
        header_str(&headers, header::HeaderName::from_static("sec-fetch-site")),
        header_str(&headers, header::ORIGIN),
        header_str(&headers, header::HOST),
    );
    if ok {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "cross-site request refused").into_response()
    }
}

/// Authentication of the UI and API, according to `AUTH_MODE`.
async fn auth_guard(State(state): State<Arc<AppState>>, mut req: Request, next: Next) -> Response {
    let user = match &state.cfg.auth {
        AuthConfig::None => Ok(String::new()),
        AuthConfig::Basic { user, pass } => {
            let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
            let xff = header_str(req.headers(), header::HeaderName::from_static("x-forwarded-for"));
            let client = client_ip(peer, xff, &state.cfg.trusted_proxies);
            basic_check(&AUTH_LIMITER, client, req.headers(), user, pass).await
        }
        AuthConfig::Proxy(p) => {
            let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
            let h = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());
            let user = p.user_header.as_deref().and_then(h);
            auth::check_proxy(p, peer, h(&p.secret_header), user).map_err(|why| {
                tracing::warn!("requête refusée (mode proxy) : {why}");
                (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
            })
        }
        AuthConfig::Oidc(_) => {
            let session = match (&state.oidc, state.oidc.as_ref().and_then(|o| auth::cookie(header_str(req.headers(), header::COOKIE), o.cfg.session_cookie()))) {
                (Some(o), Some(id)) => o.session(id).await,
                _ => None,
            };
            match session {
                Some(s) => Ok(s.user),
                // The page itself goes to the provider; API calls get a 401 the UI acts on.
                None if req.method() == Method::GET && req.uri().path() == "/" => {
                    Err((StatusCode::FOUND, [(header::LOCATION, "auth/login")]).into_response())
                }
                None => Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "unauthenticated", "login": "auth/login" })),
                )
                    .into_response()),
            }
        }
    };
    match user {
        Ok(u) => {
            req.extensions_mut().insert(AuthUser(u));
            next.run(req).await
        }
        Err(resp) => resp,
    }
}

/// HTTP Basic check. No credential is compared without a token from
/// `AUTH_LIMITER`: a 429 tells nothing about the password it carried.
#[allow(
    clippy::result_large_err,
    reason = "the error is the HTTP response itself, returned once per request"
)]
async fn basic_check(
    limiter: &std::sync::Mutex<AuthLimiter>,
    client: Option<IpAddr>,
    headers: &HeaderMap,
    user: &str,
    pass: &str,
) -> Result<String, Response> {
    let challenge = || {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"drydock\"")],
            "unauthorized",
        )
            .into_response()
    };
    // The browser's first, credential-less request costs nothing.
    let Some(given) = headers.get(header::AUTHORIZATION) else {
        return Err(challenge());
    };
    if !lock(limiter).take(client, Instant::now()) {
        AUTH_REJECTED.fetch_add(1, Ordering::Relaxed);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            "too many attempts",
        )
            .into_response());
    }
    let ok = given
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .is_some_and(|creds| credentials_match(&creds, user, pass));
    if ok {
        lock(limiter).refund(client);
        return Ok(user.to_string());
    }
    match AUTH_REJECTED.swap(0, Ordering::Relaxed) {
        0 => tracing::warn!("authentification UI refusée"),
        n => tracing::warn!("authentification UI refusée ({n} autre(s) tentative(s) rejetée(s) en 429)"),
    }
    Err(challenge())
}

fn plain(status: StatusCode, msg: String) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], msg).into_response()
}

/// `GET /auth/login`: redirect to the OIDC provider.
async fn auth_login(State(state): State<Arc<AppState>>) -> Response {
    let Some(oidc) = &state.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match oidc.begin_login().await {
        Ok((url, sealed_login)) => {
            let cookie = auth::set_cookie(oidc.cfg.state_cookie(), &sealed_login, "/auth", 600, oidc.cfg.secure_cookies());
            (StatusCode::FOUND, [(header::LOCATION, url), (header::SET_COOKIE, cookie)]).into_response()
        }
        Err(e) => {
            tracing::error!("OIDC : connexion impossible : {e:#}");
            plain(StatusCode::BAD_GATEWAY, "Fournisseur OIDC injoignable, voir les logs de Drydock.".into())
        }
    }
}

/// `GET /auth/callback`: back from the provider, open a session.
async fn auth_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(oidc) = &state.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(err) = q.get("error") {
        // Anyone can call this URL: keep only an RFC 6749 error code, and log
        // it with `?` so no control character reaches the logs.
        let code = oauth_error_code(err);
        tracing::warn!(error = ?code, "OIDC : le fournisseur a refusé la connexion");
        return plain(StatusCode::FORBIDDEN, format!("Connexion refusée par le fournisseur ({code})."));
    }
    let (Some(code), Some(login_state)) = (q.get("code"), q.get("state")) else {
        return plain(StatusCode::BAD_REQUEST, "Paramètres code/state manquants.".into());
    };
    let cookie_state = auth::cookie(header_str(&headers, header::COOKIE), oidc.cfg.state_cookie());
    match oidc.finish_login(login_state, cookie_state, code).await {
        Ok((session_id, user)) => {
            tracing::info!("OIDC : connexion de {user}");
            let secure = oidc.cfg.secure_cookies();
            let mut h = HeaderMap::new();
            h.insert(header::LOCATION, HeaderValue::from_static("../"));
            let ttl = oidc.cfg.session_ttl.as_secs();
            for c in [
                auth::set_cookie(oidc.cfg.session_cookie(), &session_id, "/", ttl, secure),
                auth::set_cookie(oidc.cfg.state_cookie(), "", "/auth", 0, secure),
            ] {
                if let Ok(v) = HeaderValue::from_str(&c) {
                    h.append(header::SET_COOKIE, v);
                }
            }
            (StatusCode::FOUND, h).into_response()
        }
        Err(e) => {
            // The reason (unauthorized user, token endpoint error…) stays in the logs.
            tracing::warn!(error = ?format!("{e:#}"), "OIDC : connexion refusée");
            plain(StatusCode::FORBIDDEN, "Connexion refusée, voir les logs de Drydock.".into())
        }
    }
}

/// OAuth `error` value reduced to the RFC 6749 code charset, 64 chars at most.
fn oauth_error_code(err: &str) -> String {
    err.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(64)
        .collect()
}

/// `POST /auth/logout`: close the Drydock session (the provider session stays).
async fn auth_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(oidc) = &state.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(id) = auth::cookie(header_str(&headers, header::COOKIE), oidc.cfg.session_cookie()) {
        oidc.logout(id).await;
    }
    let clear = auth::set_cookie(oidc.cfg.session_cookie(), "", "/", 0, oidc.cfg.secure_cookies());
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, clear)]).into_response()
}

/// Compares fixed-length digests in constant time: neither the content nor the
/// length of the expected credentials leaks through timing.
fn credentials_match(given: &str, user: &str, pass: &str) -> bool {
    let a = Sha256::digest(given.as_bytes());
    let b = Sha256::digest(format!("{user}:{pass}").as_bytes());
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn api_state(State(state): State<Arc<AppState>>, user: Option<Extension<AuthUser>>) -> impl IntoResponse {
    let snap = state.snapshot.read().await.clone();
    let jobs: Vec<_> = state.jobs.lock().await.values().rev().take(20).cloned().collect();
    Json(json!({
        "auth": state.cfg.auth.mode(),
        "user": user.map(|u| u.0.0.clone()).filter(|u| !u.is_empty()),
        "scanning": state.scanning.load(Ordering::SeqCst),
        "last_scan": snap.last_scan,
        "last_error": snap.last_error,
        "pangolin": state.pangolin.is_some(),
        "pangolin_error": snap.pangolin_error,
        "stacks": snap.stacks,
        "jobs": jobs,
    }))
}

/// Name of the authenticated user for logs and jobs (`-` with `AUTH_MODE=none`).
fn requester(user: Option<Extension<AuthUser>>) -> String {
    user.map(|u| u.0.0).filter(|u| !u.is_empty()).unwrap_or_else(|| "-".into())
}

async fn api_scan(State(state): State<Arc<AppState>>, user: Option<Extension<AuthUser>>) -> impl IntoResponse {
    // `?`: the name may come from a proxy header or an ID token claim.
    tracing::info!(user = ?requester(user), "analyse demandée");
    tokio::spawn(scan(state));
    StatusCode::ACCEPTED
}

#[derive(Deserialize, Default)]
struct UpdateBody {
    #[serde(default)]
    force: bool,
}

async fn api_update(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthUser>>,
    Path(id): Path<i64>,
    // A JSON body is required: `Content-Type: application/json` cannot be sent
    // cross-site without a CORS preflight, which Drydock never answers.
    Json(body): Json<UpdateBody>,
) -> Response {
    let who = requester(user);
    tracing::info!(user = ?who, stack = id, force = body.force, "mise à jour demandée");
    match jobs::start(state, id, body.force, who).await {
        Ok(job) => (StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(json!({ "error": format!("{e:#}") }))).into_response(),
    }
}

async fn api_job(State(state): State<Arc<AppState>>, Path(id): Path<u64>) -> Response {
    match state.jobs.lock().await.get(&id) {
        Some(j) => Json(j.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_site_requests_are_refused() {
        let post = Method::POST;
        let host = Some("drydock.example.com");
        // Browser, same page.
        assert!(same_origin(&post, Some("same-origin"), Some("https://drydock.example.com"), host));
        // Browser, other site (fetch no-cors / form).
        assert!(!same_origin(&post, Some("cross-site"), Some("https://evil.example"), host));
        assert!(!same_origin(&post, Some("same-site"), Some("https://other.example.com"), host));
        // Older browser without Sec-Fetch-*: Origin decides.
        assert!(same_origin(&post, None, Some("https://drydock.example.com"), host));
        assert!(!same_origin(&post, None, Some("https://evil.example"), host));
        assert!(!same_origin(&post, None, Some("null"), host));
        // curl / scripts.
        assert!(same_origin(&post, None, None, host));
        // Reads are never blocked here.
        assert!(same_origin(&Method::GET, Some("cross-site"), None, host));
    }

    #[test]
    fn oauth_error_is_sanitized() {
        assert_eq!(oauth_error_code("access_denied"), "access_denied");
        let forged = "a\n2026-11-23T10:00:00Z INFO drydock: OIDC : connexion de admin";
        let code = oauth_error_code(forged);
        assert!(!code.contains('\n') && !code.contains(' ') && !code.contains(':'), "{code}");
        assert_eq!(oauth_error_code("<script>alert(1)</script>"), "scriptalert1script");
        assert_eq!(oauth_error_code(&"x".repeat(500)).len(), 64);
    }

    #[test]
    fn credentials() {
        assert!(credentials_match("admin:secret", "admin", "secret"));
        assert!(!credentials_match("admin:secreT", "admin", "secret"));
        assert!(!credentials_match("admin:secret2", "admin", "secret"));
        assert!(!credentials_match("", "admin", "secret"));
    }

    fn secs(t0: Instant, s: u64) -> Instant {
        t0 + std::time::Duration::from_secs(s)
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn auth_bucket_bounds_failures() {
        let t0 = Instant::now();
        let mut b = AuthBucket::new(PEER_BURST, PEER_RATE);
        // A flood at one instant: only the burst is checked.
        assert_eq!((0..200).filter(|_| b.take(t0)).count(), PEER_BURST as usize);
        // Then the rate.
        assert_eq!((0..200).filter(|_| b.take(secs(t0, 3))).count(), (3.0 * PEER_RATE) as usize);
        // Never more than the burst after a long pause.
        assert_eq!((0..200).filter(|_| b.take(secs(t0, 3603))).count(), PEER_BURST as usize);
    }

    #[test]
    fn auth_bucket_successes_are_free() {
        let t0 = Instant::now();
        let mut l = AuthLimiter::new();
        // A logged-in UI polling many times at once never drains anything.
        for _ in 0..1000 {
            assert!(l.take(ip("10.0.0.1"), t0));
            l.refund(ip("10.0.0.1"));
        }
        assert_eq!(l.global.tokens, GLOBAL_BURST);
        assert_eq!(l.peers[&"10.0.0.1".parse::<IpAddr>().unwrap()].tokens, PEER_BURST);
    }

    #[test]
    fn one_client_cannot_lock_out_others() {
        let t0 = Instant::now();
        let mut l = AuthLimiter::new();
        // An attacker failing once per second for a minute…
        for s in 0..60 {
            l.take(ip("203.0.113.9"), secs(t0, s));
        }
        // …is throttled itself, while another client still gets checked.
        assert!(!(0..10).all(|_| l.take(ip("203.0.113.9"), secs(t0, 60))));
        assert!(l.take(ip("198.51.100.7"), secs(t0, 60)));
    }

    #[test]
    fn many_clients_stay_globally_bounded() {
        let t0 = Instant::now();
        let mut l = AuthLimiter::new();
        // 1000 addresses at once: only the global burst is checked.
        let checked = (0..1000u32)
            .filter(|i| l.take(Some(IpAddr::V4((0x0a00_0000 + i).into())), t0))
            .count();
        assert_eq!(checked, GLOBAL_BURST as usize);
        // Clients refused by the global budget keep their own tokens.
        assert_eq!(l.peers[&IpAddr::V4(0x0a00_0100.into())].tokens, PEER_BURST);
        // Then about GLOBAL_RATE per second.
        let checked = (0..1000u32)
            .filter(|i| l.take(Some(IpAddr::V4((0x0b00_0000 + i).into())), secs(t0, 10)))
            .count();
        assert_eq!(checked, (10.0 * GLOBAL_RATE) as usize);
    }

    #[test]
    fn peer_table_is_bounded() {
        let t0 = Instant::now();
        let mut l = AuthLimiter::new();
        l.global = AuthBucket::new(f64::MAX, 0.0);
        for i in 0..(MAX_PEERS as u32 + 500) {
            l.take(Some(IpAddr::V4((0x0a00_0000 + i).into())), t0);
        }
        assert!(l.peers.len() <= MAX_PEERS);
        // Much later every bucket is full again: room is made for new clients.
        assert!(l.take(ip("192.0.2.1"), secs(t0, 3600)));
        assert!(l.peers.contains_key(&"192.0.2.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn ipv6_clients_share_their_64() {
        assert_eq!(client_key("2001:db8:1:2::1".parse().unwrap()), client_key("2001:db8:1:2:ffff::9".parse().unwrap()));
        assert_ne!(client_key("2001:db8:1:2::1".parse().unwrap()), client_key("2001:db8:1:3::1".parse().unwrap()));
        assert_eq!(client_key("::ffff:10.1.2.3".parse().unwrap()), "10.1.2.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_trusts_only_configured_proxies() {
        let trusted = vec![Cidr::parse("172.18.0.0/16").unwrap()];
        let proxy = ip("172.18.0.2");
        // Direct client: X-Forwarded-For is ignored (it could be forged).
        assert_eq!(client_ip(ip("203.0.113.9"), Some("1.2.3.4"), &trusted), ip("203.0.113.9"));
        // Through the proxy: right-most untrusted entry, left-most entries are client-set.
        assert_eq!(client_ip(proxy, Some("1.2.3.4, 203.0.113.9"), &trusted), ip("203.0.113.9"));
        assert_eq!(client_ip(proxy, Some("203.0.113.9, 172.18.0.5"), &trusted), ip("203.0.113.9"));
        // No header or garbage: the proxy itself.
        assert_eq!(client_ip(proxy, None, &trusted), proxy);
        assert_eq!(client_ip(proxy, Some("not-an-ip"), &trusted), proxy);
        // No TRUSTED_PROXIES: always the TCP peer.
        assert_eq!(client_ip(proxy, Some("203.0.113.9"), &[]), proxy);
    }

    fn basic(creds: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
        h.insert(header::AUTHORIZATION, format!("Basic {b64}").parse().unwrap());
        h
    }

    #[tokio::test]
    async fn parallel_guesses_are_not_evaluated() {
        // Own limiter: tests run in parallel and must not share the global one.
        let limiter = std::sync::Mutex::new(AuthLimiter::new());
        let attacker = ip("203.0.113.9");
        let h = basic("admin:wrong-password");
        let results =
            futures::future::join_all((0..200).map(|_| basic_check(&limiter, attacker, &h, "admin", "secret"))).await;
        let evaluated = results
            .iter()
            .filter(|r| r.as_ref().unwrap_err().status() == StatusCode::UNAUTHORIZED)
            .count();
        // Burst plus at most one refill during the run.
        assert!(evaluated <= PEER_BURST as usize + 1, "{evaluated} guesses evaluated");
        // The attacker gets 429 even with the right password…
        let r = basic_check(&limiter, attacker, &basic("admin:secret"), "admin", "secret").await.unwrap_err();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        // …but another client logs in.
        let ok = basic_check(&limiter, ip("198.51.100.7"), &basic("admin:secret"), "admin", "secret").await;
        assert_eq!(ok.unwrap(), "admin");
    }

    #[tokio::test]
    async fn basic_check_without_header_costs_nothing() {
        let limiter = std::sync::Mutex::new(AuthLimiter::new());
        for _ in 0..100 {
            let r = basic_check(&limiter, ip("10.0.0.1"), &HeaderMap::new(), "admin", "secret").await.unwrap_err();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
            assert!(r.headers().contains_key(header::WWW_AUTHENTICATE));
        }
        let l = lock(&limiter);
        assert_eq!(l.global.tokens, GLOBAL_BURST);
        assert!(l.peers.is_empty());
    }

    #[test]
    fn requester_names() {
        assert_eq!(requester(Some(Extension(AuthUser("alice".into())))), "alice");
        assert_eq!(requester(Some(Extension(AuthUser(String::new())))), "-");
        assert_eq!(requester(None), "-");
    }

    #[test]
    fn csp_hashes_inline_blocks() {
        let csp = CSP.to_str().unwrap();
        assert_eq!(csp.matches("'sha256-").count(), 2, "{csp}");
        assert!(!csp.contains("unsafe-inline"));
        // Empty-string hash would mean the block was not found.
        assert!(!csp.contains("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
    }

    #[test]
    fn host_allow_list() {
        let allowed = vec!["drydock.example.com".to_string()];
        assert!(host_allowed(Some("drydock.example.com"), &allowed));
        assert!(host_allowed(Some("Drydock.Example.com:443"), &allowed));
        assert!(!host_allowed(Some("attacker.example"), &allowed));
        assert!(!host_allowed(None, &allowed));
        assert!(host_allowed(Some("anything"), &[]));
        assert_eq!(host_name("[::1]:8080"), "::1");
    }
}
