use crate::{jobs, scan, AppState};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use axum::http::HeaderValue;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

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

/// At most one failed login is being throttled (1 s) at any time.
static AUTH_FAILURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Failed logins rejected with 429 since the last logged failure.
static AUTH_REJECTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, CSP.clone());
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/scan", post(api_scan))
        .route("/api/stacks/{id}/update", post(api_update))
        .route("/api/jobs/{id}", get(api_job))
        // Last layer runs first: Host check, then cross-site check, then credentials.
        .layer(middleware::from_fn_with_state(state.clone(), basic_auth))
        .layer(middleware::from_fn(same_origin_guard))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(protected)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

fn header_str<'a>(headers: &'a HeaderMap, name: header::HeaderName) -> Option<&'a str> {
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

async fn basic_auth(State(state): State<Arc<AppState>>, headers: HeaderMap, req: Request, next: Next) -> Response {
    let Some((user, pass)) = &state.cfg.basic_auth else {
        // Only possible with UI_AUTH_DISABLED=true (checked at startup).
        return next.run(req).await;
    };
    let ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .is_some_and(|creds| credentials_match(&creds, user, pass));
    if ok {
        next.run(req).await
    } else {
        if headers.contains_key(header::AUTHORIZATION) {
            // Wrong credentials (not just the browser's first, credential-less request).
            // One failure is throttled at a time; others are rejected at once
            // instead of queueing (no pile-up of connections during a flood).
            let Ok(_slot) = AUTH_FAILURE.try_lock() else {
                AUTH_REJECTED.fetch_add(1, Ordering::Relaxed);
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, "1")],
                    "too many attempts",
                )
                    .into_response();
            };
            match AUTH_REJECTED.swap(0, Ordering::Relaxed) {
                0 => tracing::warn!("authentification UI refusée"),
                n => tracing::warn!("authentification UI refusée ({n} autre(s) tentative(s) rejetée(s) en 429)"),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"drydock\"")],
            "unauthorized",
        )
            .into_response()
    }
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

async fn api_state(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.snapshot.read().await.clone();
    let jobs: Vec<_> = state.jobs.lock().await.values().rev().take(20).cloned().collect();
    Json(json!({
        "scanning": state.scanning.load(Ordering::SeqCst),
        "last_scan": snap.last_scan,
        "last_error": snap.last_error,
        "pangolin": state.pangolin.is_some(),
        "pangolin_error": snap.pangolin_error,
        "stacks": snap.stacks,
        "jobs": jobs,
    }))
}

async fn api_scan(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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
    Path(id): Path<i64>,
    // A JSON body is required: `Content-Type: application/json` cannot be sent
    // cross-site without a CORS preflight, which Drydock never answers.
    Json(body): Json<UpdateBody>,
) -> Response {
    match jobs::start(state, id, body.force).await {
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
    fn credentials() {
        assert!(credentials_match("admin:secret", "admin", "secret"));
        assert!(!credentials_match("admin:secreT", "admin", "secret"));
        assert!(!credentials_match("admin:secret2", "admin", "secret"));
        assert!(!credentials_match("", "admin", "secret"));
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
