mod analysis;
mod auth;
mod compose;
mod config;
mod jobs;
mod pangolin;
mod portainer;
mod registry;
mod selfid;
mod version;
mod web;

use analysis::{analyse_stack, now, StackReport};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use jobs::Job;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

#[derive(Default, Clone, Serialize)]
pub struct Snapshot {
    pub stacks: Vec<StackReport>,
    pub last_scan: Option<u64>,
    pub last_error: Option<String>,
    /// Pangolin resources could not be listed: updates are blocked until it is fixed.
    pub pangolin_error: Option<String>,
}

pub struct AppState {
    pub cfg: config::Config,
    pub portainer: portainer::Portainer,
    pub registry: registry::Registry,
    pub pangolin: Option<pangolin::Pangolin>,
    pub snapshot: RwLock<Snapshot>,
    pub jobs: Mutex<BTreeMap<u64, Job>>,
    pub scanning: AtomicBool,
    /// Drydock's own container: its stack is never updated.
    pub self_id: Option<selfid::SelfId>,
    /// OIDC logins and sessions (`AUTH_MODE=oidc`).
    pub oidc: Option<auth::Oidc>,
}

/// Full scan of all stacks. Returns immediately if a scan is already running.
pub async fn scan(state: Arc<AppState>) {
    if state.scanning.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::info!("scan started");
    let mut pangolin_error = None;
    let result: Result<Vec<StackReport>> = async {
        let stacks = state.portainer.stacks().await?;
        let resources = Arc::new(match &state.pangolin {
            Some(p) => match p.resources().await {
                Ok(r) => {
                    if state.cfg.pangolin.as_ref().is_some_and(|c| c.org_id.is_some()) {
                        tracing::info!("Pangolin: {} ressource(s) dans l'organisation", r.len());
                    }
                    r
                }
                Err(e) => {
                    tracing::error!("Pangolin: {e:#}");
                    pangolin_error = Some(format!("{e:#}"));
                    vec![]
                }
            },
            None => vec![],
        });
        let mut reports: Vec<StackReport> = stream::iter(stacks)
            .map(|s| analyse_stack(state.clone(), s, resources.clone()))
            .buffer_unordered(4)
            .collect()
            .await;
        reports.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(reports)
    }
    .await;
    {
        let mut snap = state.snapshot.write().await;
        match result {
            Ok(r) => {
                snap.stacks = r;
                snap.last_error = None;
            }
            Err(e) => {
                tracing::error!("scan failed: {e:#}");
                snap.last_error = Some(format!("{e:#}"));
            }
        }
        snap.pangolin_error = pangolin_error;
        snap.last_scan = Some(now());
    }
    state.scanning.store(false, Ordering::SeqCst);
    tracing::info!("scan finished");
}

/// `drydock healthcheck`: tiny HTTP probe (no curl in a scratch image).
async fn healthcheck() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let mut addr: SocketAddr = listen.parse()?;
    // A wildcard bind is reached through loopback; a specific IP is probed as is.
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        });
    }
    let mut s = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(addr),
    )
    .await??;
    s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
    let mut buf = vec![0; 64];
    let n = s.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    if head.contains(" 200 ") {
        Ok(())
    } else {
        anyhow::bail!("unhealthy: {head}")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return match healthcheck().await {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("{e:#}");
                std::process::exit(1)
            }
        };
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drydock=info".into()),
        )
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = config::Config::from_env()?;
    let cfg_auth = cfg.auth.clone();
    let state = Arc::new(AppState {
        portainer: portainer::Portainer::new(
            &cfg.portainer_url,
            &cfg.portainer_api_key,
            cfg.portainer_insecure,
            cfg.portainer_ca_file.as_deref(),
        )?,
        registry: registry::Registry::new(
            cfg.registry_auth.clone(),
            cfg.registry_realms.clone(),
            cfg.registry_allowlist.clone(),
        )?,
        pangolin: cfg.pangolin.clone().map(pangolin::Pangolin::new).transpose()?,
        cfg,
        snapshot: RwLock::new(Snapshot::default()),
        jobs: Mutex::new(BTreeMap::new()),
        scanning: AtomicBool::new(false),
        self_id: selfid::detect(),
        oidc: match &cfg_auth {
            auth::AuthConfig::Oidc(o) => Some(auth::Oidc::new(o.clone())?),
            _ => None,
        },
    });

    match &state.self_id {
        Some(id) => tracing::info!("conteneur Drydock : {} (sa stack ne sera jamais mise à jour)", id.short()),
        None => tracing::warn!(
            "conteneur Drydock non détecté : définir DRYDOCK_CONTAINER_ID si Drydock tourne dans une stack Portainer"
        ),
    }

    if state.cfg.portainer_insecure {
        tracing::warn!(
            "PORTAINER_INSECURE=true : certificat de Portainer non vérifié, la clé API peut être interceptée. Préférer PORTAINER_CA_FILE"
        );
    }
    if state.cfg.portainer_url.starts_with("http://") {
        tracing::warn!("PORTAINER_URL en http:// : la clé API circule en clair, à réserver à un réseau Docker isolé");
    }
    if state.cfg.pangolin.as_ref().is_some_and(|p| p.url.starts_with("http://")) {
        tracing::warn!(
            "PANGOLIN_URL en http:// : la clé d'intégration circule en clair, à réserver à un réseau Docker isolé"
        );
    }
    match &state.cfg.auth {
        auth::AuthConfig::Basic { .. } => tracing::info!("authentification UI : basic"),
        auth::AuthConfig::Proxy(p) => {
            tracing::info!("authentification UI : proxy (en-tête {})", p.secret_header);
            if p.trusted.is_empty() {
                tracing::warn!("PROXY_TRUSTED_IPS absent : seul le secret partagé protège Drydock");
            }
        }
        auth::AuthConfig::Oidc(o) => {
            tracing::info!("authentification UI : OIDC ({})", o.issuer);
            if o.allowed_users.is_empty() && o.allowed_groups.is_empty() {
                tracing::warn!(
                    "OIDC_ALLOWED_GROUPS et OIDC_ALLOWED_USERS absents : tout utilisateur du fournisseur peut mettre à jour les stacks"
                );
            }
        }
        auth::AuthConfig::None => {
            tracing::warn!("authentification UI désactivée (AUTH_MODE=none) : Drydock doit être protégé autrement");
            if state.cfg.allowed_hosts.is_empty() {
                tracing::warn!("ALLOWED_HOSTS absent : définir le domaine public de Drydock pour bloquer le DNS rebinding");
            }
        }
    }
    if let Err(e) = state.portainer.ping().await {
        tracing::warn!("Portainer not reachable yet: {e:#}");
    }
    if let Some(p) = &state.cfg.pangolin {
        if p.org_id.is_none() {
            tracing::warn!(
                "PANGOLIN_ORG_ID absent : pas de correspondance par le label `{}`, seules les ressources du label `{}` passeront en maintenance",
                state.cfg.url_label,
                state.cfg.resource_label
            );
        }
    }

    // Initial scan, then periodic scans.
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                scan(state.clone()).await;
                match state.cfg.scan_interval {
                    Some(i) => tokio::time::sleep(i).await,
                    None => break,
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&state.cfg.listen).await?;
    tracing::info!("listening on {}", state.cfg.listen);
    serve(listener, web::router(state)).await
}

/// Max concurrent connections; extra ones are closed at once.
const MAX_CONNECTIONS: usize = 256;
/// A client must send its first byte within this delay: silent connections
/// would otherwise hold a slot forever (protocol detection has no timeout).
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10);
/// A client must send its full request headers within this delay (anti-slowloris).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time left to in-flight requests after SIGTERM / Ctrl-C.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// HTTP/1 server with a first-byte deadline, a header read timeout, a
/// connection cap and graceful shutdown (`axum::serve` has none of the first
/// three). HTTP/2 is not served: the UI and reverse proxies use HTTP/1, and
/// idle HTTP/2 connections would escape the header timeout.
async fn serve(listener: tokio::net::TcpListener, app: axum::Router) -> Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::server::graceful::GracefulShutdown;
    use hyper_util::service::TowerToHyperService;

    let mut builder = Builder::new(TokioExecutor::new()).http1_only();
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let graceful = GracefulShutdown::new();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut full_logged = false;

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    // EMFILE and friends: keep serving instead of exiting.
                    tracing::warn!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            if !full_logged {
                tracing::warn!("{MAX_CONNECTIONS} connexions ouvertes : nouvelles connexions refusées");
                full_logged = true;
            }
            drop(stream);
            continue;
        };
        full_logged = false;
        // Peer address for handlers (proxy mode checks PROXY_TRUSTED_IPS).
        let svc = TowerToHyperService::new(
            app.clone().layer(axum::Extension(axum::extract::ConnectInfo(peer))),
        );
        let builder = builder.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            // Wait for the first byte in the task, never in the accept loop.
            let mut first = [0u8; 1];
            match tokio::time::timeout(FIRST_BYTE_TIMEOUT, stream.peek(&mut first)).await {
                Ok(Ok(n)) if n > 0 => {}
                _ => return, // silent, closed or failed: dropped, permit released
            }
            let conn = builder
                .serve_connection(TokioIo::new(stream), svc)
                .into_owned();
            let _ = watcher.watch(conn).await;
            drop(permit);
        });
    }

    drop(listener);
    tokio::select! {
        _ = graceful.shutdown() => {}
        _ = tokio::time::sleep(SHUTDOWN_GRACE) => tracing::warn!("arrêt : requêtes en cours abandonnées"),
    }
    Ok(())
}
