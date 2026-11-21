use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::env;
use std::time::Duration;

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub portainer_url: String,
    pub portainer_api_key: String,
    pub portainer_insecure: bool,
    /// PEM certificate (or CA) trusted for Portainer, e.g. its self-signed certificate.
    pub portainer_ca_file: Option<String>,
    pub pangolin: Option<PangolinConfig>,
    /// Container label holding the public URL (matched against Pangolin `fullDomain`).
    pub url_label: String,
    /// Container label holding explicit Pangolin resource ids (`12,34`).
    pub resource_label: String,
    /// Container label to skip a service (`drydock.ignore=true`).
    pub ignore_label: String,
    /// Container label enabling/disabling updates (`drydock.enable=false`).
    pub enable_label: String,
    /// Opt-in mode: only containers with `<enable_label>=true` are updated.
    pub require_enable_label: bool,
    pub health_timeout: Duration,
    pub scan_interval: Option<Duration>,
    /// Keep the Pangolin maintenance page on when the stack never becomes healthy.
    pub keep_maintenance_on_failure: bool,
    /// `registry host -> (user, password)`.
    pub registry_auth: HashMap<String, (String, String)>,
    /// Extra token-realm hosts allowed to receive registry credentials.
    pub registry_realms: Vec<String>,
    /// When set, only these registries are queried (`REGISTRY_ALLOWLIST`).
    pub registry_allowlist: Vec<String>,
    pub basic_auth: Option<(String, String)>,
    /// Explicit opt-out of UI authentication (Drydock behind an authenticating proxy).
    pub auth_disabled: bool,
    /// Accepted `Host` values (DNS rebinding protection); empty = any.
    pub allowed_hosts: Vec<String>,
    pub maintenance_title: String,
    pub maintenance_message: String,
}

#[derive(Clone)]
pub struct PangolinConfig {
    pub url: String,
    pub api_key: String,
    pub org_id: Option<String>,
}

const REDACTED: &str = "***";

/// Secrets never appear in `{:?}` output.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("portainer_url", &self.portainer_url)
            .field("portainer_api_key", &REDACTED)
            .field("portainer_insecure", &self.portainer_insecure)
            .field("portainer_ca_file", &self.portainer_ca_file)
            .field("pangolin", &self.pangolin)
            .field("registry_auth", &self.registry_auth.keys().collect::<Vec<_>>())
            .field("registry_realms", &self.registry_realms)
            .field("registry_allowlist", &self.registry_allowlist)
            .field("basic_auth", &self.basic_auth.as_ref().map(|(u, _)| (u, REDACTED)))
            .field("auth_disabled", &self.auth_disabled)
            .field("allowed_hosts", &self.allowed_hosts)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PangolinConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PangolinConfig")
            .field("url", &self.url)
            .field("api_key", &REDACTED)
            .field("org_id", &self.org_id)
            .finish()
    }
}

/// Minimum UI password length: failed logins are throttled to about one per
/// second, so the password itself must resist that rate for years.
const MIN_PASSWORD_CHARS: usize = 12;

/// `user:password`, with a non-empty user and a password of at least 12 characters.
fn parse_basic_auth(v: &str) -> Result<(&str, &str)> {
    let (u, p) = v.split_once(':').context("UI_BASIC_AUTH must be user:password")?;
    if u.trim().is_empty() {
        bail!("UI_BASIC_AUTH: empty user name");
    }
    if p.chars().count() < MIN_PASSWORD_CHARS {
        bail!("UI_BASIC_AUTH: password must be at least {MIN_PASSWORD_CHARS} characters");
    }
    Ok((u, p))
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn var_or(name: &str, default: &str) -> String {
    var(name).unwrap_or_else(|| default.to_string())
}

fn bool_var(name: &str, default: bool) -> bool {
    var(name)
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

/// Reads `NAME`, or the content of the file named by `NAME_FILE` (Docker secrets).
fn secret(name: &str) -> Result<Option<String>> {
    if let Some(v) = var(name) {
        return Ok(Some(v));
    }
    if let Some(path) = var(&format!("{name}_FILE")) {
        let v = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
        return Ok(Some(v.trim().to_string()));
    }
    Ok(None)
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let portainer_url = var("PORTAINER_URL").context("PORTAINER_URL is required")?;
        let portainer_api_key =
            secret("PORTAINER_API_KEY")?.context("PORTAINER_API_KEY is required")?;

        let pangolin = match (var("PANGOLIN_URL"), secret("PANGOLIN_API_KEY")?) {
            (Some(url), Some(api_key)) => Some(PangolinConfig {
                url: url.trim_end_matches('/').to_string(),
                api_key,
                org_id: var("PANGOLIN_ORG_ID"),
            }),
            (None, None) => None,
            _ => bail!("PANGOLIN_URL and PANGOLIN_API_KEY must be set together"),
        };

        // REGISTRY_AUTH="docker.io=user:token,ghcr.io=user:token"
        let mut registry_auth = HashMap::new();
        if let Some(raw) = secret("REGISTRY_AUTH")? {
            for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                let (host, creds) = entry
                    .split_once('=')
                    .context("REGISTRY_AUTH entries look like host=user:password")?;
                let (u, p) = creds
                    .split_once(':')
                    .context("REGISTRY_AUTH entries look like host=user:password")?;
                registry_auth.insert(
                    crate::registry::api_host(host.trim()),
                    (u.to_string(), p.to_string()),
                );
            }
        }

        let basic_auth = match secret("UI_BASIC_AUTH")? {
            Some(v) => {
                let (u, p) = parse_basic_auth(&v)?;
                Some((u.to_string(), p.to_string()))
            }
            None => None,
        };
        // Fail closed: the API can redeploy every stack, it must not be open by accident.
        let auth_disabled = bool_var("UI_AUTH_DISABLED", false);
        if basic_auth.is_none() && !auth_disabled {
            bail!(
                "UI_BASIC_AUTH (or UI_BASIC_AUTH_FILE) is required; set UI_AUTH_DISABLED=true only when an authenticating proxy protects Drydock"
            );
        }
        let allowed_hosts = var("ALLOWED_HOSTS")
            .map(|v| {
                v.split(',')
                    .map(|h| h.trim().to_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let secs = |name: &str, default: u64| -> Result<u64> {
            var(name)
                .map(|v| v.parse::<u64>().with_context(|| format!("{name} must be a number")))
                .unwrap_or(Ok(default))
        };
        let scan = secs("SCAN_INTERVAL_SECS", 6 * 3600)?;

        Ok(Self {
            listen: var_or("LISTEN", "0.0.0.0:8080"),
            portainer_url: portainer_url.trim_end_matches('/').to_string(),
            portainer_api_key,
            portainer_insecure: bool_var("PORTAINER_INSECURE", false),
            portainer_ca_file: var("PORTAINER_CA_FILE"),
            pangolin,
            url_label: var_or("URL_LABEL", "url"),
            resource_label: var_or("RESOURCE_LABEL", "drydock.pangolin.resource"),
            ignore_label: var_or("IGNORE_LABEL", "drydock.ignore"),
            enable_label: var_or("ENABLE_LABEL", "drydock.enable"),
            require_enable_label: bool_var("REQUIRE_ENABLE_LABEL", false),
            health_timeout: Duration::from_secs(secs("HEALTH_TIMEOUT_SECS", 300)?),
            scan_interval: (scan > 0).then(|| Duration::from_secs(scan)),
            keep_maintenance_on_failure: bool_var("KEEP_MAINTENANCE_ON_FAILURE", true),
            registry_auth,
            registry_realms: var("REGISTRY_AUTH_REALMS")
                .map(|v| {
                    v.split(',')
                        .map(|h| h.trim().to_lowercase())
                        .filter(|h| !h.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            registry_allowlist: var("REGISTRY_ALLOWLIST")
                .map(|v| {
                    v.split(',')
                        .map(|h| crate::registry::api_host(&h.trim().to_lowercase()))
                        .filter(|h| !h.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            basic_auth,
            auth_disabled,
            allowed_hosts,
            maintenance_title: var_or("MAINTENANCE_TITLE", "Mise à jour en cours"),
            maintenance_message: var_or(
                "MAINTENANCE_MESSAGE",
                "Le service est en cours de mise à jour, il revient dans quelques minutes.",
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_strength() {
        assert!(parse_basic_auth("admin:").is_err());
        assert!(parse_basic_auth(":correct-horse-battery").is_err());
        assert!(parse_basic_auth("admin:short").is_err());
        assert!(parse_basic_auth("admin").is_err());
        assert_eq!(
            parse_basic_auth("admin:correct:horse:battery").unwrap(),
            ("admin", "correct:horse:battery")
        );
    }

    #[test]
    fn debug_hides_secrets() {
        let cfg = Config {
            listen: "0.0.0.0:8080".into(),
            portainer_url: "https://p".into(),
            portainer_api_key: "PTR_SECRET".into(),
            portainer_insecure: false,
            portainer_ca_file: None,
            pangolin: Some(PangolinConfig { url: "https://g".into(), api_key: "PGL_SECRET".into(), org_id: None }),
            url_label: "url".into(),
            resource_label: "r".into(),
            ignore_label: "i".into(),
            enable_label: "e".into(),
            require_enable_label: false,
            health_timeout: Duration::from_secs(1),
            scan_interval: None,
            keep_maintenance_on_failure: true,
            registry_auth: HashMap::from([("ghcr.io".into(), ("u".into(), "REG_SECRET".into()))]),
            registry_realms: vec![],
            registry_allowlist: vec![],
            basic_auth: Some(("admin".into(), "UI_SECRET".into())),
            auth_disabled: false,
            allowed_hosts: vec![],
            maintenance_title: String::new(),
            maintenance_message: String::new(),
        };
        let out = format!("{cfg:?}");
        for secret in ["PTR_SECRET", "PGL_SECRET", "REG_SECRET", "UI_SECRET"] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
    }
}
