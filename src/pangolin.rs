//! Pangolin integration API client (maintenance mode on resources).

use crate::config::PangolinConfig;
use anyhow::{bail, Context, Result};
use reqwest::{Client, RequestBuilder};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct Resource {
    pub id: i64,
    pub name: String,
    pub full_domain: Option<String>,
    pub maintenance: bool,
}

impl Resource {
    fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            id: v.get("resourceId")?.as_i64()?,
            name: v.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
            full_domain: v
                .get("fullDomain")
                .and_then(Value::as_str)
                .map(|d| d.to_lowercase()),
            maintenance: v
                .get("maintenanceModeEnabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }
}

pub struct Pangolin {
    http: Client,
    cfg: PangolinConfig,
}

impl Pangolin {
    pub fn new(cfg: PangolinConfig) -> Result<Self> {
        Ok(Self {
            http: Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            cfg,
        })
    }

    async fn call(&self, req: RequestBuilder) -> Result<Value> {
        let resp = req.bearer_auth(&self.cfg.api_key).send().await?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = body.get("message").and_then(Value::as_str).unwrap_or("");
            let hint = match status.as_u16() {
                300..=399 => " (redirection refusée : PANGOLIN_URL doit être l'URL finale)",
                401 => " (PANGOLIN_API_KEY refusée)",
                403 => " (la clé n'a pas les droits nécessaires, ou n'appartient pas à cette organisation)",
                404 => " (introuvable : vérifier l'identifiant, et que PANGOLIN_URL se termine par /integration/v1)",
                _ => "",
            };
            bail!("Pangolin HTTP {status}: {msg}{hint}");
        }
        Ok(body.get("data").cloned().unwrap_or(Value::Null))
    }

    /// Retries: Pangolin may itself be restarting (when updating its own stack).
    async fn call_retry(&self, make: impl Fn() -> RequestBuilder) -> Result<Value> {
        let mut last = None;
        for attempt in 0..10 {
            match self.call(make()).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    tracing::warn!("Pangolin call failed (attempt {}): {e:#}", attempt + 1);
                    last = Some(e);
                    tokio::time::sleep(Duration::from_secs(3 * (attempt + 1))).await;
                }
            }
        }
        Err(last.unwrap())
    }

    pub async fn resource(&self, id: i64) -> Result<Resource> {
        let url = format!("{}/resource/{id}", self.cfg.url);
        let data = self.call(self.http.get(&url)).await?;
        Resource::from_json(&data).context("unexpected resource payload")
    }

    /// All resources of the configured org (used to match on `fullDomain`).
    pub async fn resources(&self) -> Result<Vec<Resource>> {
        let Some(org) = &self.cfg.org_id else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        let page_size = 100;
        for page in 1..=50 {
            let req = self
                .http
                .get(format!("{}/org/{org}/resources", self.cfg.url))
                .query(&[("page", page), ("pageSize", page_size)]);
            let data = self
                .call(req)
                .await
                .with_context(|| format!("liste des ressources de l'organisation « {org} » (PANGOLIN_ORG_ID)"))?;
            let items = data
                .get("resources")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let n = items.len();
            out.extend(items.iter().filter_map(Resource::from_json));
            if n < page_size {
                break;
            }
        }
        Ok(out)
    }

    pub async fn set_maintenance(&self, id: i64, on: bool, title: &str, message: &str) -> Result<()> {
        let url = format!("{}/resource/{id}", self.cfg.url);
        let body = if on {
            json!({
                "maintenanceModeEnabled": true,
                "maintenanceModeType": "forced",
                "maintenanceTitle": title,
                "maintenanceMessage": message,
            })
        } else {
            json!({ "maintenanceModeEnabled": false })
        };
        self.call_retry(|| self.http.post(&url).json(&body)).await?;
        Ok(())
    }
}
