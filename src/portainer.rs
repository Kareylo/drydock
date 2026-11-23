//! Portainer API client (API key auth, Docker proxy).

use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

pub const STACK_TYPE_COMPOSE: i64 = 2;

#[derive(Debug, Clone, Deserialize)]
pub struct Stack {
    #[serde(rename = "Id")]
    pub id: i64,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type")]
    pub kind: i64,
    #[serde(rename = "EndpointId")]
    pub endpoint_id: i64,
    /// 1 = active, 2 = inactive.
    #[serde(rename = "Status")]
    pub status: i64,
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<EnvPair>>,
    #[serde(rename = "GitConfig", default)]
    pub git_config: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPair {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Container {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Names", default)]
    pub names: Vec<String>,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "ImageID")]
    pub image_id: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Labels", default)]
    pub labels: HashMap<String, String>,
}

impl Container {
    pub fn name(&self) -> String {
        self.names
            .first()
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_else(|| self.id.chars().take(12).collect())
    }

    pub fn service(&self) -> Option<&str> {
        self.labels.get("com.docker.compose.service").map(String::as_str)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImageInspect {
    #[serde(rename = "RepoDigests", default)]
    pub repo_digests: Option<Vec<String>>,
    #[serde(rename = "Architecture", default)]
    pub architecture: String,
    #[serde(rename = "Os", default)]
    pub os: String,
    #[serde(rename = "Variant", default)]
    pub variant: Option<String>,
    #[serde(rename = "Config", default)]
    pub config: Option<ImageInspectConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImageInspectConfig {
    #[serde(rename = "Labels", default)]
    pub labels: Option<HashMap<String, String>>,
}

/// Explains the usual certificate errors with a self-signed Portainer.
fn tls_hint(e: reqwest::Error) -> anyhow::Error {
    let e = anyhow::Error::from(e);
    let msg = format!("{e:#}");
    let hint = if msg.contains("CaUsedAsEndEntity") {
        "le certificat de Portainer est marqué CA : fournir dans PORTAINER_CA_FILE l'autorité qui l'a signé, ou un certificat serveur sans CA:TRUE"
    } else if msg.contains("UnknownIssuer") || msg.contains("invalid peer certificate") {
        "certificat de Portainer non reconnu : définir PORTAINER_CA_FILE (certificat PEM de Portainer ou de son autorité)"
    } else {
        return e;
    };
    e.context(hint)
}

/// Redirects are not followed (API key protection): explain the 3xx instead.
fn check_redirect(resp: &reqwest::Response) -> Result<()> {
    if resp.status().is_redirection() {
        let to = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("?");
        anyhow::bail!(
            "Portainer HTTP {} vers {to} : redirection refusée, PORTAINER_URL doit être l'URL finale",
            resp.status()
        );
    }
    Ok(())
}

/// Longest progress line kept while reading a pull stream.
const PULL_LINE_MAX: usize = 64 << 10;

/// Reads a Docker pull progress stream line by line (never buffered whole: a
/// large image produces megabytes of progress) and fails on its first `error`.
async fn pull_stream_error(mut resp: reqwest::Response) -> Result<()> {
    let check = |line: &[u8]| -> Result<()> {
        let v: Option<Value> = serde_json::from_slice(line).ok();
        match v.as_ref().and_then(|v| v.get("error")).and_then(Value::as_str) {
            Some(err) => anyhow::bail!("{err}"),
            None => Ok(()),
        }
    };
    let mut line = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        let mut rest = &chunk[..];
        while let Some(i) = rest.iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&rest[..i]);
            check(&line)?;
            line.clear();
            rest = &rest[i + 1..];
        }
        line.extend_from_slice(rest);
        if line.len() > PULL_LINE_MAX {
            anyhow::bail!("pull stream line longer than {PULL_LINE_MAX} bytes");
        }
    }
    check(&line)
}

pub struct Portainer {
    http: Client,
    /// Separate client without timeout for long deployments.
    deploy_http: Client,
    base: String,
    key: String,
}

impl Portainer {
    pub fn new(base: &str, key: &str, insecure: bool, ca_file: Option<&str>) -> Result<Self> {
        // Self-signed Portainer: trust its certificate explicitly instead of disabling checks.
        let ca = match ca_file {
            Some(path) => {
                let pem = std::fs::read(path).with_context(|| format!("reading PORTAINER_CA_FILE {path}"))?;
                Some(reqwest::Certificate::from_pem(&pem).context("PORTAINER_CA_FILE is not a PEM certificate")?)
            }
            None => None,
        };
        let build = |timeout: Option<Duration>| {
            // No redirects: X-API-Key is a custom header, reqwest would replay it to any host.
            let mut b = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .danger_accept_invalid_certs(insecure);
            if let Some(c) = &ca {
                b = b.add_root_certificate(c.clone());
            }
            if let Some(t) = timeout {
                b = b.timeout(t);
            }
            b.build()
        };
        Ok(Self {
            http: build(Some(Duration::from_secs(30)))?,
            deploy_http: build(Some(Duration::from_secs(30 * 60)))?,
            base: base.to_string(),
            key: key.to_string(),
        })
    }

    fn get(&self, path: &str) -> RequestBuilder {
        self.http
            .get(format!("{}/api{}", self.base, path))
            .header("X-API-Key", &self.key)
    }

    async fn json<T: for<'de> Deserialize<'de>>(req: RequestBuilder) -> Result<T> {
        let resp = req.send().await.map_err(tls_hint)?;
        let status = resp.status();
        check_redirect(&resp)?;
        let body = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("Portainer HTTP {status}: {}", body.chars().take(400).collect::<String>());
        }
        serde_json::from_str(&body).with_context(|| "decoding Portainer response".to_string())
    }

    pub async fn stacks(&self) -> Result<Vec<Stack>> {
        Self::json(self.get("/stacks")).await
    }

    pub async fn stack(&self, id: i64) -> Result<Stack> {
        Self::json(self.get(&format!("/stacks/{id}"))).await
    }

    pub async fn stack_file(&self, id: i64) -> Result<String> {
        let v: Value = Self::json(self.get(&format!("/stacks/{id}/file"))).await?;
        v.get("StackFileContent")
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("no StackFileContent")
    }

    pub async fn project_containers(&self, endpoint: i64, project: &str) -> Result<Vec<Container>> {
        let filters = json!({ "label": [format!("com.docker.compose.project={project}")] });
        Self::json(
            self.get(&format!("/endpoints/{endpoint}/docker/containers/json"))
                .query(&[("all", "1"), ("filters", &filters.to_string())]),
        )
        .await
    }

    pub async fn inspect_image(&self, endpoint: i64, image_id: &str) -> Result<ImageInspect> {
        Self::json(self.get(&format!("/endpoints/{endpoint}/docker/images/{image_id}/json"))).await
    }

    /// Digest the tag currently points to, as seen by the environment's Docker
    /// daemon (`GET /distribution/{name}/json`). Used when Drydock cannot reach
    /// the registry itself: plain-HTTP or self-signed registries the daemon trusts.
    /// Portainer does not add its registry credentials here, so private images
    /// still need REGISTRY_AUTH.
    pub async fn distribution_digest(&self, endpoint: i64, image: &str) -> Result<String> {
        let name = image.split('@').next().unwrap_or(image);
        let v: Value = Self::json(self.get(&format!("/endpoints/{endpoint}/docker/distribution/{name}/json"))).await?;
        v.pointer("/Descriptor/digest")
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("no Descriptor.digest in the distribution response")
    }

    /// Pull one image on the environment (Portainer adds the credentials of the
    /// registries it knows). Docker reports pull errors inside a 200 stream.
    pub async fn pull_image(&self, endpoint: i64, image: &str) -> Result<()> {
        let image = image.split('@').next().unwrap_or(image);
        let resp = self
            .deploy_http
            .post(format!("{}/api/endpoints/{endpoint}/docker/images/create", self.base))
            .query(&[("fromImage", image)])
            .header("X-API-Key", &self.key)
            .send()
            .await
            .map_err(tls_hint)?;
        let status = resp.status();
        check_redirect(&resp)?;
        if !status.is_success() {
            let body = resp.text().await?;
            anyhow::bail!("pull {image}: HTTP {status}: {}", body.chars().take(400).collect::<String>());
        }
        pull_stream_error(resp).await.map_err(|e| anyhow::anyhow!("pull {image}: {e:#}"))
    }

    /// Redeploy a compose stack with a (possibly modified) file. Images are not
    /// re-pulled: only containers whose image changed locally are recreated.
    pub async fn update_stack(&self, stack: &Stack, file: &str) -> Result<()> {
        let body = json!({
            "stackFileContent": file,
            "env": stack.env.clone().unwrap_or_default(),
            "prune": false,
            "pullImage": false,
        });
        let req = self
            .deploy_http
            .put(format!("{}/api/stacks/{}", self.base, stack.id))
            .query(&[("endpointId", stack.endpoint_id)])
            .header("X-API-Key", &self.key)
            .json(&body);
        let _: Value = Self::json(req).await?;
        Ok(())
    }

    /// Redeploy a Git-backed stack from its configured ref (images pre-pulled).
    pub async fn redeploy_git_stack(&self, stack: &Stack) -> Result<()> {
        let req = self
            .deploy_http
            .put(format!("{}/api/stacks/{}/git/redeploy", self.base, stack.id))
            .query(&[("endpointId", stack.endpoint_id)])
            .header("X-API-Key", &self.key)
            .json(&json!({ "pullImage": false, "prune": false }));
        let _: Value = Self::json(req).await?;
        Ok(())
    }

    pub async fn ping(&self) -> Result<()> {
        let _: Value = Self::json(self.get("/system/version")).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local HTTP server streaming `body` in small chunks, without Content-Length.
    async fn stream(body: Vec<u8>) -> reqwest::Response {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Some(mut c) = l.incoming().flatten().next() {
                let mut b = [0u8; 1024];
                let _ = c.read(&mut b);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                for part in body.chunks(7) {
                    let _ = c.write_all(format!("{:x}\r\n", part.len()).as_bytes());
                    let _ = c.write_all(part);
                    let _ = c.write_all(b"\r\n");
                }
                let _ = c.write_all(b"0\r\n\r\n");
            }
        });
        let _ = rustls::crypto::ring::default_provider().install_default();
        Client::new().get(format!("http://{addr}/")).send().await.unwrap()
    }

    #[tokio::test]
    async fn pull_stream_errors() {
        let ok = b"{\"status\":\"Pulling\"}\n{\"status\":\"Done\"}\n".to_vec();
        assert!(pull_stream_error(stream(ok).await).await.is_ok());
        // Error split across chunks, on the last line without a newline.
        let err = b"{\"status\":\"Pulling\"}\n{\"error\":\"manifest unknown\"}".to_vec();
        let e = pull_stream_error(stream(err).await).await.unwrap_err();
        assert_eq!(e.to_string(), "manifest unknown");
        // Many progress lines are fine (never buffered whole).
        let many = b"{\"status\":\"Downloading\"}\n".repeat(100_000);
        assert!(pull_stream_error(stream(many).await).await.is_ok());
        // One endless line is refused.
        let long = vec![b'a'; PULL_LINE_MAX + 100];
        assert!(pull_stream_error(stream(long).await).await.is_err());
    }
}
