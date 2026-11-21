//! Compose file helpers: read service images, rewrite image tags in place.

use anyhow::{bail, Context, Result};
use regex::Regex;
use std::collections::HashMap;

/// `service -> image` as written in the compose file.
pub fn service_images(file: &str) -> Result<HashMap<String, String>> {
    let doc: yaml_serde::Value = yaml_serde::from_str(file).context("invalid compose YAML")?;
    let mut out = HashMap::new();
    if let Some(services) = doc.get("services").and_then(|s| s.as_mapping()) {
        for (name, svc) in services {
            if let (Some(name), Some(image)) = (
                name.as_str(),
                svc.get("image").and_then(|i| i.as_str()),
            ) {
                out.insert(name.to_string(), image.to_string());
            }
        }
    }
    Ok(out)
}

/// Replace every `image: <old>` line by `image: <new>`, keeping quotes,
/// indentation and comments. Only the YAML scalar is touched.
pub fn replace_image(file: &str, old: &str, new: &str) -> Result<String> {
    let re = Regex::new(&format!(
        r#"(?m)^(\s*-?\s*image:\s*)(["']?){}(["']?)(\s*(?:#.*)?)$"#,
        regex::escape(old)
    ))?;
    if !re.is_match(file) {
        bail!("image `{old}` not found in compose file");
    }
    Ok(re
        .replace_all(file, |c: &regex::Captures| {
            format!("{}{}{}{}{}", &c[1], &c[2], new, &c[3], &c[4])
        })
        .into_owned())
}

/// `repo:tag` → `repo:new_tag` (keeps registry and repo exactly as written).
pub fn with_tag(image: &str, new_tag: &str) -> Result<String> {
    let name = image.split('@').next().unwrap_or(image);
    let base = match name.rsplit_once(':') {
        Some((b, t)) if !t.contains('/') => b,
        _ => name,
    };
    if base.contains('$') {
        bail!("image uses a variable, cannot rewrite its tag");
    }
    Ok(format!("{base}:{new_tag}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "services:\n  db:\n    image: \"postgres:18-alpine\"  # pinned\n  web:\n    image: docker.io/gotenberg/gotenberg:8.34\n  other:\n    image: docker.io/gotenberg/gotenberg:8.340\n";

    #[test]
    fn reads_images() {
        let m = service_images(FILE).unwrap();
        assert_eq!(m["db"], "postgres:18-alpine");
        assert_eq!(m["web"], "docker.io/gotenberg/gotenberg:8.34");
    }

    #[test]
    fn rewrites_exact_image_only() {
        let out = replace_image(FILE, "docker.io/gotenberg/gotenberg:8.34", "docker.io/gotenberg/gotenberg:8.36").unwrap();
        assert!(out.contains("image: docker.io/gotenberg/gotenberg:8.36\n"));
        assert!(out.contains("gotenberg:8.340"));
        let out = replace_image(FILE, "postgres:18-alpine", "postgres:18.2-alpine").unwrap();
        assert!(out.contains("image: \"postgres:18.2-alpine\"  # pinned"));
    }

    #[test]
    fn tag_swap() {
        assert_eq!(with_tag("localhost:5000/app:1.2", "1.3").unwrap(), "localhost:5000/app:1.3");
        assert_eq!(with_tag("redis", "7").unwrap(), "redis:7");
        assert!(with_tag("${IMG}:1", "2").is_err());
    }
}
