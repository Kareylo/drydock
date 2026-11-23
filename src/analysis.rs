//! Per-stack update analysis.

use crate::compose;
use crate::pangolin::Resource;
use crate::portainer::{Container, Stack, STACK_TYPE_COMPOSE};
use crate::registry::{ImageRef, PlatformSpec};
use crate::version::{classify_labels, same_major_candidate, Severity, TagVersion};
use crate::AppState;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

const VERSION_LABELS: &[&str] = &["org.opencontainers.image.version", "org.label-schema.version"];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    /// Same tag, new image behind it.
    Digest,
    /// Newer tag available.
    Tag,
}

#[derive(Debug, Clone, Serialize)]
pub struct Update {
    pub services: Vec<String>,
    /// Image as written in the compose file (or container).
    pub image: String,
    pub kind: UpdateKind,
    pub current_tag: String,
    pub target_tag: String,
    pub current_version: Option<String>,
    pub new_version: Option<String>,
    pub severity: Severity,
    pub breaking: bool,
    /// Applied by the "Update stack" button.
    pub auto: bool,
    /// Updates disabled by label: shown, never applied.
    pub disabled: bool,
    /// Image pulled before redeploying (only the images that must change are pulled).
    pub pull_ref: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StackStatus {
    UpToDate,
    Updatable,
    /// Pulling would bring a major version (floating tag moved): needs confirmation.
    Breaking,
    /// Updates exist but must be applied by hand (Git stack, image set by variable).
    Manual,
    /// Updates exist but their containers are disabled by label.
    Disabled,
    /// The stack Drydock itself runs in: never updated by Drydock.
    SelfStack,
    Inactive,
    Unsupported,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceInfo {
    pub service: String,
    pub container: String,
    pub image: String,
    pub state: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackReport {
    pub id: i64,
    pub name: String,
    pub endpoint_id: i64,
    pub git: bool,
    pub status: StackStatus,
    pub services: Vec<ServiceInfo>,
    pub updates: Vec<Update>,
    pub resources: Vec<Resource>,
    /// Linked resources that could not be read: updating would skip their maintenance.
    pub pangolin_errors: Vec<String>,
    pub errors: Vec<String>,
    pub can_update: bool,
    pub needs_force: bool,
    /// Drydock runs in this stack: redeploying it would kill the job mid-way.
    pub is_self: bool,
    pub checked_at: u64,
}

/// `<enable_label>=true|false`; without the label, enabled unless opt-in mode is on.
pub fn update_enabled(cfg: &crate::config::Config, c: &Container) -> bool {
    match c.labels.get(&cfg.enable_label).map(|v| v.trim().to_lowercase()) {
        Some(v) if matches!(v.as_str(), "false" | "0" | "no" | "off") => false,
        Some(v) if matches!(v.as_str(), "true" | "1" | "yes" | "on") => true,
        _ => !cfg.require_enable_label,
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn version_label(labels: &HashMap<String, String>) -> Option<String> {
    VERSION_LABELS
        .iter()
        .find_map(|k| labels.get(*k))
        .filter(|v| !v.is_empty())
        .cloned()
}

/// Pangolin resources linked to a stack: explicit ids label, or `url` label host.
pub async fn linked_resources(
    state: &AppState,
    containers: &[Container],
    all: &[Resource],
) -> (Vec<Resource>, Vec<String>) {
    let Some(pangolin) = &state.pangolin else {
        return (vec![], vec![]);
    };
    let mut ids = BTreeSet::new();
    let mut errors = vec![];
    for c in containers {
        if let Some(v) = c.labels.get(&state.cfg.resource_label) {
            ids.extend(v.split(',').filter_map(|s| s.trim().parse::<i64>().ok()));
        }
        if let Some(url) = c.labels.get(&state.cfg.url_label) {
            let host = url
                .split("://")
                .last()
                .unwrap_or(url)
                .split(['/', ':'])
                .next()
                .unwrap_or_default()
                .to_lowercase();
            ids.extend(
                all.iter()
                    .filter(|r| r.full_domain.as_deref() == Some(host.as_str()))
                    .map(|r| r.id),
            );
        }
    }
    // With an org configured, a label may only name resources of that org: a
    // stack author must not be able to put someone else's resource in maintenance.
    let org_scoped = state.cfg.pangolin.as_ref().is_some_and(|c| c.org_id.is_some());
    let mut out = vec![];
    for id in ids {
        match all.iter().find(|r| r.id == id) {
            Some(r) => out.push(r.clone()),
            None if org_scoped => errors.push(format!(
                "Ressource Pangolin {id} hors de l'organisation configurée (PANGOLIN_ORG_ID), ignorée"
            )),
            None => match pangolin.resource(id).await {
                Ok(r) => out.push(r),
                Err(e) => errors.push(format!("Ressource Pangolin {id} illisible : {e:#}")),
            },
        }
    }
    (out, errors)
}

/// Analyse one image (shared by one or more services).
async fn analyse_image(
    state: &AppState,
    stack: &Stack,
    services: Vec<String>,
    container: &Container,
    compose_image: Option<&str>,
) -> Result<Vec<Update>> {
    let shown = compose_image.unwrap_or(&container.image).to_string();
    let img = ImageRef::parse(&container.image)?;
    let local = state
        .portainer
        .inspect_image(stack.endpoint_id, &container.image_id)
        .await
        .context("image inspect")?;
    let local_labels = local.config.as_ref().and_then(|c| c.labels.clone()).unwrap_or_default();
    let local_version = version_label(&local_labels);
    let platform = PlatformSpec {
        os: if local.os.is_empty() { "linux" } else { &local.os },
        arch: if local.architecture.is_empty() { "amd64" } else { &local.architecture },
        variant: local.variant.as_deref(),
    };

    let local_digest = local.repo_digests.unwrap_or_default().into_iter().find_map(|d| {
        let (name, digest) = d.split_once('@')?;
        ImageRef::parse(name).ok().filter(|r| r.same_repo(&img)).map(|_| digest.to_string())
    });
    let Some(local_digest) = local_digest else {
        // Built locally or loaded without registry metadata: nothing to compare.
        return Ok(vec![]);
    };

    let rewritable = compose_image.is_some_and(|i| !i.contains('$')) && stack.git_config.is_none();
    let tag_shape = TagVersion::parse(&img.tag);
    let mut updates = vec![];

    // 1. Newer tags in the same major (pinned / partially pinned version tags).
    //    Like diun, other majors are never proposed.
    // When Drydock cannot reach the registry (plain HTTP, self-signed TLS…),
    // the environment's Docker daemon answers for the digest instead. It has no
    // tag-list API, so newer tags cannot be looked up that way.
    let tags = if tag_shape.is_some() {
        match state.registry.list_tags(&img).await {
            Ok(t) => Some(t),
            Err(e) if crate::registry::is_unreachable(&e) => None,
            Err(e) => return Err(e.context("listing tags")),
        }
    } else {
        None
    };
    if let Some(tags) = tags
        && let Some((target, severity)) = same_major_candidate(&img.tag, &tags)
    {
        let pull_ref = compose_image
            .filter(|_| rewritable)
            .and_then(|i| compose::with_tag(i, &target).ok());
        updates.push(Update {
            services: services.clone(),
            image: shown.clone(),
            kind: UpdateKind::Tag,
            current_tag: img.tag.clone(),
            target_tag: target,
            current_version: local_version.clone(),
            new_version: None,
            severity,
            breaking: false,
            auto: rewritable,
            disabled: false,
            pull_ref,
            note: (!rewritable).then(|| {
                if stack.git_config.is_some() {
                    "Stack Git : modifier le tag dans le dépôt".to_string()
                } else {
                    "Image définie par variable : tag non modifiable".to_string()
                }
            }),
        });
    }

    // 2. Same tag, new digest (skip if a same-major tag bump already covers it).
    let has_safe_tag_bump = updates.iter().any(|u| u.auto);
    if !has_safe_tag_bump {
        let (remote_digest, via_daemon) = match state.registry.tag_digest(&img).await {
            Ok(d) => (d, false),
            Err(e) if crate::registry::is_unreachable(&e) => {
                tracing::debug!("{shown}: registre injoignable ({e:#}), digest demandé au Docker du serveur");
                let d = state
                    .portainer
                    .distribution_digest(stack.endpoint_id, &container.image)
                    .await
                    .with_context(|| format!("registre injoignable ({e:#}), et le Docker du serveur n'a pas répondu"))?;
                (d, true)
            }
            Err(e) => return Err(e.context("remote digest")),
        };
        if remote_digest != local_digest {
            let new_version = if via_daemon {
                None
            } else {
                match state.registry.labels(&img, &remote_digest, &platform).await {
                    Ok(l) => version_label(&l),
                    Err(e) => {
                        tracing::debug!("labels for {shown}: {e:#}");
                        None
                    }
                }
            };
            let mut severity = classify_labels(local_version.as_deref(), new_version.as_deref());
            if tag_shape.is_some() && matches!(severity, Severity::Major | Severity::Unknown) {
                // The tag pins the major: a moved version tag is a rebuild or a minor/patch.
                severity = Severity::Patch;
            }
            let note = match severity {
                _ if via_daemon => Some(
                    "Registre injoignable par Drydock : nouvelle image vue par le Docker du serveur, version non comparée"
                        .to_string(),
                ),
                Severity::Unknown => Some("Version non publiée par l'image : impact inconnu".to_string()),
                Severity::Major => Some("Le tag flottant pointe vers une nouvelle version majeure".to_string()),
                _ => None,
            };
            updates.push(Update {
                services,
                image: shown,
                kind: UpdateKind::Digest,
                current_tag: img.tag.clone(),
                target_tag: img.tag.clone(),
                current_version: local_version,
                new_version,
                severity,
                breaking: severity.is_breaking(),
                auto: true,
                disabled: false,
                pull_ref: Some(container.image.clone()),
                note,
            });
        }
    }
    Ok(updates)
}

pub async fn analyse_stack(state: Arc<AppState>, stack: Stack, resources: Arc<Vec<Resource>>) -> StackReport {
    let mut report = StackReport {
        id: stack.id,
        name: stack.name.clone(),
        endpoint_id: stack.endpoint_id,
        git: stack.git_config.is_some(),
        status: StackStatus::UpToDate,
        services: vec![],
        updates: vec![],
        resources: vec![],
        pangolin_errors: vec![],
        errors: vec![],
        can_update: false,
        needs_force: false,
        is_self: false,
        checked_at: now(),
    };
    if stack.kind != STACK_TYPE_COMPOSE {
        report.status = StackStatus::Unsupported;
        report.errors.push("Seules les stacks Docker Compose sont gérées".into());
        return report;
    }

    let containers = match state.portainer.project_containers(stack.endpoint_id, &stack.name).await {
        Ok(c) => c,
        Err(e) => {
            report.status = StackStatus::Error;
            report.errors.push(format!("{e:#}"));
            return report;
        }
    };
    if containers.is_empty() {
        report.status = StackStatus::Inactive;
        return report;
    }

    let compose_images = match state.portainer.stack_file(stack.id).await.and_then(|f| compose::service_images(&f)) {
        Ok(m) => m,
        Err(e) => {
            report.errors.push(format!("Lecture du compose : {e:#}"));
            HashMap::new()
        }
    };

    let (res, res_errors) = linked_resources(&state, &containers, &resources).await;
    report.resources = res;
    report.pangolin_errors = res_errors;

    // Group services by image so shared images are analysed once. An image is
    // updatable only if every service using it is enabled: pulling it changes them all.
    let mut by_image: BTreeMap<String, (Vec<String>, &Container, bool)> = BTreeMap::new();
    for c in &containers {
        let service = c.service().unwrap_or("?").to_string();
        report.services.push(ServiceInfo {
            service: service.clone(),
            container: c.name(),
            image: c.image.clone(),
            state: c.state.clone(),
            status: c.status.clone(),
        });
        let ignored = c
            .labels
            .get(&state.cfg.ignore_label)
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if ignored {
            continue;
        }
        let enabled = update_enabled(&state.cfg, c);
        let entry = by_image.entry(c.image.clone()).or_insert_with(|| (vec![], c, true));
        entry.2 &= enabled;
        if !entry.0.contains(&service) {
            entry.0.push(service);
        }
    }
    report.services.sort_by(|a, b| a.service.cmp(&b.service));

    for (_, (services, container, enabled)) in by_image {
        let compose_image = services
            .iter()
            .find_map(|s| compose_images.get(s))
            .map(String::as_str);
        match analyse_image(&state, &stack, services.clone(), container, compose_image).await {
            Ok(mut u) => {
                if !enabled {
                    let why = if services.len() > 1 {
                        "Mises à jour désactivées par label (image partagée : un des services est désactivé)"
                    } else {
                        "Mises à jour désactivées par label"
                    };
                    for up in &mut u {
                        up.auto = false;
                        up.disabled = true;
                        up.pull_ref = None;
                        up.note = Some(why.to_string());
                    }
                }
                report.updates.extend(u)
            }
            Err(e) => report
                .errors
                .push(format!("{} ({}) : {e:#}", container.image, services.join(", "))),
        }
    }

    // Drydock's own stack: redeploying it would stop Drydock mid-job (maintenance
    // left on, job lost). Updates stay visible but are never applied.
    report.is_self = state
        .self_id
        .as_ref()
        .is_some_and(|id| containers.iter().any(|c| id.matches(&c.id)));
    if report.is_self {
        for up in &mut report.updates {
            up.auto = false;
            up.disabled = true;
            up.pull_ref = None;
            up.note = Some("Stack de Drydock : à mettre à jour manuellement".into());
        }
    }

    let auto: Vec<&Update> = report.updates.iter().filter(|u| u.auto).collect();
    report.needs_force = auto.iter().any(|u| u.breaking);
    report.can_update = !auto.is_empty();
    report.status = if report.is_self {
        StackStatus::SelfStack
    } else if report.needs_force {
        StackStatus::Breaking
    } else if report.can_update {
        StackStatus::Updatable
    } else if report.updates.iter().any(|u| !u.auto && !u.disabled) {
        StackStatus::Manual
    } else if report.updates.iter().any(|u| u.disabled) {
        StackStatus::Disabled
    } else if !report.errors.is_empty() && report.updates.is_empty() {
        StackStatus::Error
    } else {
        StackStatus::UpToDate
    };
    report
}
