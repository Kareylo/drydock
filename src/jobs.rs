//! Update workflow: maintenance on → redeploy → wait healthy → maintenance off.

use crate::analysis::{analyse_stack, now, StackReport, UpdateKind};
use crate::compose;
use crate::portainer::Container;
use crate::AppState;
use anyhow::{bail, Result};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Running,
    Success,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub at: u64,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: u64,
    pub stack_id: i64,
    pub stack_name: String,
    pub status: JobStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    /// Who started it (`-` when the UI has no authentication).
    pub requested_by: String,
    /// A major update was confirmed.
    pub forced: bool,
    pub log: Vec<LogLine>,
}

struct Ctx {
    state: Arc<AppState>,
    job_id: u64,
}

impl Ctx {
    async fn log(&self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::info!(job = self.job_id, "{msg}");
        if let Some(j) = self.state.jobs.lock().await.get_mut(&self.job_id) {
            j.log.push(LogLine { at: now(), msg });
        }
    }
}

/// Health of a compose project after a redeploy.
enum Health {
    Ready,
    Waiting(String),
    Failed(String),
}

fn container_health(containers: &[Container]) -> Health {
    if containers.is_empty() {
        return Health::Waiting("aucun conteneur".into());
    }
    let mut waiting = vec![];
    for c in containers {
        let status = c.status.to_lowercase();
        match c.state.as_str() {
            "running" if status.contains("(unhealthy)") => {
                return Health::Failed(format!("{} est unhealthy", c.name()))
            }
            "running" if status.contains("health: starting") => waiting.push(c.name()),
            "running" => {}
            // One-shot init containers end with exit code 0.
            "exited" if status.starts_with("exited (0)") => {}
            "exited" | "dead" => return Health::Failed(format!("{} : {}", c.name(), c.status)),
            _ => waiting.push(format!("{} ({})", c.name(), c.state)),
        }
    }
    if waiting.is_empty() {
        Health::Ready
    } else {
        Health::Waiting(waiting.join(", "))
    }
}

async fn wait_healthy(ctx: &Ctx, report: &StackReport) -> Result<()> {
    let deadline = Instant::now() + ctx.state.cfg.health_timeout;
    let mut ready_streak = 0;
    let mut last_msg = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let containers = ctx
            .state
            .portainer
            .project_containers(report.endpoint_id, &report.name)
            .await?;
        match container_health(&containers) {
            Health::Ready => {
                ready_streak += 1;
                // Two consecutive good polls: avoids catching a crash-looping container mid-cycle.
                if ready_streak >= 2 {
                    return Ok(());
                }
            }
            Health::Waiting(w) => {
                ready_streak = 0;
                let msg = format!("En attente : {w}");
                if msg != last_msg {
                    ctx.log(&msg).await;
                    last_msg = msg;
                }
            }
            Health::Failed(f) => {
                // A container can briefly be unhealthy/restarting during start: keep
                // waiting until the deadline, but report it.
                ready_streak = 0;
                let msg = format!("Problème : {f}");
                if msg != last_msg {
                    ctx.log(&msg).await;
                    last_msg = msg;
                }
            }
        }
        if Instant::now() > deadline {
            bail!(
                "stack non healthy après {}s ({last_msg})",
                ctx.state.cfg.health_timeout.as_secs()
            );
        }
    }
}

async fn run(ctx: &Ctx, stack_id: i64, force: bool) -> Result<()> {
    let state = &ctx.state;
    let stack = state.portainer.stack(stack_id).await?;

    ctx.log("Analyse des mises à jour…").await;
    // Without a working Pangolin access, linked resources would silently stay
    // online during the update: refuse before touching anything.
    let resources = Arc::new(match &state.pangolin {
        Some(p) => p.resources().await.map_err(|e| {
            anyhow::anyhow!("Pangolin inaccessible, rien n'a été modifié : {e:#}")
        })?,
        None => vec![],
    });
    let report = analyse_stack(state.clone(), stack.clone(), resources).await;
    if report.is_self {
        bail!("Drydock tourne dans cette stack : il ne peut pas la mettre à jour lui-même");
    }
    if !report.pangolin_errors.is_empty() {
        bail!(
            "ressource(s) Pangolin illisible(s), rien n'a été modifié : {}",
            report.pangolin_errors.join(" ; ")
        );
    }
    if !report.can_update {
        bail!("aucune mise à jour applicable");
    }
    if report.needs_force && !force {
        bail!("mise à jour majeure détectée : confirmation requise");
    }

    // Build the new compose file.
    let mut file = state.portainer.stack_file(stack.id).await?;
    for u in report.updates.iter().filter(|u| u.auto) {
        match u.kind {
            UpdateKind::Tag => {
                let new_image = compose::with_tag(&u.image, &u.target_tag)?;
                file = compose::replace_image(&file, &u.image, &new_image)?;
                ctx.log(format!("{} : {} → {}", u.services.join(", "), u.current_tag, u.target_tag))
                    .await;
            }
            UpdateKind::Digest => {
                let v = match (&u.current_version, &u.new_version) {
                    (Some(a), Some(b)) if a != b => format!(" ({a} → {b})"),
                    _ => String::new(),
                };
                ctx.log(format!("{} : nouvelle image {}{v}", u.services.join(", "), u.image)).await;
            }
        }
    }

    // Pull only the images that must change (disabled containers keep theirs).
    // Done before maintenance: shorter downtime, and a failed pull changes nothing.
    let mut pulls: Vec<&str> = report
        .updates
        .iter()
        .filter(|u| u.auto)
        .filter_map(|u| u.pull_ref.as_deref())
        .collect();
    pulls.sort_unstable();
    pulls.dedup();
    for image in pulls {
        ctx.log(format!("Pull de {image}…")).await;
        state
            .portainer
            .pull_image(stack.endpoint_id, image)
            .await
            .map_err(|e| anyhow::anyhow!("{e:#} (rien n'a été modifié)"))?;
    }

    // Maintenance on (only for resources not already in maintenance).
    let mut enabled = vec![];
    if let Some(p) = &state.pangolin {
        for r in &report.resources {
            let current = p.resource(r.id).await.map(|r| r.maintenance).unwrap_or(r.maintenance);
            if current {
                ctx.log(format!("Pangolin « {} » déjà en maintenance, laissée telle quelle", r.name)).await;
                continue;
            }
            p.set_maintenance(r.id, true, &state.cfg.maintenance_title, &state.cfg.maintenance_message)
                .await?;
            enabled.push(r.clone());
            ctx.log(format!("Pangolin « {} » en maintenance", r.name)).await;
        }
    }

    let outcome: Result<()> = async {
        ctx.log("Redéploiement de la stack…").await;
        if report.git {
            state.portainer.redeploy_git_stack(&stack).await?;
        } else {
            state.portainer.update_stack(&stack, &file).await?;
        }
        ctx.log("Stack redéployée, vérification de la santé…").await;
        wait_healthy(ctx, &report).await?;
        ctx.log("Stack healthy").await;
        Ok(())
    }
    .await;

    let keep = outcome.is_err() && state.cfg.keep_maintenance_on_failure;
    if let Some(p) = &state.pangolin {
        for r in &enabled {
            if keep {
                ctx.log(format!("Pangolin « {} » laissée en maintenance (échec)", r.name)).await;
                continue;
            }
            match p.set_maintenance(r.id, false, "", "").await {
                Ok(()) => ctx.log(format!("Pangolin « {} » : maintenance retirée", r.name)).await,
                Err(e) => ctx.log(format!("Impossible de retirer la maintenance de « {} » : {e:#}", r.name)).await,
            }
        }
    }
    outcome
}

pub async fn start(state: Arc<AppState>, stack_id: i64, force: bool, requested_by: String) -> Result<u64> {
    let stack_name = {
        let snap = state.snapshot.read().await;
        snap.stacks
            .iter()
            .find(|s| s.id == stack_id)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| format!("#{stack_id}"))
    };
    let id = {
        let mut jobs = state.jobs.lock().await;
        if jobs
            .values()
            .any(|j| j.stack_id == stack_id && j.status == JobStatus::Running)
        {
            bail!("une mise à jour de cette stack est déjà en cours");
        }
        let id = jobs.keys().max().copied().unwrap_or(0) + 1;
        jobs.insert(
            id,
            Job {
                id,
                stack_id,
                stack_name,
                status: JobStatus::Running,
                started_at: now(),
                finished_at: None,
                requested_by: requested_by.clone(),
                forced: force,
                log: vec![],
            },
        );
        // Keep the last 50 jobs.
        while jobs.len() > 50 {
            let oldest = *jobs.keys().min().unwrap();
            jobs.remove(&oldest);
        }
        id
    };

    tokio::spawn(async move {
        let ctx = Ctx { state: state.clone(), job_id: id };
        ctx.log(format!(
            "Demandée par {requested_by}{}",
            if force { " (mise à jour majeure confirmée)" } else { "" }
        ))
        .await;
        let result = run(&ctx, stack_id, force).await;
        let status = match &result {
            Ok(()) => {
                ctx.log("Mise à jour terminée").await;
                JobStatus::Success
            }
            Err(e) => {
                ctx.log(format!("Échec : {e:#}")).await;
                JobStatus::Failed
            }
        };
        if let Some(j) = state.jobs.lock().await.get_mut(&id) {
            j.status = status;
            j.finished_at = Some(now());
        }
        // Refresh this stack's report.
        if let Ok(stack) = state.portainer.stack(stack_id).await {
            let resources = Arc::new(match &state.pangolin {
                Some(p) => p.resources().await.unwrap_or_default(),
                None => vec![],
            });
            let report = analyse_stack(state.clone(), stack, resources).await;
            let mut snap = state.snapshot.write().await;
            if let Some(slot) = snap.stacks.iter_mut().find(|s| s.id == stack_id) {
                *slot = report;
            }
        }
    });
    Ok(id)
}
