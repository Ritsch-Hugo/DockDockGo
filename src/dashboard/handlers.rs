use crate::auth::{extract_role_from_cookie, AppState};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        Html, IntoResponse, Redirect, Response,
    },
};
use futures::stream;
use sqlx::postgres::PgListener;
use sqlx::types::chrono;
use std::convert::Infallible;

// ─── Dashboard Dev ────────────────────────────────────────────────────────────

pub async fn dev_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match extract_role_from_cookie(&headers).as_deref() {
        Some("dev") => (),
        _ => return Redirect::to("/").into_response(),
    }

    let db = &state.db;

    // Récupère le sub de l'user depuis le cookie pour trouver ses IPs
    let sub = match crate::auth::extract_cookie(&headers, "sub") {
        Some(s) => s,
        None => return Redirect::to("/").into_response(),
    };

    let user = match sqlx::query!(
        "SELECT username, allowed_ips FROM users WHERE sub = $1",
        sub
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    {
        Some(u) => u,
        None => return Redirect::to("/").into_response(),
    };

    let allowed_ips: Vec<String> = user.allowed_ips.unwrap_or_default();
    let username = user.username.unwrap_or_else(|| "Dev".to_string());

    if allowed_ips.is_empty() {
        // Pas d'IPs configurées → dashboard vide
        let html = include_str!("../../template/dev.html")
            .replace("{{DEV_USERNAME}}", &username)
            .replace("{{DEV_IPS}}", "aucune IP")
            .replace("{{DEV_ALLOWED_IPS_JSON}}", "[]")
            .replace("{{ACTIVE_COUNT}}", "0")
            .replace("{{ACTIVE_PULLS_ROWS}}", "<tr><td colspan='6' style='color:var(--text-tertiary);text-align:center;padding:20px'>Aucun pull actif</td></tr>")
            .replace("{{HISTORY_COUNT}}", "0")
            .replace("{{HISTORY_PULLS_ROWS}}", "<tr><td colspan='5' style='color:var(--text-tertiary);text-align:center;padding:20px'>Aucun historique</td></tr>");
        return Html(html).into_response();
    }

    // ── Pulls actifs filtrés par IP ───────────────────────────────────────────
    let active_pulls = sqlx::query!(
        "SELECT uuid, repository, tag, ip_client, arch, client_type, decision_final, started_at
         FROM pulls
         WHERE scan_completed = false AND ip_client = ANY($1)
         ORDER BY started_at DESC LIMIT 50",
        &allowed_ips[..]
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let active_count = active_pulls.len();
    let mut active_rows_html = String::new();
    for p in &active_pulls {
        let uuid_str = p.uuid.to_string();
        let uuid_short = &uuid_str[..8];
        let decision = p.decision_final.as_deref().unwrap_or("PENDING");
        let badge = decision_badge(decision);
        active_rows_html.push_str(&format!(
            "<tr data-uuid='{uuid}' style='cursor:pointer' onclick=\"window.location.href='/dashboard/pull/{uuid}'\">
              <td style='color:var(--text-tertiary);font-family:var(--font-mono);font-size:11px'>{short}...</td>
              <td>{repo}:{tag}</td>
              <td style='color:var(--text-secondary)'>{ip}</td>
              <td><span class='chip'>{arch}</span></td>
              <td><div class='progress-bar' style='width:80px'><div class='progress-fill' style='width:50%'></div></div></td>
              <td><span class='badge {badge}'>{decision}</span></td>
            </tr>",
            uuid = uuid_str,
            short = uuid_short,
            repo = p.repository,
            tag = p.tag.as_deref().unwrap_or("latest"),
            ip = p.ip_client,
            arch = p.arch.as_deref().unwrap_or("unknown"),
            badge = badge,
            decision = decision,
        ));
    }
    if active_rows_html.is_empty() {
        active_rows_html = "<tr><td colspan='6' style='color:var(--text-tertiary);text-align:center;padding:20px'>Aucun pull actif</td></tr>".to_string();
    }

    // ── Historique filtré par IP ───────────────────────────────────────────────
    let history = sqlx::query!(
        "SELECT uuid, repository, tag, ip_client, client_type, decision_final, started_at
         FROM pulls
         WHERE scan_completed = true AND ip_client = ANY($1)
         ORDER BY started_at DESC LIMIT 100",
        &allowed_ips[..]
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let history_count = history.len();
    let mut history_rows_html = String::new();
    for h in &history {
        let uuid_str = h.uuid.to_string();
        let decision = h.decision_final.as_deref().unwrap_or("PENDING");
        let badge = decision_badge(decision);
        history_rows_html.push_str(&format!(
            "<tr data-uuid='{uuid}' style='cursor:pointer' onclick=\"window.location.href='/dashboard/pull/{uuid}'\">
              <td style='color:var(--text-secondary)'>{date}</td>
              <td>{repo}:{tag}</td>
              <td style='color:var(--text-secondary)'>{ip}</td>
              <td><span class='chip'>{client}</span></td>
              <td><span class='badge {badge}'>{decision}</span></td>
            </tr>",
            uuid = uuid_str,
            date = format_datetime(h.started_at),
            repo = h.repository,
            tag = h.tag.as_deref().unwrap_or("latest"),
            ip = h.ip_client,
            client = h.client_type.as_deref().unwrap_or("unknown"),
            badge = badge,
            decision = decision,
        ));
    }
    if history_rows_html.is_empty() {
        history_rows_html = "<tr><td colspan='5' style='color:var(--text-tertiary);text-align:center;padding:20px'>Aucun historique</td></tr>".to_string();
    }

    // IPs pour le JS (déduplication SSE côté client)
    let ips_json = serde_json::to_string(&allowed_ips).unwrap_or_else(|_| "[]".to_string());
    let ips_display = allowed_ips.join(", ");

    let html = include_str!("../../template/dev.html")
        .replace("{{DEV_USERNAME}}", &username)
        .replace("{{DEV_IPS}}", &ips_display)
        .replace("{{DEV_ALLOWED_IPS_JSON}}", &ips_json)
        .replace("{{ACTIVE_COUNT}}", &active_count.to_string())
        .replace("{{ACTIVE_PULLS_ROWS}}", &active_rows_html)
        .replace("{{HISTORY_COUNT}}", &history_count.to_string())
        .replace("{{HISTORY_PULLS_ROWS}}", &history_rows_html);

    Html(html).into_response()
}

// ─── Dashboard RSSI ───────────────────────────────────────────────────────────

pub async fn rssi_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match extract_role_from_cookie(&headers).as_deref() {
        Some("rssi") => (),
        _ => return Redirect::to("/").into_response(),
    }

    let db = &state.db;

    // ── Métriques vue globale ─────────────────────────────────────────────────

    let pulls_actifs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pulls WHERE scan_completed = false")
            .fetch_one(db)
            .await
            .unwrap_or(0);

    let bloques_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pulls WHERE decision_final = 'DENY' AND started_at >= NOW() - INTERVAL '24 hours'"
    ).fetch_one(db).await.unwrap_or(0);

    let en_quarantaine: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM quarantine")
        .fetch_one(db)
        .await
        .unwrap_or(0);

    let en_cache: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cache")
        .fetch_one(db)
        .await
        .unwrap_or(0);

    let allow_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pulls WHERE decision_final = 'ALLOW' AND started_at >= NOW() - INTERVAL '24 hours'"
    ).fetch_one(db).await.unwrap_or(0);

    let pending_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pulls WHERE decision_final = 'PENDING' AND started_at >= NOW() - INTERVAL '24 hours'"
    ).fetch_one(db).await.unwrap_or(0);

    let deny_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pulls WHERE decision_final = 'DENY' AND started_at >= NOW() - INTERVAL '24 hours'"
    ).fetch_one(db).await.unwrap_or(0);

    let total_24h = (allow_24h + pending_24h + deny_24h).max(1);
    let allow_pct = (allow_24h * 100 / total_24h).min(100);
    let pending_pct = (pending_24h * 100 / total_24h).min(100);
    let deny_pct = (deny_24h * 100 / total_24h).min(100);

    // ── Alertes actives (DENY et PENDING récents) ─────────────────────────────
    // FIX: inclure PENDING en plus de DENY dans les alertes actives

    let alerts = sqlx::query!(
        "SELECT uuid, repository, tag, ip_client, registry, started_at, decision_final
         FROM pulls WHERE decision_final IN ('DENY', 'PENDING')
         ORDER BY started_at DESC LIMIT 5"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut alerts_html = String::new();
    for a in &alerts {
        let since = format_since(a.started_at);
        let decision = a.decision_final.as_deref().unwrap_or("PENDING");
        let is_pending = decision == "PENDING";
        let uuid_str = a.uuid.to_string();
        // FIX: chaque alerte est cliquable et redirige vers la page détail du pull
        alerts_html.push_str(&format!(
            "<div class='alert-row' data-uuid='{uuid}' style='cursor:pointer' onclick=\"window.location.href='/dashboard/pull/{uuid}'\">
              <div class='alert-icon{icon_class}'><div class='alert-icon-dot{dot_class}'></div></div>
              <div>
                <div class='alert-text'><strong>{decision}</strong> — {}:{}</div>
                <div class='alert-text' style='color:var(--text-secondary)'>{} · {}</div>
                <div class='alert-time'>{}</div>
              </div>
            </div>",
            a.repository,
            a.tag.as_deref().unwrap_or("latest"),
            a.ip_client,
            a.registry,
            since,
            uuid = uuid_str,
            icon_class = if is_pending { " amber" } else { "" },
            dot_class = if is_pending { " amber" } else { "" },
            decision = decision,
        ));
    }
    if alerts_html.is_empty() {
        alerts_html = "<div style='color:var(--text-tertiary);font-size:12px'>Aucune alerte</div>"
            .to_string();
    }

    // ── Pulls actifs (vue globale + page pulls) ───────────────────────────────

    let active_pulls = sqlx::query!(
        "SELECT uuid, repository, tag, ip_client, registry, arch, client_type,
                decision_final, scan_completed, started_at
         FROM pulls WHERE scan_completed = false
         ORDER BY started_at DESC LIMIT 50"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    // FIX: ajout de data-uuid sur les lignes de la vue globale pour rendre cliquables
    let mut overview_pulls_html = String::new();
    for p in &active_pulls {
        let decision = p.decision_final.as_deref().unwrap_or("PENDING");
        let badge = decision_badge(decision);
        let uuid_str = p.uuid.to_string();
        overview_pulls_html.push_str(&format!(
            "<tr data-uuid='{uuid}' style='cursor:pointer' onclick=\"window.location.href='/dashboard/pull/{uuid}'\">
              <td>{}:{}</td>
              <td style='color:var(--text-secondary)'>{}</td>
              <td><span class='chip'>{}</span></td>
              <td><div class='progress-bar' style='width:100px'>
                <div class='progress-fill {}' style='width:50%'></div>
              </div></td>
              <td><span class='badge {}'>{}</span></td>
            </tr>",
            p.repository,
            p.tag.as_deref().unwrap_or("latest"),
            p.ip_client,
            p.client_type.as_deref().unwrap_or("unknown"),
            "",
            badge, decision,
            uuid = uuid_str,
        ));
    }

    // Lignes pour la page "Pulls en cours" (tableau détaillé)
    let mut pulls_rows_html = String::new();
    for p in &active_pulls {
        let uuid_str = p.uuid.to_string();
        let uuid_short = &uuid_str[..8];
        let decision = p.decision_final.as_deref().unwrap_or("PENDING");
        let badge = decision_badge(decision);
        pulls_rows_html.push_str(&format!(
            "<tr data-uuid='{uuid}' style='cursor:pointer' onclick=\"window.location.href='/dashboard/pull/{uuid}'\">
              <td style='color:var(--text-tertiary);font-family:var(--font-mono);font-size:11px'>{short}...</td>
              <td>{repo}:{tag}</td>
              <td style='color:var(--text-secondary)'>{ip}</td>
              <td><span class='chip'>{arch}</span></td>
              <td>
                <div class='progress-bar' style='width:80px'>
                  <div class='progress-fill' style='width:50%'></div>
                </div>
              </td>
              <td><span class='badge {badge}'>{decision}</span></td>
              <td><button class='btn btn-danger' style='font-size:11px;padding:3px 8px'>Forcer DENY</button></td>
            </tr>",
            uuid = uuid_str,
            short = uuid_short,
            repo = p.repository,
            tag = p.tag.as_deref().unwrap_or("latest"),
            ip = p.ip_client,
            arch = p.arch.as_deref().unwrap_or("unknown"),
            badge = badge,
            decision = decision
        ));
    }

    // ── Quarantaine ───────────────────────────────────────────────────────────

    let quarantine_items = sqlx::query!(
        "SELECT id, registry, repository, digest, type, file_path, size_bytes, added_at
         FROM quarantine ORDER BY added_at DESC LIMIT 50"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut quarantine_rows_html = String::new();
    for q in &quarantine_items {
        let size = format_size(q.size_bytes.unwrap_or(0));
        let since = format_since(q.added_at);
        let q_id = q.id.to_string();
        quarantine_rows_html.push_str(&format!(
            "<tr data-id='{id}'>
            <td style='font-family:var(--font-mono);font-size:11px;color:var(--text-secondary)'>{}...</td>
            <td>{}</td>
            <td style='color:var(--text-secondary)'>{}</td>
            <td>{}</td>
            <td style='color:var(--text-secondary)'>{}</td>
            <td><span class='chip'>{}</span></td>
            <td style='color:var(--text-tertiary);font-size:11px'>—</td>
            </tr>",
            &q.digest.chars().take(32).collect::<String>(),
            q.repository,
            q.registry,
            size,
            since,
            q.r#type.as_deref().unwrap_or("?"),
            id = q_id,
        ));
    }
    if quarantine_rows_html.is_empty() {
        quarantine_rows_html = "<tr><td colspan='6' style='color:var(--text-tertiary);text-align:center;padding:20px'>Quarantaine vide</td></tr>".to_string();
    }

    // ── Cache ─────────────────────────────────────────────────────────────────

    let cache_items = sqlx::query!(
        "SELECT id, registry, repository, digest, type, size_bytes, added_at
         FROM cache ORDER BY added_at DESC LIMIT 50"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut cache_rows_html = String::new();
    for c in &cache_items {
        let size = format_size(c.size_bytes.unwrap_or(0));
        let date = format_since(c.added_at);
        let cache_id = c.id.to_string();
        cache_rows_html.push_str(&format!(
            "<tr data-id='{id}'>
              <td style='font-family:var(--font-mono);font-size:11px;color:var(--text-secondary)'>{digest}...</td>
              <td>{repo}</td>
              <td style='color:var(--text-secondary)'>{registry}</td>
              <td>{size}</td>
              <td style='color:var(--text-secondary)'>{date}</td>
              <td><button class='btn btn-danger' style='font-size:11px;padding:3px 8px'
                onclick=\"deleteFromCache('{id}', this.closest('tr'))\">Supprimer</button></td>
            </tr>",
            id = cache_id,
            digest = &c.digest.chars().take(32).collect::<String>(),
            repo = c.repository,
            registry = c.registry,
            size = size,
            date = date,
        ));
    }
    if cache_rows_html.is_empty() {
        cache_rows_html = "<tr><td colspan='5' style='color:var(--text-tertiary);text-align:center;padding:20px'>Cache vide</td></tr>".to_string();
    }

    // ── Whitelist ─────────────────────────────────────────────────────────────

    let wl_items = sqlx::query!(
        "SELECT id, registry, repository, tag, added_at FROM whitelist ORDER BY added_at DESC"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let wl_count = wl_items.len();
    let mut wl_rows_html = String::new();
    for w in &wl_items {
        let wl_id = w.id.to_string();
        // FIX: data-id présent sur la ligne, onclick appelle removeFromList avec l'id correct
        wl_rows_html.push_str(&format!(
            "<tr data-id='{id}'>
              <td>{reg}/{repo}:{tag}</td>
              <td style='color:var(--text-secondary)'>{date}</td>
              <td><button class='btn' style='font-size:10px;padding:2px 6px'
                onclick=\"removeFromList('whitelist', '{id}', this.closest('tr'))\">Retirer</button></td>
            </tr>",
            id = wl_id,
            reg = w.registry,
            repo = w.repository,
            tag = w.tag.as_deref().unwrap_or("*"),
            date = format_datetime(w.added_at),
        ));
    }

    // ── Blacklist ─────────────────────────────────────────────────────────────

    let bl_items = sqlx::query!(
        "SELECT id, registry, repository, tag, added_at FROM blacklist ORDER BY added_at DESC"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let bl_count = bl_items.len();
    let mut bl_rows_html = String::new();
    for b in &bl_items {
        let bl_id = b.id.to_string();
        // FIX: bouton "Retirer" ajouté pour la blacklist avec data-id correct
        bl_rows_html.push_str(&format!(
            r#"<tr data-id="{id}">
            <td>{reg}/{repo}:{tag}</td>
            <td style="color:var(--text-secondary)">{date}</td>
            <td>
                <button class="btn btn-danger" style="font-size:10px;padding:2px 6px"
                onclick="removeFromList('blacklist', '{id}', this.closest('tr'))">Retirer</button>
            </td>
            </tr>"#,
            id = bl_id,
            reg = b.registry,
            repo = b.repository,
            tag = b.tag.as_deref().unwrap_or("*"),
            date = format_datetime(b.added_at),
        ));
    }

    // ── Historique (pulls terminés) ───────────────────────────────────────────

    let history = sqlx::query!(
        "SELECT uuid, repository, tag, ip_client, client_type, decision_final,
                scan_completed, started_at
         FROM pulls
         WHERE scan_completed = true
         ORDER BY started_at DESC LIMIT 100"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut history_rows_html = String::new();
    for h in &history {
        let decision = h.decision_final.as_deref().unwrap_or("PENDING");
        let badge = decision_badge(decision);
        let date = format_datetime(h.started_at);
        let hist_uuid = h.uuid.to_string();
        history_rows_html.push_str(&format!(
            r#"<tr data-uuid="{uuid}" style="cursor:pointer" onclick="window.location.href='/dashboard/pull/{uuid}'">
            <td style="color:var(--text-secondary)">{date}</td>
            <td>{repo}:{tag}</td>
            <td style="color:var(--text-secondary)">{ip}</td>
            <td><span class="chip">{client}</span></td>
            <td><span class="badge {badge}">{decision}</span></td>
            <td><span class="badge badge-gray">Non</span></td>
            </tr>"#,
            uuid = hist_uuid,
            date = date,
            repo = h.repository,
            tag = h.tag.as_deref().unwrap_or("latest"),
            ip = h.ip_client,
            client = h.client_type.as_deref().unwrap_or("unknown"),
            badge = badge,
            decision = decision
        ));
    }
    if history_rows_html.is_empty() {
        history_rows_html = "<tr><td colspan='6' style='color:var(--text-tertiary);text-align:center;padding:20px'>Aucun historique</td></tr>".to_string();
    }

    // ── Injection dans le HTML ────────────────────────────────────────────────

    let html = include_str!("../../template/rssi.html")
        // Métriques
        .replace("{{PULLS_ACTIFS}}", &pulls_actifs.to_string())
        .replace("{{BLOQUES_TODAY}}", &bloques_today.to_string())
        .replace("{{EN_QUARANTAINE}}", &en_quarantaine.to_string())
        .replace("{{EN_CACHE}}", &en_cache.to_string())
        // Barres de décisions 24h
        .replace("{{ALLOW_24H}}", &allow_24h.to_string())
        .replace("{{ALLOW_PCT}}", &allow_pct.to_string())
        .replace("{{PENDING_24H}}", &pending_24h.to_string())
        .replace("{{PENDING_PCT}}", &pending_pct.to_string())
        .replace("{{DENY_24H}}", &deny_24h.to_string())
        .replace("{{DENY_PCT}}", &deny_pct.to_string())
        // Alertes
        .replace("{{ALERTS_ROWS}}", &alerts_html)
        // Vue globale pulls
        .replace("{{OVERVIEW_PULLS}}", &overview_pulls_html)
        // Page pulls en cours
        .replace("{{PULLS_ROWS}}", &pulls_rows_html)
        // Quarantaine
        .replace("{{QUARANTINE_ROWS}}", &quarantine_rows_html)
        .replace("{{QUARANTINE_COUNT}}", &en_quarantaine.to_string())
        // Cache
        .replace("{{CACHE_ROWS}}", &cache_rows_html)
        .replace("{{CACHE_COUNT}}", &en_cache.to_string())
        // Whitelist
        .replace("{{WL_ROWS}}", &wl_rows_html)
        .replace("{{WL_COUNT}}", &wl_count.to_string())
        // Blacklist
        .replace("{{BL_ROWS}}", &bl_rows_html)
        .replace("{{BL_COUNT}}", &bl_count.to_string())
        // Historique
        .replace("{{HISTORY_ROWS}}", &history_rows_html);

    Html(html).into_response()
}

// ─── SSE ──────────────────────────────────────────────────────────────────────

pub async fn dashboard_events_stream(
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if extract_role_from_cookie(&headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL non définie");
    let mut listener = PgListener::connect(&db_url).await.unwrap();
    listener.listen("dashboard_updates").await.unwrap();

    println!("[SSE] Nouveau client connecté");

    let event_stream = stream::unfold(listener, |mut listener| async move {
        match listener.recv().await {
            Ok(notification) => {
                println!("[SSE] Notification : {}", notification.payload());
                let event = Event::default().data(notification.payload());
                Some((Ok::<Event, Infallible>(event), listener))
            }
            Err(_) => None,
        }
    });

    Sse::new(event_stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

// ─── Helpers formatage ────────────────────────────────────────────────────────

fn decision_badge(decision: &str) -> &'static str {
    match decision {
        "ALLOW" => "badge-green",
        "DENY" => "badge-red",
        "ERROR" => "badge-red",
        _ => "badge-amber",
    }
}

fn format_size(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} MB", bytes / (1024 * 1024))
    }
}

fn format_since(ts: Option<chrono::DateTime<chrono::Utc>>) -> String {
    let Some(ts) = ts else {
        return "—".to_string();
    };
    let secs = (chrono::Utc::now() - ts).num_seconds();
    if secs < 60 {
        format!("il y a {}s", secs)
    } else if secs < 3600 {
        format!("il y a {}min", secs / 60)
    } else if secs < 86400 {
        format!("il y a {}h", secs / 3600)
    } else {
        format!("il y a {}j", secs / 86400)
    }
}

fn format_datetime(ts: Option<chrono::DateTime<chrono::Utc>>) -> String {
    match ts {
        Some(t) => t.format("%d/%m %H:%M").to_string(),
        None => "—".to_string(),
    }
}

// ─── Page détail d'un pull ────────────────────────────────────────────────────
pub async fn pull_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(uuid): axum::extract::Path<String>,
) -> Response {
    if extract_role_from_cookie(&headers).is_none() {
        return Redirect::to("/").into_response();
    }

    let db = &state.db;
    let uuid_parsed: uuid::Uuid = match uuid.parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "UUID invalide").into_response(),
    };

    let pull = match sqlx::query!(
        "SELECT uuid, ip_client, registry, repository, tag, os, arch, client_type,
                started_at, last_activity, scan_completed, decision_final
         FROM pulls WHERE uuid = $1",
        uuid_parsed
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, "Pull introuvable").into_response(),
    };

    let digests = sqlx::query!(
        "SELECT id, digest_value, digest_type, digest_algo, received_at
         FROM pull_digests WHERE pull_id = $1 ORDER BY received_at ASC",
        uuid_parsed
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let ia_decisions = sqlx::query!(
        "SELECT id, created_at, decision, scan_reasoning,
                dynamic_scan, compliance_scan, static_scan,
                vulnerability_score, confidence, rationale,
                decision_metadata, alternatives
        FROM ia_decisions WHERE pull_id = $1 ORDER BY created_at ASC",
        uuid_parsed
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let scan_events = sqlx::query!(
        "SELECT id, scanner_type, response_scanner, created_at, ia_decision_id,
                llm_summary, executed
         FROM scan_events WHERE pull_id = $1 ORDER BY created_at ASC",
        uuid_parsed
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let decision = pull.decision_final.as_deref().unwrap_or("PENDING");
    let badge = decision_badge(decision);

    // ── Digests ───────────────────────────────────────────────────────────────
    let mut digests_html = String::new();
    for d in &digests {
        digests_html.push_str(&format!(
            "<tr>
              <td style='font-family:var(--font-mono);font-size:11px;color:var(--text-secondary)'>{}</td>
              <td><span class='chip'>{}</span></td>
              <td><span class='chip'>{}</span></td>
              <td style='color:var(--text-tertiary);font-size:11px'>{}</td>
            </tr>",
            d.digest_value,
            d.digest_type.as_deref().unwrap_or("?"),
            d.digest_algo.as_deref().unwrap_or("?"),
            format_since(d.received_at)
        ));
    }
    if digests_html.is_empty() {
        digests_html = "<tr><td colspan='4' style='color:var(--text-tertiary);text-align:center;padding:16px'>Aucun digest</td></tr>".to_string();
    }

    // ── IA Decisions ──────────────────────────────────────────────────────────
    let mut ia_cards_html = String::new();
    for ia in &ia_decisions {
        let score = ia.vulnerability_score.unwrap_or(0.0);
        let vuln_score = ia.vulnerability_score.unwrap_or(0.0);
        let confidence = ia.confidence.unwrap_or(0.0);
        let score_color = if score > 0.75 {
            "var(--text-success)"
        } else if score > 0.4 {
            "var(--text-warning)"
        } else {
            "var(--text-danger)"
        };
        let vuln_color = if vuln_score > 7.0 {
            "var(--text-danger)"
        } else if vuln_score > 4.0 {
            "var(--text-warning)"
        } else {
            "var(--text-success)"
        };

        let planned_count = [ia.static_scan, ia.compliance_scan, ia.dynamic_scan]
            .iter()
            .filter(|b| b.unwrap_or(false))
            .count();
        let done_count = scan_events
            .iter()
            .filter(|ev| ev.ia_decision_id == Some(ia.id))
            .count();
        let scan_done = planned_count > 0 && done_count >= planned_count;
        let decision_str = if scan_done {
            ia.decision.as_deref().unwrap_or("—")
        } else {
            "EN COURS"
        };
        let ia_badge = match decision_str {
            "ALLOW" => "badge-green",
            "DENY" => "badge-red",
            "EN COURS" => "badge-gray",
            _ => "badge-amber",
        };

        let scanners: Vec<&str> = [
            if ia.static_scan.unwrap_or(false) {
                Some("statique")
            } else {
                None
            },
            if ia.compliance_scan.unwrap_or(false) {
                Some("compliance")
            } else {
                None
            },
            if ia.dynamic_scan.unwrap_or(false) {
                Some("dynamique")
            } else {
                None
            },
        ]
        .iter()
        .filter_map(|x| *x)
        .collect();

        let scanners_chips: String = if scanners.is_empty() {
            "<span style='color:var(--text-tertiary);font-size:11px'>aucun</span>".to_string()
        } else {
            scanners
                .iter()
                .map(|s| format!("<span class='chip chip-blue'>{}</span>", s))
                .collect()
        };

        let rationale_html = markdown_to_html(ia.rationale.as_deref().unwrap_or("—"));
        let reasoning_dec = "—";

        let workers_html = build_workers_html(ia.scan_reasoning.as_ref());
        let arbiter_html = build_arbiter_html(ia.scan_reasoning.as_ref());
        let alternatives_html = build_alternatives_html(ia.alternatives.as_ref());
        let dec_workers_html = build_decision_workers_html(ia.decision_metadata.as_ref());
        let dec_arbiter_html = build_decision_arbiter_html(ia.decision_metadata.as_ref());

        let reasoning_dec_section = if reasoning_dec != "—" {
            format!(
                "<div class='ia-section'><div class='ia-section-label'>Raisonnement choix des scanners</div><div class='ia-text-block'>{}</div></div>",
                html_escape(reasoning_dec)
            )
        } else {
            String::new()
        };

        let alternatives_tab = if ia.alternatives.is_some() {
            format!(
                "<button class='ia-tab' onclick=\"switchTab('{}','alt')\">Alternatives</button>",
                ia.id
            )
        } else {
            String::new()
        };

        ia_cards_html.push_str(&format!(r#"
<div class="ia-card" id="ia-{ia_id}">
  <div class="ia-card-header" onclick="toggleIaCard('{ia_id}')">
    <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0">
      <span class="badge {ia_badge}">{decision_str}</span>
      <span style="font-size:12px;color:var(--text-secondary)">{time}</span>
      <div style="display:flex;gap:4px;margin-left:8px">{scanners_chips}</div>
    </div>
    <div style="display:flex;align-items:center;gap:16px;flex-shrink:0">
      <div style="text-align:right">
        <div style="font-size:10px;color:var(--text-tertiary)">Score IA</div>
        <div style="font-size:15px;font-weight:600;color:{score_color}">{score:.2}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:10px;color:var(--text-tertiary)">Vuln. score</div>
        <div style="font-size:15px;font-weight:600;color:{vuln_color}">{vuln_score:.1}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:10px;color:var(--text-tertiary)">Confiance</div>
        <div style="font-size:13px;font-weight:500;color:var(--text-secondary)">{confidence_pct}%</div>
      </div>
      <span class="ia-chevron" id="chevron-{ia_id}">▼</span>
    </div>
  </div>
  <div class="ia-card-body hidden" id="body-{ia_id}">
    <div class="ia-section">
      <div class="ia-section-label">Raisonnement final (arbitre)</div>
      <div class="ia-text-block md-text">{rationale_html}</div>
    </div>
    {reasoning_dec_section}
    <div class="ia-tabs" id="tabs-{ia_id}">
      <button class="ia-tab active" onclick="switchTab('{ia_id}','scan')">Analyse des scans</button>
      <button class="ia-tab" onclick="switchTab('{ia_id}','decision')">Choix des scanners</button>
      {alternatives_tab}
    </div>
    <div class="ia-panel" id="panel-scan-{ia_id}">
      <div class="ia-section-label" style="margin-bottom:8px">Workers — analyse des résultats de scan</div>
      <div class="workers-grid">{workers_html}</div>
      {arbiter_html}
    </div>
    <div class="ia-panel hidden" id="panel-decision-{ia_id}">
      <div class="ia-section-label" style="margin-bottom:8px">Workers — décision sur les scanners à lancer</div>
      <div class="workers-grid">{dec_workers_html}</div>
      {dec_arbiter_html}
    </div>
    <div class="ia-panel hidden" id="panel-alt-{ia_id}">
      {alternatives_html}
    </div>
  </div>
</div>
"#,
            ia_id             = ia.id,
            ia_badge          = ia_badge,
            decision_str      = decision_str,
            time              = format_since(ia.created_at),
            scanners_chips    = scanners_chips,
            score_color       = score_color,
            score             = score,
            vuln_color        = vuln_color,
            vuln_score        = vuln_score,
            confidence_pct    = (confidence * 100.0) as i32,
            rationale_html    = rationale_html,
            reasoning_dec_section = reasoning_dec_section,
            alternatives_tab  = alternatives_tab,
            workers_html      = workers_html,
            arbiter_html      = arbiter_html,
            dec_workers_html  = dec_workers_html,
            dec_arbiter_html  = dec_arbiter_html,
            alternatives_html = alternatives_html,
        ));
    }
    if ia_cards_html.is_empty() {
        ia_cards_html = "<div style='color:var(--text-tertiary);font-size:12px;padding:12px'>Aucune décision IA enregistrée</div>".to_string();
    }

    // ── Scan events ───────────────────────────────────────────────────────────
    let mut events_html = String::new();
    for ev in &scan_events {
        let scanner_type = ev.scanner_type.as_deref().unwrap_or("?");
        let executed = ev.executed.unwrap_or(false);
        let resp = ev.response_scanner.as_ref();
        let llm_summary = ev.llm_summary.as_deref().unwrap_or("");
        let raw_json = resp
            .map(|v| serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()))
            .unwrap_or_default();

        let exec_badge = if executed {
            "<span class='badge badge-green' style='font-size:10px'>Exécuté</span>"
        } else {
            "<span class='badge badge-gray' style='font-size:10px'>Non exécuté</span>"
        };

        let (scanner_summary, scanner_body) = if let Some(r) = resp {
            let stype = scanner_type.to_lowercase();
            if stype.contains("haut") || stype.contains("hl") || stype.contains("high") {
                render_hl_scanner(r)
            } else if stype.contains("static") || stype.contains("cve") || stype.contains("trivy") {
                render_static_scanner(r)
            } else if stype.contains("compliance") {
                render_compliance_scanner(r)
            } else {
                let preview = if raw_json.len() > 120 {
                    format!("{}…", &raw_json[..120])
                } else {
                    raw_json.clone()
                };
                (String::new(), format!(
                    "<pre style='font-size:10px;color:var(--text-secondary);white-space:pre-wrap;overflow-wrap:break-word'>{}</pre>",
                    html_escape(&preview)
                ))
            }
        } else {
            (
                "<span style='color:var(--text-tertiary);font-size:11px'>—</span>".to_string(),
                String::new(),
            )
        };

        let llm_html = if !llm_summary.is_empty() {
            format!(
                "<div class='ev-llm-summary'>🤖 {}</div>",
                html_escape(llm_summary)
            )
        } else {
            String::new()
        };

        let ev_id = ev.id;
        let json_attr = html_escape(&raw_json);

        events_html.push_str(&format!(r#"
<div class='ev-card' id='ev-{ev_id}'>
  <div class='ev-card-header' onclick="toggleEvCard('{ev_id}')">
    <div style='display:flex;align-items:center;gap:8px;flex:1;flex-wrap:wrap'>
      <span class='chip'>{scanner}</span>
      {exec_badge}
      <div class='ev-stats'>{scanner_summary}</div>
    </div>
    <div style='display:flex;align-items:center;gap:10px;flex-shrink:0'>
      <span style='font-size:11px;color:var(--text-tertiary)'>{time}</span>
      <span class='ia-chevron' id='ev-chevron-{ev_id}'>▼</span>
    </div>
  </div>
  <div class='ev-card-body hidden' id='ev-body-{ev_id}'>
    {scanner_body}
    {llm_html}
    <div style='margin-top:10px;padding-top:10px;border-top:0.5px solid var(--border)'>
      <button class='json-btn' data-json='{json_attr}' onclick="openJsonModal(this.getAttribute('data-json'))">Voir JSON brut</button>
    </div>
  </div>
</div>"#,
            ev_id          = ev_id,
            scanner        = html_escape(scanner_type),
            exec_badge     = exec_badge,
            scanner_summary = scanner_summary,
            time           = format_since(ev.created_at),
            scanner_body   = scanner_body,
            llm_html       = llm_html,
            json_attr      = json_attr,
        ));
    }
    if events_html.is_empty() {
        events_html = "<div data-empty style='color:var(--text-tertiary);font-size:12px;padding:12px'>Aucun scan event</div>".to_string();
    }

    // ── Timeline ──────────────────────────────────────────────────────────────
    let mut timeline_html = String::new();
    for ia in &ia_decisions {
        let score = ia.vulnerability_score.unwrap_or(0.0);
        let score_color = if score > 0.75 {
            "var(--text-success)"
        } else if score > 0.4 {
            "var(--text-warning)"
        } else {
            "var(--text-danger)"
        };

        let planned_count = [ia.static_scan, ia.compliance_scan, ia.dynamic_scan]
            .iter()
            .filter(|b| b.unwrap_or(false))
            .count();
        let done_count = scan_events
            .iter()
            .filter(|ev| ev.ia_decision_id == Some(ia.id))
            .count();
        let scan_done = planned_count > 0 && done_count >= planned_count;

        let decision_str = if scan_done {
            ia.decision.as_deref().unwrap_or("PENDING")
        } else {
            "EN COURS"
        };
        let ia_badge = match decision_str {
            "ALLOW" => "badge-green",
            "DENY" => "badge-red",
            "EN COURS" => "badge-gray",
            _ => "badge-amber",
        };

        let scanners: Vec<&str> = [
            if ia.static_scan.unwrap_or(false) {
                Some("statique")
            } else {
                None
            },
            if ia.compliance_scan.unwrap_or(false) {
                Some("compliance")
            } else {
                None
            },
            if ia.dynamic_scan.unwrap_or(false) {
                Some("dynamique")
            } else {
                None
            },
        ]
        .iter()
        .filter_map(|x| *x)
        .collect();

        timeline_html.push_str(&format!(r#"<div class='tl-item'>
  <div class='tl-dot blue'></div>
  <div class='tl-label'>Décision IA — <span class='badge {ia_badge}' style='font-size:10px;padding:2px 6px'>{decision_str}</span></div>
  <div class='tl-sub'>{time} · Score : <span style='color:{score_color}'>{score:.2}</span> · <span style='color:var(--text-secondary)'>Conf. {conf_pct}%</span></div>
  <div class='tl-sub' style='margin-top:3px'>Scanners : {scanners}</div>
</div>"#,
            ia_badge     = ia_badge,
            decision_str = decision_str,
            time         = format_since(ia.created_at),
            score_color  = score_color,
            score        = score,
            conf_pct     = (ia.confidence.unwrap_or(0.0) * 100.0) as i32,
            scanners     = if scanners.is_empty() { "aucun".to_string() } else { scanners.join(", ") },
        ));

        for scanner_name in &["statique", "compliance", "dynamique"] {
            let planned = match *scanner_name {
                "statique" => ia.static_scan.unwrap_or(false),
                "compliance" => ia.compliance_scan.unwrap_or(false),
                "dynamique" => ia.dynamic_scan.unwrap_or(false),
                _ => false,
            };
            if !planned {
                continue;
            }

            // Match scanner_type broadly: the DB value may be "scanner-static",
            // "cve", "trivy", etc. — not necessarily the display label.
            let done_event = scan_events.iter().find(|ev| {
                let t = ev.scanner_type.as_deref().unwrap_or("").to_lowercase();
                let matches = match *scanner_name {
                    "statique" => {
                        t.contains("static")
                            || t.contains("cve")
                            || t.contains("trivy")
                            || t.contains("statique")
                    }
                    "compliance" => t.contains("compliance"),
                    "dynamique" => t.contains("dynamic") || t.contains("dynamique"),
                    _ => false,
                };
                matches && ev.ia_decision_id == Some(ia.id)
            });

            if let Some(ev) = done_event {
                let summary = ev.llm_summary.as_deref().unwrap_or("Terminé");
                timeline_html.push_str(&format!(r#"<div class='tl-item'>
  <div class='tl-dot green'></div>
  <div class='tl-label'>Scanner : {name}</div>
  <div class='tl-sub'>{time} · <span style='color:var(--text-success)'>✓ Terminé</span></div>
  <div class='tl-sub' style='color:var(--text-success);margin-top:2px;font-size:10px;word-break:break-word'>{summary}</div>
</div>"#,
                    name    = scanner_name,
                    time    = format_since(ev.created_at),
                    summary = html_escape(summary),
                ));
            } else {
                timeline_html.push_str(&format!(
                    r#"<div class='tl-item' data-scanner='{name}'>
  <div class='tl-dot' style='background:var(--border-md)'></div>
  <div class='tl-label' style='color:var(--text-tertiary)'>Scanner : {name}</div>
  <div class='tl-sub' style='color:var(--text-tertiary)'>En attente...</div>
</div>"#,
                    name = scanner_name,
                ));
            }
        }
    }

    // Décision finale
    let final_decision = pull.decision_final.as_deref().unwrap_or("PENDING");
    let final_badge = decision_badge(final_decision);
    let final_dot = match final_decision {
        "ALLOW" => "green",
        "DENY" => "red",
        _ => "amber",
    };
    timeline_html.push_str(&format!(r#"<div class='tl-item' id='tl-final'>
  <div class='tl-dot {final_dot}'></div>
  <div class='tl-label'>Décision finale</div>
  <div class='tl-sub'><span class='badge {final_badge}' id='decision-badge-tl'>{final_decision}</span></div>
</div>"#,
        final_dot      = final_dot,
        final_badge    = final_badge,
        final_decision = final_decision,
    ));

    if timeline_html.is_empty() {
        timeline_html = "<div style='color:var(--text-tertiary);font-size:12px;padding:12px'>En attente...</div>".to_string();
    }

    // ── HTML final ────────────────────────────────────────────────────────────
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pull {short}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg-primary: #1c1c1a; --bg-secondary: #252523; --bg-tertiary: #161614;
    --bg-info: #0c447c; --bg-success: #27500a; --bg-warning: #633806; --bg-danger: #791f1f;
    --text-primary: #e8e6e0; --text-secondary: #a09e97; --text-tertiary: #5f5e5a;
    --text-info: #85b7eb; --text-success: #c0dd97; --text-warning: #fac775; --text-danger: #f09595;
    --border: rgba(255,255,255,0.08); --border-md: rgba(255,255,255,0.15);
    --radius-md: 8px; --radius-lg: 12px;
    --font: 'Segoe UI', system-ui, sans-serif;
    --font-mono: 'Cascadia Code', 'Fira Code', 'Courier New', monospace;
    --blue: #378ADD; --green: #639922; --amber: #BA7517; --red: #E24B4A;
  }}
  body {{ font-family: var(--font); font-size: 14px; color: var(--text-primary); background: var(--bg-tertiary); padding: 28px 36px; }}
  .back {{ display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-secondary); text-decoration: none; margin-bottom: 20px; }}
  .back:hover {{ color: var(--text-primary); }}
  .page-title {{ font-size: 18px; font-weight: 500; margin-bottom: 4px; }}
  .subtitle {{ font-size: 12px; color: var(--text-tertiary); margin-bottom: 22px; font-family: var(--font-mono); }}
  .info-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }}
  .info-card {{ background: var(--bg-secondary); border-radius: var(--radius-md); padding: 10px 14px; }}
  .info-label {{ font-size: 10px; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 4px; }}
  .info-value {{ font-size: 13px; font-weight: 500; }}
  .card {{ background: var(--bg-primary); border: 0.5px solid var(--border); border-radius: var(--radius-lg); padding: 14px 16px; margin-bottom: 16px; }}
  .section-title {{ font-size: 11px; font-weight: 500; color: var(--text-secondary); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 12px; }}
  .table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  .table th {{ text-align: left; color: var(--text-secondary); font-weight: 500; padding: 0 8px 8px; border-bottom: 0.5px solid var(--border); }}
  .table td {{ padding: 8px; border-bottom: 0.5px solid var(--border); vertical-align: top; }}
  .table tr:last-child td {{ border-bottom: none; }}
  .badge {{ display: inline-flex; align-items: center; font-size: 11px; padding: 3px 8px; border-radius: var(--radius-md); font-weight: 500; }}
  .badge-green {{ background: var(--bg-success); color: var(--text-success); }}
  .badge-red   {{ background: var(--bg-danger);  color: var(--text-danger); }}
  .badge-amber {{ background: var(--bg-warning); color: var(--text-warning); }}
  .badge-gray  {{ background: var(--bg-secondary); color: var(--text-secondary); }}
  .chip {{ display: inline-flex; align-items: center; font-size: 11px; padding: 2px 7px; border-radius: var(--radius-md); background: var(--bg-secondary); color: var(--text-secondary); margin-right: 4px; border: 0.5px solid var(--border); }}
  .chip-blue {{ background: rgba(55,138,221,0.15); color: var(--blue); border-color: rgba(55,138,221,0.3); }}
  .detail-layout {{ display: grid; grid-template-columns: 1fr 280px; gap: 16px; align-items: start; }}
  /* ── IA Cards ── */
  .ia-card {{ background: var(--bg-secondary); border: 0.5px solid var(--border); border-radius: var(--radius-lg); margin-bottom: 10px; overflow: hidden; }}
  .ia-card-header {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 14px; cursor: pointer; transition: background .1s; }}
  .ia-card-header:hover {{ background: rgba(255,255,255,0.03); }}
  .ia-chevron {{ font-size: 10px; color: var(--text-tertiary); transition: transform .2s; user-select: none; }}
  .ia-chevron.open {{ transform: rotate(180deg); }}
  .ia-card-body {{ padding: 0 14px 14px; border-top: 0.5px solid var(--border); }}
  .ia-section {{ margin-top: 12px; }}
  .ia-section-label {{ font-size: 10px; font-weight: 600; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 6px; }}
  .ia-text-block {{ font-size: 12px; color: var(--text-secondary); line-height: 1.6; padding: 8px 10px; background: var(--bg-primary); border-radius: var(--radius-md); border-left: 2px solid var(--blue); }}
  /* ── Tabs ── */
  .ia-tabs {{ display: flex; gap: 4px; margin-top: 14px; border-bottom: 0.5px solid var(--border); }}
  .ia-tab {{ padding: 6px 12px; font-size: 11px; font-weight: 500; background: transparent; border: none; border-bottom: 2px solid transparent; color: var(--text-tertiary); cursor: pointer; font-family: var(--font); transition: all .1s; margin-bottom: -1px; }}
  .ia-tab:hover {{ color: var(--text-secondary); }}
  .ia-tab.active {{ color: var(--text-primary); border-bottom-color: var(--blue); }}
  .ia-panel {{ margin-top: 12px; }}
  /* ── Workers ── */
  .workers-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; margin-bottom: 10px; }}
  .worker-card {{ background: var(--bg-primary); border: 0.5px solid var(--border); border-radius: var(--radius-md); padding: 10px 12px; }}
  .worker-card-failed {{ opacity: 0.5; }}
  .arbiter-card {{ background: rgba(55,138,221,0.08); border: 0.5px solid rgba(55,138,221,0.25); border-radius: var(--radius-md); padding: 12px 14px; margin-top: 8px; }}
  /* ── Timeline ── */
  .timeline-card {{ background: var(--bg-primary); border: 0.5px solid var(--border); border-radius: var(--radius-lg); padding: 14px 16px; position: sticky; top: 20px; max-height: calc(100vh - 40px); overflow-y: auto; }}
  .timeline {{ position: relative; padding-left: 20px; }}
  .tl-item {{ position: relative; padding-bottom: 14px; }}
  .tl-item::before {{ content: ''; position: absolute; left: -14px; top: 6px; width: 1px; height: 100%; background: var(--border); }}
  .tl-item:last-child::before {{ display: none; }}
  .tl-dot {{ position: absolute; left: -18px; top: 4px; width: 9px; height: 9px; border-radius: 50%; background: var(--blue); border: 2px solid var(--bg-primary); }}
  .tl-dot.green {{ background: var(--green); }}
  .tl-dot.red   {{ background: var(--red); }}
  .tl-dot.amber {{ background: var(--amber); }}
  .tl-label {{ font-size: 12px; font-weight: 500; }}
  .tl-sub {{ font-size: 11px; color: var(--text-secondary); margin-top: 2px; line-height: 1.5; word-break: break-word; }}
  /* ── JSON Modal ── */
  .modal-overlay {{ display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center; }}
  .modal-overlay.open {{ display: flex; }}
  .modal-box {{ background: var(--bg-primary); border: 0.5px solid var(--border-md); border-radius: var(--radius-lg); padding: 20px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; position: relative; }}
  .modal-close {{ position: absolute; top: 12px; right: 14px; background: none; border: none; color: var(--text-secondary); font-size: 18px; cursor: pointer; }}
  .modal-close:hover {{ color: var(--text-primary); }}
  pre.json-view {{ font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); line-height: 1.6; white-space: pre-wrap; word-break: break-all; }}
  .hidden {{ display: none !important; }}
  /* ── Scan event cards ── */
  .ev-card {{ background: var(--bg-secondary); border: 0.5px solid var(--border); border-radius: var(--radius-lg); margin-bottom: 8px; overflow: hidden; }}
  .ev-card-header {{ display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; cursor: pointer; transition: background .1s; gap: 8px; }}
  .ev-card-header:hover {{ background: rgba(255,255,255,0.03); }}
  .ev-card-body {{ padding: 12px 14px; border-top: 0.5px solid var(--border); }}
  .ev-stats {{ display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }}
  .ev-llm-summary {{ font-size: 11px; color: var(--text-success); margin-top: 10px; padding: 6px 10px; background: rgba(99,153,34,0.1); border-radius: var(--radius-md); border-left: 2px solid var(--green); line-height: 1.5; }}
  .json-btn {{ font-size: 11px; color: var(--text-secondary); background: transparent; border: 0.5px solid var(--border); border-radius: var(--radius-md); padding: 4px 10px; cursor: pointer; font-family: var(--font); }}
  .json-btn:hover {{ color: var(--text-primary); border-color: var(--border-md); }}
  /* ── Markdown rendering ── */
  .md-text {{ font-size: 12px; color: var(--text-secondary); line-height: 1.7; }}
  .md-text .md-p {{ margin-bottom: 6px; }}
  .md-text .md-p:last-child {{ margin-bottom: 0; }}
  .md-text .md-gap {{ height: 4px; }}
  .md-text .md-list {{ margin: 4px 0 8px 18px; }}
  .md-text .md-list li {{ margin-bottom: 4px; }}
  .md-text strong {{ color: var(--text-primary); font-weight: 600; }}
  .md-text em {{ font-style: italic; }}
  .md-text .inline-code {{ font-family: var(--font-mono); font-size: 0.9em; background: rgba(255,255,255,0.07); padding: 1px 4px; border-radius: 3px; color: var(--text-info); }}
  /* ── CVE list ── */
  .vuln-list {{ display: flex; flex-direction: column; gap: 5px; max-height: 400px; overflow-y: auto; padding-right: 4px; }}
  .vuln-row {{ background: var(--bg-primary); border-radius: var(--radius-md); padding: 6px 10px; border-left: 2px solid var(--border-md); }}
  .sev-critical {{ color: #f09595; font-size: 11px; font-weight: 700; }}
  .sev-high     {{ color: #fac775; font-size: 11px; font-weight: 700; }}
  .sev-medium   {{ color: #fde68a; font-size: 11px; }}
  .sev-low      {{ color: #a0c4ff; font-size: 11px; }}
  .sev-unknown  {{ color: var(--text-tertiary); font-size: 11px; }}
  /* ── Compliance findings ── */
  .finding-row {{ background: var(--bg-primary); border-radius: var(--radius-md); padding: 6px 10px; margin-bottom: 4px; }}
  .finding-fail {{ border-left: 2px solid var(--red) !important; }}
  .finding-warn {{ border-left: 2px solid var(--amber) !important; }}
  .finding-pass {{ border-left: 2px solid var(--green) !important; }}
</style>
</head>
<body>
  <a class="back" href="javascript:history.back()">← Retour</a>
  <div class="page-title">{repo}:{tag}</div>
  <div class="subtitle">Pull ID : {uuid_full}</div>

  <div class="info-grid">
    <div class="info-card"><div class="info-label">IP client</div><div class="info-value">{ip}</div></div>
    <div class="info-card"><div class="info-label">Registry</div><div class="info-value">{registry}</div></div>
    <div class="info-card"><div class="info-label">OS / Arch</div><div class="info-value">{os} / {arch}</div></div>
    <div class="info-card"><div class="info-label">Client</div><div class="info-value">{client_type}</div></div>
    <div class="info-card"><div class="info-label">Démarré</div><div class="info-value">{started}</div></div>
    <div class="info-card"><div class="info-label">Dernière activité</div><div class="info-value">{last_act}</div></div>
    <div class="info-card"><div class="info-label">Terminé</div><div class="info-value">{completed}</div></div>
    <div class="info-card"><div class="info-label">Décision finale</div>
      <div class="info-value"><span class="badge {badge}" id="decision-badge">{decision}</span></div>
    </div>
  </div>

  <div class="detail-layout">
    <div>
      <div class="card">
        <div class="section-title">Digests reçus ({nb_digests})</div>
        <table class="table">
          <thead><tr><th>Valeur</th><th>Type</th><th>Algo</th><th>Reçu</th></tr></thead>
          <tbody id="digests-tbody">{digests}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="section-title">Décisions IA ({nb_ia})</div>
        <div id="ia-container">{ia_cards}</div>
      </div>
      <div class="card">
        <div class="section-title">Scan events ({nb_events})</div>
        <div id="events-container">{events}</div>
      </div>
    </div>
    <div class="timeline-card">
      <div class="section-title">Flux des scans</div>
      <div class="timeline" id="timeline-container">{timeline}</div>
    </div>
  </div>

  <div class="modal-overlay" id="json-modal" onclick="closeJsonModal(event)">
    <div class="modal-box">
      <button class="modal-close" onclick="document.getElementById('json-modal').classList.remove('open')">✕</button>
      <div class="section-title" style="margin-bottom:12px">Réponse scanner (JSON)</div>
      <pre class="json-view" id="json-content"></pre>
    </div>
  </div>

<script>
const PULL_UUID = '{uuid_full}';

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(iaId, panel) {{
  ['scan','decision','alt'].forEach(p => {{
    const el = document.getElementById('panel-' + p + '-' + iaId);
    if (el) el.classList.add('hidden');
  }});
  const target = document.getElementById('panel-' + panel + '-' + iaId);
  if (target) target.classList.remove('hidden');
  const tabs = document.querySelectorAll('#tabs-' + iaId + ' .ia-tab');
  const panels = ['scan','decision','alt'];
  tabs.forEach((tab, i) => tab.classList.toggle('active', panels[i] === panel));
}}

// ── Collapse ──────────────────────────────────────────────────────────────────
function toggleIaCard(iaId) {{
  const body    = document.getElementById('body-' + iaId);
  const chevron = document.getElementById('chevron-' + iaId);
  if (!body) return;
  const isOpen = !body.classList.contains('hidden');
  body.classList.toggle('hidden', isOpen);
  if (chevron) chevron.classList.toggle('open', !isOpen);
}}

// Ouvrir la première carte par défaut
window.addEventListener('DOMContentLoaded', () => {{
  const first = document.querySelector('.ia-card');
  if (first) {{
    const id = first.id.replace('ia-', '');
    const body    = document.getElementById('body-' + id);
    const chevron = document.getElementById('chevron-' + id);
    if (body)    body.classList.remove('hidden');
    if (chevron) chevron.classList.add('open');
  }}
}});

// ── Collapse scan event card ──────────────────────────────────────────────────
function toggleEvCard(evId) {{
  const body    = document.getElementById('ev-body-' + evId);
  const chevron = document.getElementById('ev-chevron-' + evId);
  if (!body) return;
  const isOpen = !body.classList.contains('hidden');
  body.classList.toggle('hidden', isOpen);
  if (chevron) chevron.classList.toggle('open', !isOpen);
}}

// ── JSON Modal ────────────────────────────────────────────────────────────────
function openJsonModal(rawJson) {{
  if (!rawJson) return;
  // data-json attributes are decoded by the browser natively; only legacy
  // onclick-embedded strings need manual entity decoding.
  let str = rawJson;
  if (str.includes('&quot;') || str.includes('&#39;') || str.includes('&amp;')) {{
    str = str.replace(/&quot;/g, '"')
             .replace(/&#39;/g, "'")
             .replace(/&amp;/g, '&')
             .replace(/&lt;/g, '<')
             .replace(/&gt;/g, '>');
  }}
  try {{
    const obj = JSON.parse(str);
    document.getElementById('json-content').textContent = JSON.stringify(obj, null, 2);
  }} catch {{
    document.getElementById('json-content').textContent = str;
  }}
  document.getElementById('json-modal').classList.add('open');
}}
function closeJsonModal(e) {{
  if (e.target === document.getElementById('json-modal'))
    document.getElementById('json-modal').classList.remove('open');
}}

// ── SSE ───────────────────────────────────────────────────────────────────────
function connectSSE() {{
  const es = new EventSource('/dashboard/events');

  es.onmessage = (event) => {{
    let payload;
    try {{ payload = JSON.parse(event.data); }} catch {{ return; }}
    const {{ table, action, data }} = payload;

    const normalize = s => (s || '').toLowerCase().replace(/-/g, '');
    const myUuid = normalize(PULL_UUID);
    if (normalize(data.pull_id) !== myUuid && normalize(data.uuid) !== myUuid) return;

    if (table === 'pull_digests' && action === 'INSERT') {{
      const tbody = document.getElementById('digests-tbody');
      if (!tbody) return;
      const empty = tbody.querySelector('td[colspan]');
      if (empty) empty.parentElement.remove();
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-secondary)">${{data.digest_value}}</td>
        <td><span class="chip">${{data.digest_type || '?'}}</span></td>
        <td><span class="chip">${{data.digest_algo || '?'}}</span></td>
        <td style="color:var(--text-tertiary);font-size:11px">À l'instant</td>`;
      tbody.appendChild(tr);
      updateCount('Digests reçus', tbody.rows.length);
    }}

    if (table === 'ia_decisions' && action === 'INSERT') {{
      addIaCardFromSSE(data);
    }}

    if (table === 'scan_events' && action === 'INSERT') {{
      addScanEventFromSSE(data);
      markTimelineScannerDone(data.scanner_type, data.llm_summary);
    }}

    if (table === 'pulls' && action === 'UPDATE') {{
      const dec = data.decision_final;
      if (!dec) return;
      const cls = dec === 'ALLOW' ? 'badge-green' : dec === 'DENY' ? 'badge-red' : 'badge-amber';
      ['decision-badge'].forEach(id => {{
        const el = document.getElementById(id);
        if (el) {{ el.textContent = dec; el.className = 'badge ' + cls; }}
      }});
      const tlBadge = document.getElementById('decision-badge-tl');
      if (tlBadge) {{ tlBadge.textContent = dec; tlBadge.className = 'badge ' + cls; }}
      const tlFinal = document.getElementById('tl-final');
      if (tlFinal) {{
        const dot = tlFinal.querySelector('.tl-dot');
        if (dot) dot.className = 'tl-dot ' + (dec === 'ALLOW' ? 'green' : dec === 'DENY' ? 'red' : 'amber');
      }}
    }}
  }};

  es.onerror = () => {{ es.close(); setTimeout(connectSSE, 3000); }};
}}

function updateCount(label, count) {{
  document.querySelectorAll('.section-title').forEach(el => {{
    if (el.textContent.startsWith(label)) el.textContent = label + ' (' + count + ')';
  }});
}}

function addIaCardFromSSE(data) {{
  const container = document.getElementById('ia-container');
  if (!container) return;
  const empty = container.querySelector('div[style*="Aucune"]');
  if (empty) empty.remove();

  const score     = parseFloat(data.score || 0);
  const vulnScore = parseFloat(data.vulnerability_score || 0);
  const conf      = parseFloat(data.confidence || 0);
  const decision  = data.decision || 'PENDING';
  const badgeCls  = decision === 'ALLOW' ? 'badge-green' : decision === 'DENY' ? 'badge-red' : 'badge-amber';
  const scColor   = score > 0.75 ? 'var(--text-success)' : score > 0.4 ? 'var(--text-warning)' : 'var(--text-danger)';
  const vcColor   = vulnScore > 7 ? 'var(--text-danger)' : vulnScore > 4 ? 'var(--text-warning)' : 'var(--text-success)';

  const scanners = [];
  if (data.static_scan)     scanners.push('statique');
  if (data.compliance_scan) scanners.push('compliance');
  if (data.dynamic_scan)    scanners.push('dynamique');
  const chips = scanners.map(s => `<span class="chip chip-blue">${{s}}</span>`).join('') ||
    '<span style="color:var(--text-tertiary);font-size:11px">aucun</span>';

  const iaId = data.id || ('sse-' + Date.now());
  const card = document.createElement('div');
  card.className = 'ia-card';
  card.id = 'ia-' + iaId;
  card.innerHTML = `
    <div class="ia-card-header" onclick="toggleIaCard('${{iaId}}')">
      <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0">
        <span class="badge ${{badgeCls}}">${{decision}}</span>
        <span style="font-size:12px;color:var(--text-secondary)">À l'instant</span>
        <div style="display:flex;gap:4px;margin-left:8px">${{chips}}</div>
      </div>
      <div style="display:flex;align-items:center;gap:16px;flex-shrink:0">
        <div style="text-align:right">
          <div style="font-size:10px;color:var(--text-tertiary)">Score IA</div>
          <div style="font-size:15px;font-weight:600;color:${{scColor}}">${{score.toFixed(2)}}</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:10px;color:var(--text-tertiary)">Vuln. score</div>
          <div style="font-size:15px;font-weight:600;color:${{vcColor}}">${{vulnScore.toFixed(1)}}</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:10px;color:var(--text-tertiary)">Confiance</div>
          <div style="font-size:13px;font-weight:500;color:var(--text-secondary)">${{Math.round(conf*100)}}%</div>
        </div>
        <span class="ia-chevron open" id="chevron-${{iaId}}">▼</span>
      </div>
    </div>
    <div class="ia-card-body" id="body-${{iaId}}">
      <div class="ia-section">
        <div class="ia-section-label">Raisonnement final</div>
        <div class="ia-text-block">${{data.rationale || '—'}}</div>
      </div>
      <div style="color:var(--text-tertiary);font-size:11px;margin-top:10px;padding:8px;background:var(--bg-primary);border-radius:var(--radius-md)">
        ℹ️ Détail des workers disponible après rechargement
      </div>
    </div>`;
  container.prepend(card);
  updateTimelineFromIA(data, scanners);
  updateCount('Décisions IA', container.querySelectorAll('.ia-card').length);
}}

function addScanEventFromSSE(data) {{
  const container = document.getElementById('events-container');
  if (!container) return;
  const empty = container.querySelector('[data-empty]');
  if (empty) empty.remove();

  const scanner  = data.scanner_type || '?';
  const executed = data.executed;
  const summary  = data.llm_summary  || '';
  const evId     = data.id || ('sse-' + Date.now());

  const execBadge = executed
    ? "<span class='badge badge-green' style='font-size:10px'>Exécuté</span>"
    : "<span class='badge badge-gray'  style='font-size:10px'>Non exécuté</span>";

  const llmHtml = summary
    ? `<div class="ev-llm-summary">🤖 ${{escHtml(summary)}}</div>`
    : '';

  // response_scanner is stripped from SSE payload to stay under pg_notify limit.
  const bodyHtml = `
    <div style="color:var(--text-tertiary);font-size:12px;padding:4px 0">
      Détail complet disponible après rechargement de la page.
    </div>
    ${{llmHtml}}`;

  const card = document.createElement('div');
  card.className = 'ev-card';
  card.id = 'ev-' + evId;
  card.innerHTML = `
    <div class="ev-card-header" onclick="toggleEvCard('${{evId}}')">
      <div style="display:flex;align-items:center;gap:8px;flex:1;flex-wrap:wrap">
        <span class="chip">${{escHtml(scanner)}}</span>
        ${{execBadge}}
      </div>
      <div style="display:flex;align-items:center;gap:10px;flex-shrink:0">
        <span style="font-size:11px;color:var(--text-tertiary)">À l'instant</span>
        <span class="ia-chevron" id="ev-chevron-${{evId}}">▼</span>
      </div>
    </div>
    <div class="ev-card-body hidden" id="ev-body-${{evId}}">${{bodyHtml}}</div>`;
  container.appendChild(card);
  updateCount('Scan events', container.querySelectorAll('.ev-card').length);
}}

function escHtml(s) {{
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}}

function updateTimelineFromIA(data, scanners) {{
  const container = document.getElementById('timeline-container');
  if (!container) return;
  const decision = data.decision || 'PENDING';
  const badgeCls = decision === 'ALLOW' ? 'badge-green' : decision === 'DENY' ? 'badge-red' : 'badge-amber';
  const score    = parseFloat(data.score || 0);
  const scColor  = score > 0.75 ? 'var(--text-success)' : score > 0.4 ? 'var(--text-warning)' : 'var(--text-danger)';
  const finalStep = document.getElementById('tl-final');

  const iaItem = document.createElement('div');
  iaItem.className = 'tl-item';
  iaItem.innerHTML = `
    <div class="tl-dot blue"></div>
    <div class="tl-label">Décision IA — <span class="badge ${{badgeCls}}" style="font-size:10px;padding:2px 6px">${{decision}}</span></div>
    <div class="tl-sub">À l'instant · Score : <span style="color:${{scColor}}">${{score.toFixed(2)}}</span></div>
    <div class="tl-sub" style="margin-top:3px">Scanners : ${{scanners.join(', ') || 'aucun'}}</div>`;
  finalStep ? container.insertBefore(iaItem, finalStep) : container.appendChild(iaItem);

  scanners.forEach(name => {{
    const item = document.createElement('div');
    item.className = 'tl-item';
    item.dataset.scanner = name;
    item.innerHTML = `
      <div class="tl-dot" style="background:var(--border-md)"></div>
      <div class="tl-label" style="color:var(--text-tertiary)">Scanner : ${{name}}</div>
      <div class="tl-sub"  style="color:var(--text-tertiary)">En attente...</div>`;
    finalStep ? container.insertBefore(item, finalStep) : container.appendChild(item);
  }});
}}

function scannerMatches(scannerType, label) {{
  const t = scannerType.toLowerCase();
  switch (label) {{
    case 'statique':   return t.includes('static') || t.includes('cve') || t.includes('trivy') || t.includes('statique');
    case 'compliance': return t.includes('compliance');
    case 'dynamique':  return t.includes('dynamic') || t.includes('dynamique');
    default:           return t.includes(label);
  }}
}}

function markTimelineScannerDone(scannerType, llmSummary) {{
  if (!scannerType) return;
  document.querySelectorAll('#timeline-container .tl-item[data-scanner]').forEach(item => {{
    if (!scannerMatches(scannerType, item.dataset.scanner)) return;
    const dot   = item.querySelector('.tl-dot');
    const label = item.querySelector('.tl-label');
    const sub   = item.querySelector('.tl-sub');
    if (dot)   {{ dot.style.background = 'var(--green)'; dot.style.border = '2px solid var(--bg-primary)'; }}
    if (label) {{ label.style.color = ''; }}
    if (sub)   {{
      sub.style.color = 'var(--text-success)';
      sub.textContent = '✓ Terminé — ' + new Date().toLocaleTimeString();
    }}
    if (llmSummary) {{
      const el = document.createElement('div');
      el.style.cssText = 'font-size:10px;color:var(--text-success);margin-top:2px';
      el.textContent = llmSummary;
      item.appendChild(el);
    }}
    delete item.dataset.scanner;
  }});
}}

connectSSE();
</script>
</body>
</html>"#,
        short = &uuid[..8],
        repo = pull.repository,
        tag = pull.tag.as_deref().unwrap_or("latest"),
        uuid_full = pull.uuid,
        ip = pull.ip_client,
        registry = pull.registry,
        os = pull.os.as_deref().unwrap_or("?"),
        arch = pull.arch.as_deref().unwrap_or("?"),
        client_type = pull.client_type.as_deref().unwrap_or("?"),
        started = format_datetime(pull.started_at),
        last_act = format_datetime(pull.last_activity),
        completed = if pull.scan_completed.unwrap_or(false) {
            "Oui"
        } else {
            "Non"
        },
        badge = badge,
        decision = decision,
        nb_digests = digests.len(),
        digests = digests_html,
        nb_ia = ia_decisions.len(),
        ia_cards = ia_cards_html,
        nb_events = scan_events.len(),
        events = events_html,
        timeline = timeline_html,
    );

    Html(html).into_response()
}

// ─── API recherche pulls (autocomplétion) ─────────────────────────────────────

pub async fn search_pulls(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).is_none() {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!([]))).into_response();
    }

    let raw_q = params
        .get("q")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    if raw_q.len() < 2 {
        return (StatusCode::OK, axum::Json(serde_json::json!([]))).into_response();
    }
    let q = format!("%{}%", raw_q);

    let results = sqlx::query!(
        "SELECT uuid, repository, tag, ip_client, decision_final, started_at
         FROM pulls
         WHERE LOWER(repository) LIKE $1 OR LOWER(tag) LIKE $1 OR LOWER(ip_client) LIKE $1
         ORDER BY started_at DESC LIMIT 10",
        q
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let json: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "uuid": r.uuid.to_string(),
                "repository": r.repository,
                "tag": r.tag.as_deref().unwrap_or("latest"),
                "ip_client": r.ip_client,
                "decision": r.decision_final.as_deref().unwrap_or("PENDING"),
                "started_at": format_datetime(r.started_at),
            })
        })
        .collect();

    (StatusCode::OK, axum::Json(serde_json::json!(json))).into_response()
}

// ─── API Whitelist ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ListAddForm {
    registry: String,
    repository: String,
    tag: Option<String>,
}

pub async fn api_add_whitelist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ListAddForm>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "Non autorisé"})),
        )
            .into_response();
    }

    let exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM whitelist WHERE registry=$1 AND repository=$2 AND tag IS NOT DISTINCT FROM $3)",
        body.registry, body.repository, body.tag
    )
    .fetch_one(&state.db).await.unwrap_or(Some(false)).unwrap_or(false);

    if exists {
        return (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({"error": "Déjà présent en whitelist"})),
        )
            .into_response();
    }

    let id = uuid::Uuid::new_v4();
    match sqlx::query!(
        "INSERT INTO whitelist (id, registry, repository, tag) VALUES ($1, $2, $3, $4)",
        id,
        body.registry,
        body.repository,
        body.tag
    )
    .execute(&state.db)
    .await
    {
        Ok(_) => {
            // SBOM generation is triggered automatically by the DB trigger
            // trg_whitelist_new → pg_notify('whitelist_new') → cycle-de-vie watcher
            (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({"id": id.to_string(), "ok": true})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn api_remove_whitelist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "Non autorisé"})),
        )
            .into_response();
    }

    let uuid_parsed: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "UUID invalide"})),
            )
                .into_response()
        }
    };

    match sqlx::query!("DELETE FROM whitelist WHERE id = $1", uuid_parsed)
        .execute(&state.db)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))).into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "Entrée introuvable"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ─── API Blacklist ─────────────────────────────────────────────────────────────

pub async fn api_add_blacklist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ListAddForm>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "Non autorisé"})),
        )
            .into_response();
    }

    let exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM blacklist WHERE registry=$1 AND repository=$2 AND tag IS NOT DISTINCT FROM $3)",
        body.registry, body.repository, body.tag
    )
    .fetch_one(&state.db).await.unwrap_or(Some(false)).unwrap_or(false);

    if exists {
        return (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({"error": "Déjà présent en blacklist"})),
        )
            .into_response();
    }

    let id = uuid::Uuid::new_v4();
    match sqlx::query!(
        "INSERT INTO blacklist (id, registry, repository, tag) VALUES ($1, $2, $3, $4)",
        id,
        body.registry,
        body.repository,
        body.tag
    )
    .execute(&state.db)
    .await
    {
        Ok(_) => (
            StatusCode::CREATED,
            axum::Json(serde_json::json!({"id": id.to_string(), "ok": true})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn api_remove_blacklist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "Non autorisé"})),
        )
            .into_response();
    }

    let uuid_parsed: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "UUID invalide"})),
            )
                .into_response()
        }
    };

    match sqlx::query!("DELETE FROM blacklist WHERE id = $1", uuid_parsed)
        .execute(&state.db)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))).into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "Entrée introuvable"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ─── API Cache suppression ────────────────────────────────────────────────────

pub async fn api_delete_cache(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "Non autorisé"})),
        )
            .into_response();
    }

    let uuid_parsed: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "UUID invalide"})),
            )
                .into_response()
        }
    };

    let row = sqlx::query!("SELECT file_path FROM cache WHERE id = $1", uuid_parsed)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let file_path = row.and_then(|r| r.file_path);

    match sqlx::query!("DELETE FROM cache WHERE id = $1", uuid_parsed)
        .execute(&state.db)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            if let Some(path) = file_path {
                if let Err(e) = std::fs::remove_file(&path) {
                    eprintln!("[CACHE DELETE] Erreur filesystem {} : {}", path, e);
                }
            }
            (StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))).into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "Entrée introuvable"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
pub async fn search_pulls_dev(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("dev") {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!([]))).into_response();
    }

    let sub = match crate::auth::extract_cookie(&headers, "sub") {
        Some(s) => s,
        None => {
            return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!([]))).into_response()
        }
    };

    let allowed_ips: Vec<String> =
        sqlx::query_scalar!("SELECT allowed_ips FROM users WHERE sub = $1", sub)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None)
            .unwrap_or_default()
            .unwrap_or_default();

    let q = params
        .get("q")
        .map(|s| format!("%{}%", s.to_lowercase()))
        .unwrap_or_default();
    if q.len() < 3 || allowed_ips.is_empty() {
        return (StatusCode::OK, axum::Json(serde_json::json!([]))).into_response();
    }

    let results = sqlx::query!(
        "SELECT uuid, repository, tag, ip_client, decision_final, started_at
         FROM pulls
         WHERE ip_client = ANY($1)
           AND (LOWER(repository) LIKE $2 OR LOWER(tag) LIKE $2 OR LOWER(ip_client) LIKE $2)
         ORDER BY started_at DESC LIMIT 10",
        &allowed_ips[..],
        q
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let json: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "uuid": r.uuid.to_string(),
                "repository": r.repository,
                "tag": r.tag.as_deref().unwrap_or("latest"),
                "ip_client": r.ip_client,
                "decision": r.decision_final.as_deref().unwrap_or("PENDING"),
                "started_at": format_datetime(r.started_at),
            })
        })
        .collect();

    (StatusCode::OK, axum::Json(serde_json::json!(json))).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn build_workers_html(scan_reasoning: Option<&serde_json::Value>) -> String {
    let Some(val) = scan_reasoning else {
        return String::new();
    };
    let workers = match val.get("workers").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return String::new(),
    };
    let mut html = String::new();
    for w in workers {
        let model = w.get("model").and_then(|v| v.as_str()).unwrap_or("?");
        let status = w.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        let score = w.get("vulnerability_score").and_then(|v| v.as_f64());
        let conf = w.get("confidence").and_then(|v| v.as_f64());
        let reason = w.get("reasoning").and_then(|v| v.as_str()).unwrap_or("—");
        let is_ok = status == "ok";
        let score_color = score
            .map(|s| {
                if s > 7.0 {
                    "var(--text-danger)"
                } else if s > 4.0 {
                    "var(--text-warning)"
                } else {
                    "var(--text-success)"
                }
            })
            .unwrap_or("var(--text-tertiary)");

        html.push_str(&format!(r#"
<div class="worker-card {cls}">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
    <span style="font-size:11px;font-weight:600;color:var(--text-secondary);font-family:var(--font-mono)">{model}</span>
    <span class="badge {status_badge}">{status}</span>
  </div>
  {scores}
  {reasoning}
</div>"#,
            cls = if is_ok { "" } else { "worker-card-failed" },
            model = html_escape(model),
            status_badge = if is_ok { "badge-green" } else { "badge-red" },
            status = status,
            scores = if is_ok {
                format!(r#"<div style="display:flex;gap:12px;margin-bottom:6px">
                  <div><div style="font-size:9px;color:var(--text-tertiary)">Vuln. score</div>
                  <div style="font-size:13px;font-weight:600;color:{}">{}</div></div>
                  <div><div style="font-size:9px;color:var(--text-tertiary)">Confiance</div>
                  <div style="font-size:13px;font-weight:600;color:var(--text-secondary)">{}%</div></div>
                </div>"#,
                score_color,
                score.map(|s| format!("{:.1}", s)).unwrap_or("—".to_string()),
                conf.map(|c| format!("{}", (c * 100.0) as i32)).unwrap_or("—".to_string()),
                )
            } else { String::new() },
            reasoning = if is_ok && reason != "—" {
                format!("<div class='md-text'>{}</div>", markdown_to_html(reason))
            } else { String::new() },
        ));
    }
    html
}

fn build_arbiter_html(scan_reasoning: Option<&serde_json::Value>) -> String {
    let Some(val) = scan_reasoning else {
        return String::new();
    };
    let arbiter = match val.get("arbiter") {
        Some(a) => a,
        None => return String::new(),
    };
    let model = arbiter.get("model").and_then(|v| v.as_str()).unwrap_or("?");
    let score = arbiter
        .get("vulnerability_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let conf = arbiter
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let reason = arbiter
        .get("reasoning")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let score_color = if score > 7.0 {
        "var(--text-danger)"
    } else if score > 4.0 {
        "var(--text-warning)"
    } else {
        "var(--text-success)"
    };
    format!(
        r#"<div class="arbiter-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <span style="font-size:11px;font-weight:700;color:var(--text-primary)">⚖️ Arbitre</span>
        <span style="font-size:11px;font-family:var(--font-mono);color:var(--text-tertiary)">{model}</span>
      </div>
      <div style="display:flex;gap:16px;margin-bottom:8px">
        <div><div style="font-size:9px;color:var(--text-tertiary)">Score final</div>
        <div style="font-size:16px;font-weight:700;color:{score_color}">{score:.1}</div></div>
        <div><div style="font-size:9px;color:var(--text-tertiary)">Confiance</div>
        <div style="font-size:16px;font-weight:700;color:var(--text-secondary)">{conf_pct}%</div></div>
      </div>
      <div class="md-text">{reasoning}</div>
    </div>"#,
        model = html_escape(model),
        score_color = score_color,
        score = score,
        conf_pct = (conf * 100.0) as i32,
        reasoning = markdown_to_html(reason),
    )
}

fn build_alternatives_html(alternatives: Option<&serde_json::Value>) -> String {
    let Some(val) = alternatives else {
        return "<div style='color:var(--text-tertiary);font-size:12px'>Aucune alternative proposée</div>".to_string();
    };
    let arr = match val.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return "<div style='color:var(--text-tertiary);font-size:12px'>Aucune alternative proposée</div>".to_string(),
    };
    let mut html = "<div style='display:flex;flex-direction:column;gap:8px'>".to_string();
    for alt in arr {
        let image = alt.get("image").and_then(|v| v.as_str()).unwrap_or("?");
        let reason = alt.get("reason").and_then(|v| v.as_str()).unwrap_or("—");
        let conf = alt
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        html.push_str(&format!(r#"
<div style="background:var(--bg-secondary);border:0.5px solid var(--border);border-radius:var(--radius-md);padding:10px 12px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
    <code style="font-size:12px;color:var(--text-info)">{image}</code>
    <span style="font-size:11px;color:var(--text-secondary)">{conf_pct}% confiance</span>
  </div>
  <div style="font-size:11px;color:var(--text-secondary)">{reason}</div>
</div>"#,
            image = html_escape(image),
            conf_pct = (conf * 100.0) as i32,
            reason = html_escape(reason),
        ));
    }
    html.push_str("</div>");
    html
}

fn build_decision_workers_html(decision_metadata: Option<&serde_json::Value>) -> String {
    let Some(val) = decision_metadata else {
        return String::new();
    };
    let workers = match val.get("workers").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return String::new(),
    };
    let mut html = String::new();
    for w in workers {
        let model = w.get("model").and_then(|v| v.as_str()).unwrap_or("?");
        let status = w.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        let reason = w.get("reasoning").and_then(|v| v.as_str()).unwrap_or("—");
        let conf = w.get("confidence").and_then(|v| v.as_f64());
        let is_ok = status == "ok";

        let static_scan = w
            .get("run_static_scan")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let compliance_scan = w
            .get("run_compliance_scan")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let dynamic_scan = w
            .get("run_dynamic_scan")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let scanners_decided: Vec<&str> = [
            if static_scan { Some("statique") } else { None },
            if compliance_scan {
                Some("compliance")
            } else {
                None
            },
            if dynamic_scan {
                Some("dynamique")
            } else {
                None
            },
        ]
        .iter()
        .filter_map(|x| *x)
        .collect();

        html.push_str(&format!(r#"
<div class="worker-card {cls}">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
    <span style="font-size:11px;font-weight:600;color:var(--text-secondary);font-family:var(--font-mono)">{model}</span>
    <span class="badge {status_badge}">{status}</span>
  </div>
  {scanners_row}
  {conf_row}
  {reasoning}
</div>"#,
            cls = if is_ok { "" } else { "worker-card-failed" },
            model = html_escape(model),
            status_badge = if is_ok { "badge-green" } else { "badge-red" },
            status = status,
            scanners_row = if is_ok {
                let chips = if scanners_decided.is_empty() {
                    "<span style='color:var(--text-tertiary);font-size:11px'>aucun scanner</span>".to_string()
                } else {
                    scanners_decided.iter().map(|s| format!("<span class='chip chip-blue'>{}</span>", s)).collect()
                };
                format!("<div style='margin-bottom:6px'><span style='font-size:10px;color:var(--text-tertiary)'>Scanners choisis : </span>{}</div>", chips)
            } else { String::new() },
            conf_row = conf.map(|c| format!(
                "<div style='font-size:11px;color:var(--text-tertiary);margin-bottom:4px'>Confiance : {}%</div>",
                (c * 100.0) as i32
            )).unwrap_or_default(),
            reasoning = if is_ok && reason != "—" {
                format!("<div class='md-text'>{}</div>", markdown_to_html(reason))
            } else { String::new() },
        ));
    }
    html
}

fn build_decision_arbiter_html(decision_metadata: Option<&serde_json::Value>) -> String {
    let Some(val) = decision_metadata else {
        return String::new();
    };
    let arbiter = match val.get("arbiter") {
        Some(a) => a,
        None => return String::new(),
    };
    let model = arbiter.get("model").and_then(|v| v.as_str()).unwrap_or("?");
    let reason = arbiter
        .get("reasoning")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    format!(
        r#"<div class="arbiter-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <span style="font-size:11px;font-weight:700;color:var(--text-primary)">⚖️ Arbitre — choix des scanners</span>
        <span style="font-size:11px;font-family:var(--font-mono);color:var(--text-tertiary)">{model}</span>
      </div>
      <div class="md-text">{reasoning}</div>
    </div>"#,
        model = html_escape(model),
        reasoning = markdown_to_html(reason),
    )
}

// ─── Markdown helpers ─────────────────────────────────────────────────────────

/// Wraps paired `marker` occurrences with HTML open/close tags.
fn toggle_wrap(s: &str, marker: &str, open_tag: &str, close_tag: &str) -> String {
    let parts: Vec<&str> = s.split(marker).collect();
    if parts.len() <= 1 {
        return s.to_string();
    }
    let mut out =
        String::with_capacity(s.len() + parts.len() * (open_tag.len() + close_tag.len()) / 2);
    for (i, part) in parts.iter().enumerate() {
        out.push_str(part);
        if i < parts.len() - 1 {
            out.push_str(if i % 2 == 0 { open_tag } else { close_tag });
        }
    }
    // Odd number of markers → last open tag is unclosed
    if parts.len().is_multiple_of(2) {
        out.push_str(close_tag);
    }
    out
}

/// Applies inline markdown (bold/italic/code) to an already HTML-escaped string.
fn apply_inline_md(s: &str) -> String {
    // ** must run before * to avoid consuming doubled chars
    let s = toggle_wrap(s, "**", "<strong>", "</strong>");
    let s = toggle_wrap(&s, "*", "<em>", "</em>");
    toggle_wrap(&s, "`", "<code class='inline-code'>", "</code>")
}

/// Converts a markdown block (headings, lists, paragraphs) to safe HTML.
fn markdown_to_html(raw: &str) -> String {
    let mut html = String::with_capacity(raw.len() * 2);
    let mut in_list = false;
    let mut ordered = false;

    for raw_line in raw.lines() {
        let line = raw_line.trim();

        // Ordered list: line starts with digit(s) + ". "
        let is_ordered = line
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
            && line
                .find(". ")
                .map(|p| line[..p].chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false);
        // Bullet list: line starts with "* " or "- " (with 1–3 trailing spaces)
        let is_bullet = !is_ordered
            && (line.starts_with("* ")
                || line.starts_with("- ")
                || line.starts_with("*  ")
                || line.starts_with("-  ")
                || line.starts_with("*   ")
                || line.starts_with("-   "));

        if is_ordered || is_bullet {
            if !in_list {
                html.push_str(if is_ordered {
                    "<ol class='md-list'>"
                } else {
                    "<ul class='md-list'>"
                });
                in_list = true;
                ordered = is_ordered;
            } else if ordered != is_ordered {
                html.push_str(if ordered { "</ol>" } else { "</ul>" });
                html.push_str(if is_ordered {
                    "<ol class='md-list'>"
                } else {
                    "<ul class='md-list'>"
                });
                ordered = is_ordered;
            }
            let content = if is_ordered {
                line[line.find(". ").map(|p| p + 2).unwrap_or(0)..].trim()
            } else {
                line.trim_start_matches(['*', '-']).trim_start()
            };
            html.push_str(&format!(
                "<li>{}</li>",
                apply_inline_md(&html_escape(content))
            ));
        } else {
            if in_list {
                html.push_str(if ordered { "</ol>" } else { "</ul>" });
                in_list = false;
            }
            if line.is_empty() {
                html.push_str("<div class='md-gap'></div>");
            } else {
                html.push_str(&format!(
                    "<p class='md-p'>{}</p>",
                    apply_inline_md(&html_escape(line))
                ));
            }
        }
    }
    if in_list {
        html.push_str(if ordered { "</ol>" } else { "</ul>" });
    }
    html
}

// ─── Scan event renderers ─────────────────────────────────────────────────────

/// HL / supply-chain scanner — shows score + formatted markdown analysis.
fn render_hl_scanner(resp: &serde_json::Value) -> (String, String) {
    let score = resp.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0) as i32;
    let decision = resp.get("decision").and_then(|v| v.as_str()).unwrap_or("?");
    let raw_text = resp.get("raw_text").and_then(|v| v.as_str()).unwrap_or("");

    let (badge_cls, score_color) = match decision {
        "ALLOW" => ("badge-green", "var(--text-success)"),
        "DENY" => ("badge-red", "var(--text-danger)"),
        _ => ("badge-amber", "var(--text-warning)"),
    };
    let summary = format!(
        "<span class='badge {badge}'>{decision}</span>\
         <span style='font-size:13px;font-weight:700;color:{color}'>{score}/100</span>",
        badge = badge_cls,
        decision = html_escape(decision),
        color = score_color,
        score = score,
    );
    let body = if raw_text.is_empty() {
        "<div style='color:var(--text-tertiary);font-size:12px'>Aucun détail disponible</div>"
            .to_string()
    } else {
        format!(
            "<div class='md-text' style='padding:4px 0'>{}</div>",
            markdown_to_html(raw_text)
        )
    };
    (summary, body)
}

/// Static / CVE scanner (Trivy) — shows severity counts + CVE list.
fn render_static_scanner(resp: &serde_json::Value) -> (String, String) {
    let mut crit = 0usize;
    let mut high = 0usize;
    let mut med = 0usize;
    let mut low = 0usize;
    let mut unk = 0usize;
    let mut rows = String::new();

    if let Some(results) = resp.get("Results").and_then(|v| v.as_array()) {
        for r in results {
            if let Some(vulns) = r.get("Vulnerabilities").and_then(|v| v.as_array()) {
                for v in vulns {
                    let sev = v
                        .get("Severity")
                        .and_then(|s| s.as_str())
                        .unwrap_or("UNKNOWN");
                    let id = v
                        .get("VulnerabilityID")
                        .and_then(|s| s.as_str())
                        .unwrap_or("?");
                    let pkg = v.get("PkgName").and_then(|s| s.as_str()).unwrap_or("?");
                    let ver = v
                        .get("InstalledVersion")
                        .and_then(|s| s.as_str())
                        .unwrap_or("?");
                    let fix = v.get("FixedVersion").and_then(|s| s.as_str()).unwrap_or("");
                    let title = v.get("Title").and_then(|s| s.as_str()).unwrap_or("");
                    let (sev_cls, border) = match sev {
                        "CRITICAL" => {
                            crit += 1;
                            ("sev-critical", "var(--red)")
                        }
                        "HIGH" => {
                            high += 1;
                            ("sev-high", "var(--amber)")
                        }
                        "MEDIUM" => {
                            med += 1;
                            ("sev-medium", "#fde68a")
                        }
                        "LOW" => {
                            low += 1;
                            ("sev-low", "#a0c4ff")
                        }
                        _ => {
                            unk += 1;
                            ("sev-unknown", "var(--border-md)")
                        }
                    };
                    rows.push_str(&format!(
                        r#"<div class='vuln-row' style='border-left-color:{border}'>
  <div style='display:flex;align-items:center;gap:8px;margin-bottom:2px;flex-wrap:wrap'>
    <span class='{sev_cls}'>{sev}</span>
    <code style='font-size:11px;color:var(--text-info)'>{id}</code>
    <span style='font-size:11px;color:var(--text-secondary)'>{pkg} {ver}</span>
    {fix_span}
  </div>{title_row}
</div>"#,
                        border   = border,
                        sev_cls  = sev_cls,
                        sev      = sev,
                        id       = html_escape(id),
                        pkg      = html_escape(pkg),
                        ver      = html_escape(ver),
                        fix_span = if !fix.is_empty() {
                            format!("<span style='font-size:10px;color:var(--text-success)'>fix: {}</span>", html_escape(fix))
                        } else { String::new() },
                        title_row = if !title.is_empty() {
                            format!("<div style='font-size:11px;color:var(--text-tertiary)'>{}</div>", html_escape(title))
                        } else { String::new() },
                    ));
                }
            }
        }
    }

    let total = crit + high + med + low + unk;
    let summary = if total == 0 {
        "<span style='color:var(--text-success);font-size:12px'>✓ Aucune CVE</span>".to_string()
    } else {
        let mut parts = Vec::new();
        if crit > 0 {
            parts.push(format!(
                "<span class='sev-critical'>{} CRITICAL</span>",
                crit
            ));
        }
        if high > 0 {
            parts.push(format!("<span class='sev-high'>{} HIGH</span>", high));
        }
        if med > 0 {
            parts.push(format!("<span class='sev-medium'>{} MED</span>", med));
        }
        if low > 0 {
            parts.push(format!("<span class='sev-low'>{} LOW</span>", low));
        }
        parts.join("<span style='color:var(--border-md);margin:0 3px'>·</span>")
    };
    let body = if rows.is_empty() {
        "<div style='color:var(--text-success);font-size:12px;padding:8px 0'>✓ Aucune CVE détectée</div>".to_string()
    } else {
        format!("<div class='vuln-list'>{}</div>", rows)
    };
    (summary, body)
}

/// Compliance scanner — shows FAIL/WARN/PASS counts + findings.
fn render_compliance_scanner(resp: &serde_json::Value) -> (String, String) {
    let mut fail = 0usize;
    let mut warn = 0usize;
    let mut pass = 0usize;
    let mut rows = String::new();

    if let Some(findings) = resp.get("findings").and_then(|v| v.as_array()) {
        for f in findings {
            let status = f.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            let rule_id = f.get("rule_id").and_then(|v| v.as_str()).unwrap_or("?");
            let msg = f.get("message").and_then(|v| v.as_str()).unwrap_or("—");
            let (border_cls, color) = match status {
                "FAIL" => {
                    fail += 1;
                    ("finding-fail", "var(--text-danger)")
                }
                "WARN" => {
                    warn += 1;
                    ("finding-warn", "var(--text-warning)")
                }
                "PASS" => {
                    pass += 1;
                    ("finding-pass", "var(--text-success)")
                }
                _ => ("", "var(--text-tertiary)"),
            };
            if status != "PASS" {
                // only show non-passing findings in detail
                rows.push_str(&format!(
                    r#"<div class='finding-row {border}'>
  <div style='display:flex;align-items:center;gap:8px;margin-bottom:2px'>
    <span style='font-size:10px;font-weight:700;color:{color}'>{status}</span>
    <code style='font-size:11px;color:var(--text-secondary)'>{rule_id}</code>
  </div>
  <div style='font-size:11px;color:var(--text-tertiary)'>{msg}</div>
</div>"#,
                    border = border_cls,
                    color = color,
                    status = status,
                    rule_id = html_escape(rule_id),
                    msg = html_escape(msg),
                ));
            }
        }
    }

    let mut parts = Vec::new();
    if fail > 0 {
        parts.push(format!(
            "<span style='color:var(--text-danger)'>{} FAIL</span>",
            fail
        ));
    }
    if warn > 0 {
        parts.push(format!(
            "<span style='color:var(--text-warning)'>{} WARN</span>",
            warn
        ));
    }
    if pass > 0 {
        parts.push(format!(
            "<span style='color:var(--text-success)'>{} PASS</span>",
            pass
        ));
    }
    let summary = if parts.is_empty() {
        "<span style='color:var(--text-tertiary)'>—</span>".to_string()
    } else {
        parts.join("<span style='color:var(--border-md);margin:0 3px'>·</span>")
    };
    let body = if rows.is_empty() {
        format!("<div style='color:var(--text-success);font-size:12px;padding:8px 0'>✓ {} PASS — aucun problème détecté</div>", pass)
    } else {
        format!(
            "<div style='display:flex;flex-direction:column;gap:4px'>{}</div>",
            rows
        )
    };
    (summary, body)
}

// ─── Logo ─────────────────────────────────────────────────────────────────────

pub async fn serve_logo() -> impl IntoResponse {
    static LOGO: &[u8] = include_bytes!("../../template/logo.png");
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        LOGO,
    )
}
