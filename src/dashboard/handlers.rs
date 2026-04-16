use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response, sse::{Event, Sse}},
};
use crate::auth::{extract_role_from_cookie, AppState};
use futures::stream;
use std::convert::Infallible;
use sqlx::postgres::PgListener;
use sqlx::types::chrono;

// ─── Dashboard Dev ────────────────────────────────────────────────────────────

pub async fn dev_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
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
    ).fetch_optional(db).await.unwrap_or(None) {
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
    ).fetch_all(db).await.unwrap_or_default();

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
    ).fetch_all(db).await.unwrap_or_default();

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

pub async fn rssi_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    match extract_role_from_cookie(&headers).as_deref() {
        Some("rssi") => (),
        _ => return Redirect::to("/").into_response(),
    }

    let db = &state.db;

    // ── Métriques vue globale ─────────────────────────────────────────────────

    let pulls_actifs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pulls WHERE pull_completed = false"
    ).fetch_one(db).await.unwrap_or(0);

    let bloques_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pulls WHERE decision_final = 'DENY' AND started_at >= NOW() - INTERVAL '24 hours'"
    ).fetch_one(db).await.unwrap_or(0);

    let en_quarantaine: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM quarantine"
    ).fetch_one(db).await.unwrap_or(0);

    let en_cache: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM cache"
    ).fetch_one(db).await.unwrap_or(0);

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
    ).fetch_all(db).await.unwrap_or_default();

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
        alerts_html = "<div style='color:var(--text-tertiary);font-size:12px'>Aucune alerte</div>".to_string();
    }

    // ── Pulls actifs (vue globale + page pulls) ───────────────────────────────

    let active_pulls = sqlx::query!(
        "SELECT uuid, repository, tag, ip_client, registry, arch, client_type,
                decision_final, scan_completed, started_at
         FROM pulls WHERE scan_completed = false
         ORDER BY started_at DESC LIMIT 50"
    ).fetch_all(db).await.unwrap_or_default();

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
    ).fetch_all(db).await.unwrap_or_default();

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
              <td>
                <button class='btn btn-success' style='font-size:11px;padding:3px 8px;margin-right:4px'>Valider</button>
                <button class='btn btn-danger' style='font-size:11px;padding:3px 8px'>Rejeter</button>
              </td>
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
    ).fetch_all(db).await.unwrap_or_default();

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
    ).fetch_all(db).await.unwrap_or_default();

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
    ).fetch_all(db).await.unwrap_or_default();

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
    ).fetch_all(db).await.unwrap_or_default();

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
    State(state): State<AppState>,
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
        while let Ok(notification) = listener.recv().await {
            println!("[SSE] Notification : {}", notification.payload());
            let event = Event::default().data(notification.payload());
            return Some((Ok::<Event, Infallible>(event), listener));
        }
        None
    });

    Sse::new(event_stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

// ─── Helpers formatage ────────────────────────────────────────────────────────

fn decision_badge(decision: &str) -> &'static str {
    match decision {
        "ALLOW" => "badge-green",
        "DENY"  => "badge-red",
        _       => "badge-amber",
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
    let Some(ts) = ts else { return "—".to_string() };
    let secs = (chrono::Utc::now() - ts).num_seconds();
    if secs < 60 { format!("il y a {}s", secs) }
    else if secs < 3600 { format!("il y a {}min", secs / 60) }
    else if secs < 86400 { format!("il y a {}h", secs / 3600) }
    else { format!("il y a {}j", secs / 86400) }
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
    ).fetch_optional(db).await.unwrap_or(None) {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, "Pull introuvable").into_response(),
    };

    let digests = sqlx::query!(
        "SELECT id, digest_value, digest_type, digest_algo, received_at
         FROM pull_digests WHERE pull_id = $1 ORDER BY received_at ASC",
        uuid_parsed
    ).fetch_all(db).await.unwrap_or_default();

    let ia_decisions = sqlx::query!(
        "SELECT id, created_at, reasoning_scan_choice, decision, reasonning_decision,
                score, dynamic_scan, compliance_scan, static_scan
         FROM ia_decisions WHERE pull_id = $1 ORDER BY created_at ASC",
        uuid_parsed
    ).fetch_all(db).await.unwrap_or_default();

    let scan_events = sqlx::query!(
        "SELECT id, scanner_type, response_scanner, created_at, ia_decision_id
         FROM scan_events WHERE pull_id = $1 ORDER BY created_at ASC",
        uuid_parsed
    ).fetch_all(db).await.unwrap_or_default();

    let decision = pull.decision_final.as_deref().unwrap_or("PENDING");
    let badge = decision_badge(decision);

    // Digests
    let mut digests_html = String::new();
    for d in &digests {
        digests_html.push_str(&format!(
            "<tr><td style='font-family:var(--font-mono);font-size:11px;color:var(--text-secondary)'>{}</td>
              <td><span class='chip'>{}</span></td>
              <td><span class='chip'>{}</span></td>
              <td style='color:var(--text-tertiary);font-size:11px'>{}</td></tr>",
            d.digest_value,
            d.digest_type.as_deref().unwrap_or("?"),
            d.digest_algo.as_deref().unwrap_or("?"),
            format_since(d.received_at)
        ));
    }
    if digests_html.is_empty() {
        digests_html = "<tr><td colspan='4' style='color:var(--text-tertiary);text-align:center;padding:16px'>Aucun digest</td></tr>".to_string();
    }

    // Timeline scanners depuis ia_decisions + scan_events
    let mut timeline_html = String::new();
    for ia in &ia_decisions {
        let score = ia.score.unwrap_or(0.0);
        let score_color = if score > 0.75 { "var(--text-success)" } else if score > 0.4 { "var(--text-warning)" } else { "var(--text-danger)" };
        let scanners_planned: Vec<&str> = [
            if ia.static_scan.unwrap_or(false) { Some("statique") } else { None },
            if ia.compliance_scan.unwrap_or(false) { Some("compliance") } else { None },
            if ia.dynamic_scan.unwrap_or(false) { Some("dynamique") } else { None },
        ].iter().filter_map(|x| *x).collect();

        // IA decision step
        timeline_html.push_str(&format!(
            "<div class='tl-item'>
              <div class='tl-dot blue'></div>
              <div class='tl-label'>Décision IA</div>
              <div class='tl-sub'>{} · Score : <span style='color:{}'>{:.2}</span> · Scanners : {}</div>
            </div>",
            format_since(ia.created_at),
            score_color, score,
            if scanners_planned.is_empty() { "aucun".to_string() } else { scanners_planned.join(", ") }
        ));

        // Pour chaque scanner planifié, chercher s'il a un scan_event correspondant
        let scanner_types = [
            ("statique", ia.static_scan.unwrap_or(false)),
            ("compliance", ia.compliance_scan.unwrap_or(false)),
            ("dynamique", ia.dynamic_scan.unwrap_or(false)),
        ];

        for (scanner_name, planned) in &scanner_types {
            if !planned { continue; }

            let done_event = scan_events.iter().find(|ev| {
                ev.scanner_type.as_deref().map(|t| t.to_lowercase().contains(scanner_name)).unwrap_or(false)
                && ev.ia_decision_id == Some(ia.id)
            });

            if let Some(ev) = done_event {
                let resp_preview = ev.response_scanner.as_ref()
                    .map(|v| { let s = v.to_string(); if s.len() > 60 { format!("{}...", &s[..60]) } else { s } })
                    .unwrap_or_else(|| "—".to_string());
                timeline_html.push_str(&format!(
                    "<div class='tl-item'>
                      <div class='tl-dot green'></div>
                      <div class='tl-label'>Scanner : {}</div>
                      <div class='tl-sub'>{} · <span style='color:var(--text-success)'>Terminé</span> · {}</div>
                    </div>",
                    scanner_name, format_since(ev.created_at), resp_preview
                ));
            } else {
                // FIX: ajout de data-scanner pour que le JS puisse mettre à jour en temps réel
                timeline_html.push_str(&format!(
                    "<div class='tl-item' data-scanner='{}'>
                      <div class='tl-dot' style='background:var(--border-md)'></div>
                      <div class='tl-label' style='color:var(--text-tertiary)'>Scanner : {}</div>
                      <div class='tl-sub' style='color:var(--text-tertiary)'>En attente...</div>
                    </div>",
                    scanner_name, scanner_name
                ));
            }
        }
    }

    if timeline_html.is_empty() {
        timeline_html = "<div style='color:var(--text-tertiary);font-size:12px;padding:12px'>Aucune décision IA enregistrée</div>".to_string();
    }

    // Scan events (tableau détaillé avec bouton JSON)
    let mut events_html = String::new();
    for ev in &scan_events {
        let resp_json = ev.response_scanner.as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string());
        let resp_escaped = resp_json.replace('\\', "\\\\").replace('"', "&quot;").replace('\'', "\\'");
        let resp_preview = if resp_json.len() > 60 { format!("{}...", &resp_json[..60]) } else { resp_json.clone() };
        events_html.push_str(&format!(
            "<tr>
              <td><span class='chip'>{}</span></td>
              <td style='font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);max-width:240px;overflow:hidden;white-space:nowrap;cursor:pointer'
                  onclick=\"openJsonModal('{}')\" title='Cliquer pour voir le JSON complet'>{}</td>
              <td style='color:var(--text-tertiary);font-size:11px'>{}</td>
            </tr>",
            ev.scanner_type.as_deref().unwrap_or("?"),
            resp_escaped,
            resp_preview,
            format_since(ev.created_at)
        ));
    }
    if events_html.is_empty() {
        events_html = "<tr><td colspan='3' style='color:var(--text-tertiary);text-align:center;padding:16px'>Aucun scan event</td></tr>".to_string();
    }

    // IA decisions (tableau)
    let mut ia_html = String::new();
    for ia in &ia_decisions {
        let score = ia.score.unwrap_or(0.0);
        let score_color = if score > 0.75 { "var(--text-success)" } else if score > 0.4 { "var(--text-warning)" } else { "var(--text-danger)" };
        ia_html.push_str(&format!(
            "<tr>
              <td style='font-family:var(--font-mono);font-size:11px;color:var(--text-tertiary)'>{}</td>
              <td style='color:{};font-weight:500'>{:.2}</td>
              <td><span class='chip'>{}</span><span class='chip'>{}</span><span class='chip'>{}</span></td>
              <td style='color:var(--text-tertiary);font-size:11px'>{}</td>
            </tr>",
            &ia.id.to_string()[..8],
            score_color, score,
            if ia.static_scan.unwrap_or(false) { "statique" } else { "" },
            if ia.compliance_scan.unwrap_or(false) { "compliance" } else { "" },
            if ia.dynamic_scan.unwrap_or(false) { "dynamique" } else { "" },
            format_since(ia.created_at)
        ));
    }
    if ia_html.is_empty() {
        ia_html = "<tr><td colspan='4' style='color:var(--text-tertiary);text-align:center;padding:16px'>Aucune décision IA</td></tr>".to_string();
    }

    let _uuid_str = uuid.clone();

    // FIX: layout inversé — tableaux à gauche, timeline à droite
    let html = format!(r#"<!DOCTYPE html>
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
  .table td {{ padding: 8px; border-bottom: 0.5px solid var(--border); vertical-align: middle; }}
  .table tr:last-child td {{ border-bottom: none; }}
  .badge {{ display: inline-flex; align-items: center; font-size: 11px; padding: 3px 8px; border-radius: var(--radius-md); font-weight: 500; }}
  .badge-green {{ background: var(--bg-success); color: var(--text-success); }}
  .badge-red {{ background: var(--bg-danger); color: var(--text-danger); }}
  .badge-amber {{ background: var(--bg-warning); color: var(--text-warning); }}
  .chip {{ display: inline-flex; align-items: center; font-size: 11px; padding: 2px 7px; border-radius: var(--radius-md); background: var(--bg-secondary); color: var(--text-secondary); margin-right: 4px; border: 0.5px solid var(--border); }}
  /* FIX: Layout inversé — tableaux à gauche (flex:1), timeline à droite (260px fixe) */
  .detail-layout {{ display: grid; grid-template-columns: 1fr 260px; gap: 16px; align-items: start; }}
  /* Timeline */
  .timeline-card {{ background: var(--bg-primary); border: 0.5px solid var(--border); border-radius: var(--radius-lg); padding: 14px 16px; position: sticky; top: 0; }}
  .timeline {{ position: relative; padding-left: 20px; }}
  .tl-item {{ position: relative; padding-bottom: 14px; }}
  .tl-item::before {{ content: ''; position: absolute; left: -14px; top: 6px; width: 1px; height: 100%; background: var(--border); }}
  .tl-item:last-child::before {{ display: none; }}
  .tl-dot {{ position: absolute; left: -18px; top: 4px; width: 9px; height: 9px; border-radius: 50%; background: var(--blue); border: 2px solid var(--bg-primary); }}
  .tl-dot.green {{ background: var(--green); }}
  .tl-dot.red {{ background: var(--red); }}
  .tl-dot.amber {{ background: var(--amber); }}
  .tl-label {{ font-size: 12px; font-weight: 500; }}
  .tl-sub {{ font-size: 11px; color: var(--text-secondary); margin-top: 2px; line-height: 1.5; }}
  /* JSON Modal */
  .modal-overlay {{ display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center; }}
  .modal-overlay.open {{ display: flex; }}
  .modal-box {{ background: var(--bg-primary); border: 0.5px solid var(--border-md); border-radius: var(--radius-lg); padding: 20px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; position: relative; }}
  .modal-close {{ position: absolute; top: 12px; right: 14px; background: none; border: none; color: var(--text-secondary); font-size: 18px; cursor: pointer; }}
  .modal-close:hover {{ color: var(--text-primary); }}
  pre.json-view {{ font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); line-height: 1.6; white-space: pre-wrap; word-break: break-all; }}
</style>
</head>
<body>
  <a class="back" href="/dashboard/rssi">← Retour au dashboard</a>
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
    <div class="info-card"><div class="info-label">Décision finale</div><div class="info-value"><span class="badge {badge}" id="decision-badge">{decision}</span></div></div>
  </div>

  <!-- FIX: layout inversé : tableaux à gauche, timeline à droite -->
  <div class="detail-layout">
    <!-- Colonne gauche : tableaux -->
    <div>
      <div class="card">
        <div class="section-title">Digests reçus ({nb_digests} digests)</div>
        <table class="table">
          <thead><tr><th>Valeur</th><th>Type</th><th>Algo</th><th>Reçu</th></tr></thead>
          <tbody id="digests-tbody">{digests}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="section-title">Décisions IA ({nb_ia} décisions)</div>
        <table class="table">
          <thead><tr><th>ID</th><th>Score</th><th>Scanners</th><th>Créé</th></tr></thead>
          <tbody id="ia-tbody">{ia}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="section-title">Scan events ({nb_events} events) — cliquer sur la réponse pour voir le JSON</div>
        <table class="table">
          <thead><tr><th>Scanner</th><th>Réponse (cliquer)</th><th>Créé</th></tr></thead>
          <tbody id="events-tbody">{events}</tbody>
        </table>
      </div>
    </div>

    <!-- FIX: Colonne droite : timeline -->
    <div class="timeline-card">
      <div class="section-title">Flux des scans</div>
      <div class="timeline" id="timeline-container">{timeline}</div>
    </div>
  </div>

  <!-- JSON Modal -->
  <div class="modal-overlay" id="json-modal" onclick="closeJsonModal(event)">
    <div class="modal-box">
      <button class="modal-close" onclick="document.getElementById('json-modal').classList.remove('open')">✕</button>
      <div class="section-title" style="margin-bottom:12px">Réponse scanner (JSON)</div>
      <pre class="json-view" id="json-content"></pre>
    </div>
  </div>

<script>
const PULL_UUID = '{uuid_full}';

// ── JSON Modal ────────────────────────────────────────────────────────────────
function openJsonModal(rawJson) {{
  try {{
    const obj = JSON.parse(rawJson.replace(/&quot;/g, '"'));
    document.getElementById('json-content').textContent = JSON.stringify(obj, null, 2);
  }} catch {{
    document.getElementById('json-content').textContent = rawJson.replace(/&quot;/g, '"');
  }}
  document.getElementById('json-modal').classList.add('open');
}}

function closeJsonModal(e) {{
  if (e.target === document.getElementById('json-modal')) {{
    document.getElementById('json-modal').classList.remove('open');
  }}
}}

// ── SSE pour mise à jour temps réel ──────────────────────────────────────────
function connectSSE() {{
  const es = new EventSource('/dashboard/events');

  es.onmessage = (event) => {{
    let payload;
    try {{ payload = JSON.parse(event.data); }} catch {{ return; }}
    const {{ table, action, data }} = payload;

    // On ne traite que les événements liés à CE pull
    if (data.pull_id !== PULL_UUID && data.uuid !== PULL_UUID) return;

    if (table === 'pull_digests' && action === 'INSERT') {{
      const tbody = document.getElementById('digests-tbody');
      if (!tbody) return;
      const row = document.createElement('tr');
      row.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-secondary)">${{data.digest_value}}</td>
        <td><span class="chip">${{data.digest_type || '?'}}</span></td>
        <td><span class="chip">${{data.digest_algo || '?'}}</span></td>
        <td style="color:var(--text-tertiary);font-size:11px">À l'instant</td>`;
      const empty = tbody.querySelector('td[colspan]');
      if (empty) empty.parentElement.remove();
      tbody.appendChild(row);
      updateSectionCount('digests-tbody', 'Digests reçus', 'digests');
    }}

    // FIX: mise à jour temps réel de la timeline lors d'une décision IA
    if (table === 'ia_decisions' && action === 'INSERT') {{
      const tbody = document.getElementById('ia-tbody');
      if (!tbody) return;
      const score = parseFloat(data.score || 0);
      const scoreColor = score > 0.75 ? 'var(--text-success)' : score > 0.4 ? 'var(--text-warning)' : 'var(--text-danger)';
      const row = document.createElement('tr');
      row.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-tertiary)">${{(data.id||'').substring(0,8)}}</td>
        <td style="color:${{scoreColor}};font-weight:500">${{score.toFixed(2)}}</td>
        <td>
          ${{data.static_scan ? "<span class='chip'>statique</span>" : ''}}
          ${{data.compliance_scan ? "<span class='chip'>compliance</span>" : ''}}
          ${{data.dynamic_scan ? "<span class='chip'>dynamique</span>" : ''}}
        </td>
        <td style="color:var(--text-tertiary);font-size:11px">À l'instant</td>`;
      const empty = tbody.querySelector('td[colspan]');
      if (empty) empty.parentElement.remove();
      tbody.appendChild(row);
      updateSectionCount('ia-tbody', 'Décisions IA', 'ia');
      // FIX: mettre à jour la timeline avec les scanners planifiés (grisés)
      updateTimelineFromIA(data);
    }}

    // FIX: mise à jour temps réel de la timeline lors de la réception d'un scan event
    if (table === 'scan_events' && action === 'INSERT') {{
      const tbody = document.getElementById('events-tbody');
      if (!tbody) return;
      const resp = data.response_scanner ? JSON.stringify(data.response_scanner) : '—';
      const preview = resp.length > 60 ? resp.substring(0, 60) + '...' : resp;
      const row = document.createElement('tr');
      row.innerHTML = `
        <td><span class="chip">${{data.scanner_type || '?'}}</span></td>
        <td style="font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);max-width:240px;overflow:hidden;white-space:nowrap;cursor:pointer"
            onclick="openJsonModal('${{resp.replace(/'/g, "\\'")}}')" title="Cliquer pour voir le JSON">${{preview}}</td>
        <td style="color:var(--text-tertiary);font-size:11px">À l'instant</td>`;
      const empty = tbody.querySelector('td[colspan]');
      if (empty) empty.parentElement.remove();
      tbody.appendChild(row);
      updateSectionCount('events-tbody', 'Scan events', 'events');
      // FIX: colorier le scanner correspondant dans la timeline (scan terminé)
      markTimelineScannerDone(data.scanner_type);
    }}

    if (table === 'pulls' && action === 'UPDATE') {{
      const decEl = document.getElementById('decision-badge');
      if (decEl && data.decision_final) {{
        decEl.textContent = data.decision_final;
        decEl.className = 'badge ' + (data.decision_final === 'ALLOW' ? 'badge-green' : data.decision_final === 'DENY' ? 'badge-red' : 'badge-amber');
      }}
    }}
  }};

  es.onerror = () => {{ es.close(); setTimeout(connectSSE, 3010); }};
}}

function updateSectionCount(tbodyId, label, key) {{
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const count = tbody.rows.length;
  const card = tbody.closest('.card');
  if (card) {{
    const title = card.querySelector('.section-title');
    if (title && title.textContent.includes(label)) {{
      title.textContent = `${{label}} (${{count}} ${{key}})`;
    }}
  }}
}}

// FIX: ajoute un step IA + les scanners planifiés (grisés) dans la timeline à droite
function updateTimelineFromIA(data) {{
  const container = document.getElementById('timeline-container');
  if (!container) return;
  const score = parseFloat(data.score || 0);
  const scoreColor = score > 0.75 ? 'var(--text-success)' : score > 0.4 ? 'var(--text-warning)' : 'var(--text-danger)';
  const scanners = [];
  if (data.static_scan) scanners.push('statique');
  if (data.compliance_scan) scanners.push('compliance');
  if (data.dynamic_scan) scanners.push('dynamique');

  // Retirer le message vide si présent
  const emptyMsg = container.querySelector('div[style*="color:var(--text-tertiary)"]');
  if (emptyMsg && !emptyMsg.classList.contains('tl-item')) emptyMsg.remove();

  // Ajouter l'étape IA
  const iaItem = document.createElement('div');
  iaItem.className = 'tl-item';
  iaItem.innerHTML = `
    <div class="tl-dot blue"></div>
    <div class="tl-label">Décision IA</div>
    <div class="tl-sub">À l'instant · Score : <span style="color:${{scoreColor}}">${{score.toFixed(2)}}</span> · Scanners : ${{scanners.join(', ') || 'aucun'}}</div>`;
  container.appendChild(iaItem);

  // Ajouter les scanners planifiés en grisé avec data-scanner pour mise à jour ultérieure
  scanners.forEach(name => {{
    const item = document.createElement('div');
    item.className = 'tl-item';
    item.dataset.scanner = name;
    item.innerHTML = `
      <div class="tl-dot" style="background:var(--border-md)"></div>
      <div class="tl-label" style="color:var(--text-tertiary)">Scanner : ${{name}}</div>
      <div class="tl-sub" style="color:var(--text-tertiary)">En attente...</div>`;
    container.appendChild(item);
  }});
}}

// FIX: colorie le step scanner dans la timeline quand le scan event arrive
function markTimelineScannerDone(scannerType) {{
  if (!scannerType) return;
  const container = document.getElementById('timeline-container');
  if (!container) return;
  const items = container.querySelectorAll('.tl-item[data-scanner]');
  items.forEach(item => {{
    if (scannerType.toLowerCase().includes(item.dataset.scanner)) {{
      const dot = item.querySelector('.tl-dot');
      const label = item.querySelector('.tl-label');
      const sub = item.querySelector('.tl-sub');
      if (dot) {{ dot.style.background = 'var(--green)'; dot.style.border = '2px solid var(--bg-primary)'; }}
      if (label) {{ label.style.color = ''; label.textContent = `Scanner : ${{item.dataset.scanner}}`; }}
      if (sub) {{ sub.style.color = 'var(--text-success)'; sub.textContent = 'Terminé — ' + new Date().toLocaleTimeString(); }}
    }}
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
        completed = if pull.scan_completed.unwrap_or(false) { "Oui" } else { "Non" },
        badge = badge,
        decision = decision,
        timeline = timeline_html,
        nb_digests = digests.len(),
        digests = digests_html,
        nb_ia = ia_decisions.len(),
        ia = ia_html,
        nb_events = scan_events.len(),
        events = events_html,
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

    let q = params.get("q").map(|s| format!("%{}%", s.to_lowercase())).unwrap_or_default();
    if q.len() < 3 {
        return (StatusCode::OK, axum::Json(serde_json::json!([]))).into_response();
    }

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

    let json: Vec<serde_json::Value> = results.iter().map(|r| serde_json::json!({
        "uuid": r.uuid.to_string(),
        "repository": r.repository,
        "tag": r.tag.as_deref().unwrap_or("latest"),
        "ip_client": r.ip_client,
        "decision": r.decision_final.as_deref().unwrap_or("PENDING"),
        "started_at": format_datetime(r.started_at),
    })).collect();

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
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error": "Non autorisé"}))).into_response();
    }

    let exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM whitelist WHERE registry=$1 AND repository=$2 AND tag IS NOT DISTINCT FROM $3)",
        body.registry, body.repository, body.tag
    )
    .fetch_one(&state.db).await.unwrap_or(Some(false)).unwrap_or(false);

    if exists {
        return (StatusCode::CONFLICT, axum::Json(serde_json::json!({"error": "Déjà présent en whitelist"}))).into_response();
    }

    let id = uuid::Uuid::new_v4();
    match sqlx::query!(
        "INSERT INTO whitelist (id, registry, repository, tag) VALUES ($1, $2, $3, $4)",
        id, body.registry, body.repository, body.tag
    ).execute(&state.db).await {
        Ok(_) => (StatusCode::CREATED, axum::Json(serde_json::json!({"id": id.to_string(), "ok": true}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

pub async fn api_remove_whitelist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error": "Non autorisé"}))).into_response();
    }

    let uuid_parsed: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "UUID invalide"}))).into_response(),
    };

    match sqlx::query!("DELETE FROM whitelist WHERE id = $1", uuid_parsed)
        .execute(&state.db).await {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"error": "Entrée introuvable"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

// ─── API Blacklist ─────────────────────────────────────────────────────────────

pub async fn api_add_blacklist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ListAddForm>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error": "Non autorisé"}))).into_response();
    }

    let exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM blacklist WHERE registry=$1 AND repository=$2 AND tag IS NOT DISTINCT FROM $3)",
        body.registry, body.repository, body.tag
    )
    .fetch_one(&state.db).await.unwrap_or(Some(false)).unwrap_or(false);

    if exists {
        return (StatusCode::CONFLICT, axum::Json(serde_json::json!({"error": "Déjà présent en blacklist"}))).into_response();
    }

    let id = uuid::Uuid::new_v4();
    match sqlx::query!(
        "INSERT INTO blacklist (id, registry, repository, tag) VALUES ($1, $2, $3, $4)",
        id, body.registry, body.repository, body.tag
    ).execute(&state.db).await {
        Ok(_) => (StatusCode::CREATED, axum::Json(serde_json::json!({"id": id.to_string(), "ok": true}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

pub async fn api_remove_blacklist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error": "Non autorisé"}))).into_response();
    }

    let uuid_parsed: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "UUID invalide"}))).into_response(),
    };

    match sqlx::query!("DELETE FROM blacklist WHERE id = $1", uuid_parsed)
        .execute(&state.db).await {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"error": "Entrée introuvable"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

// ─── API Cache suppression ────────────────────────────────────────────────────

pub async fn api_delete_cache(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if extract_role_from_cookie(&headers).as_deref() != Some("rssi") {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error": "Non autorisé"}))).into_response();
    }

    let uuid_parsed: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "UUID invalide"}))).into_response(),
    };

    let row = sqlx::query!(
        "SELECT file_path FROM cache WHERE id = $1",
        uuid_parsed
    ).fetch_optional(&state.db).await.unwrap_or(None);

    let file_path = row.and_then(|r| r.file_path);

    match sqlx::query!("DELETE FROM cache WHERE id = $1", uuid_parsed)
        .execute(&state.db).await {
        Ok(r) if r.rows_affected() > 0 => {
            if let Some(path) = file_path {
                if let Err(e) = std::fs::remove_file(&path) {
                    eprintln!("[CACHE DELETE] Erreur filesystem {} : {}", path, e);
                }
            }
            (StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))).into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"error": "Entrée introuvable"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({"error": e.to_string()}))).into_response(),
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
        None => return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!([]))).into_response(),
    };

    let allowed_ips: Vec<String> = sqlx::query_scalar!(
        "SELECT allowed_ips FROM users WHERE sub = $1",
        sub
    )
    .fetch_optional(&state.db).await.unwrap_or(None)
    .unwrap_or_default()
    .unwrap_or_default();

    let q = params.get("q").map(|s| format!("%{}%", s.to_lowercase())).unwrap_or_default();
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

    let json: Vec<serde_json::Value> = results.iter().map(|r| serde_json::json!({
        "uuid": r.uuid.to_string(),
        "repository": r.repository,
        "tag": r.tag.as_deref().unwrap_or("latest"),
        "ip_client": r.ip_client,
        "decision": r.decision_final.as_deref().unwrap_or("PENDING"),
        "started_at": format_datetime(r.started_at),
    })).collect();

    (StatusCode::OK, axum::Json(serde_json::json!(json))).into_response()
}

