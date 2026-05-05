use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::oneshot;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    http: Client,
    quarantine_base: String,
    cache_base: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Phase {
    Initial,
    Final,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct PullContext {
    pull_id: Uuid,
    phase: Phase,
    ip_client: String,
    registry: String,
    repository: String,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    arch: Option<String>,
    #[serde(default)]
    client_type: Option<String>,
    #[serde(default)]
    digests: Vec<DigestInput>,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DigestInput {
    digest_value: String,
    #[serde(default)]
    digest_type: Option<String>,
    #[serde(default)]
    digest_algo: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct HighLevelDigest {
    algorithm: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct HighLevelPullContext {
    uuid: Uuid,
    ip_client: String,
    registry: String,
    repository: String,
    tag: String,
    manifest_digests: Vec<HighLevelDigest>,
    blob_digests: Vec<HighLevelDigest>,
    referrers_digests: Vec<HighLevelDigest>,
    manifest_racine_digest: Option<HighLevelDigest>,
    digests_possible: Vec<HighLevelDigest>,
    digests_expected: Vec<HighLevelDigest>,
    os: String,
    arch: String,
    pull_completed: bool,
    scan_final_done: bool,
    in_whitelist: Option<bool>,
    in_blacklist: Option<bool>,
    in_cache: Option<bool>,
    check_if_verify_digest_completed: bool,
    scan_status: Option<String>,
    client_type: String,
}

#[derive(Debug, Deserialize)]
struct HighLevelServiceResponse {
    #[allow(dead_code)]
    pull_id: Uuid,
    opinion: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
struct ProxyDigest {
    algorithm: String,
    value: String,
}

impl ProxyDigest {
    fn as_prefixed(&self) -> String {
        format!("{}:{}", self.algorithm, self.value)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ProxyPullContext {
    uuid: Uuid,
    ip_client: String,
    registry: String,
    repository: String,
    tag: String,

    #[serde(default)]
    manifest_digests: Vec<ProxyDigest>,
    #[serde(default)]
    blob_digests: Vec<ProxyDigest>,
    #[serde(default)]
    referrers_digests: Vec<ProxyDigest>,

    #[serde(default)]
    manifest_racine_digest: Option<ProxyDigest>,
    #[serde(default)]
    digests_possible: Vec<ProxyDigest>,
    #[serde(default)]
    digests_expected: Vec<ProxyDigest>,

    os: String,
    arch: String,

    pull_completed: bool,
    scan_final_done: bool,
    #[serde(default)]
    in_whitelist: Option<bool>,
    #[serde(default)]
    in_blacklist: Option<bool>,
    #[serde(default)]
    in_cache: Option<bool>,
    check_if_verify_digest_completed: bool,
    #[serde(default)]
    scan_status: Option<String>,
    client_type: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    database: &'static str,
}

#[derive(Debug, Serialize)]
struct DecisionResponse {
    decision: String,
}

#[derive(Debug, Serialize)]
struct LegacyOrchestratorResponse {
    pull_id: Uuid,
    state: String,
}

#[derive(Debug, Serialize)]
struct DecisionStatusResponse {
    pull_id: Uuid,
    scan_completed: bool,
    decision: String,
    started_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct ScannerCallbackPayload {
    pull_id: Uuid,
    #[serde(default)]
    response_scanner: Value,
}

#[derive(Debug, Clone)]
struct AttachmentData {
    field_name: String,
    file_name: Option<String>,
    content_type: Option<String>,
    bytes: Bytes,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Modern,
    LegacyProxy,
}

struct PendingDecisionTask {
    pool: PgPool,
    http: Client,
    pull_id: Uuid,
    ia_id: Uuid,
    registry: String,
    repository: String,
    tag: String,
    digests: Vec<DigestInput>,
    raw_context_bytes: Bytes,
    attachments: Vec<AttachmentData>,
    llm_url: String,
    quarantine_base: String,
    cache_base: String,
    tx: oneshot::Sender<String>,
}

#[derive(Debug)]
struct HighLevelResult {
    state: String,
    reasoning_lines: Vec<String>,
    raw_text: String,
    score: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://docdockgo_admin:docdockgo@127.0.0.1:5432/docdockgo".to_string()
    });

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let quarantine_base = env::var("QUARANTINE_BASE").unwrap_or_else(|_| "./quarantaine".to_string());
    let cache_base = env::var("CACHE_BASE").unwrap_or_else(|_| "./cache".to_string());

    info!("========== Démarrage orchestrateur DockDockGo ==========");
    info!("BIND_ADDR={}", bind_addr);
    info!("QUARANTINE_BASE={}", quarantine_base);
    info!("CACHE_BASE={}", cache_base);
    info!("DATABASE_URL={}", mask_database_url(&database_url));

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    info!("[DB] Connexion PostgreSQL OK");

    let http = Client::builder().build()?;
    let state = Arc::new(AppState { pool, http, quarantine_base, cache_base });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/decision", post(decision))
        .route("/v1/decision/:pull_id", get(get_decision))
        .route("/v1/scanners/:scanner_type/callback", post(scanner_callback))
        .with_state(state)
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024))
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = bind_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("✅ Orchestrateur en écoute sur http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing() {
    let filter = env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=info".to_string());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();
}

fn mask_database_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(proto_pos) = url.find("://") {
            let prefix = &url[..proto_pos + 3];
            let suffix = &url[at_pos..];
            return format!("{}***:***{}", prefix, suffix);
        }
    }

    "<hidden>".to_string()
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    info!("GET /health reçu");

    let db_ok = sqlx::query("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();

    info!("Healthcheck DB: {}", if db_ok { "ok" } else { "error" });

    let body = HealthResponse {
        status: "ok",
        database: if db_ok { "ok" } else { "error" },
    };

    let status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(body))
}

async fn decision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response, AppError> {
    info!("POST /v1/decision reçu");
    debug!("Headers reçus: {:#?}", headers);

    handle_multipart_decision(&state, headers, multipart).await
}

async fn handle_multipart_decision(
    state: &Arc<AppState>,
    _headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    info!("========== Nouvelle décision ==========");

    let mut modern_pullcontext: Option<PullContext> = None;
    let mut legacy_context: Option<ProxyPullContext> = None;
    let mut raw_context_bytes: Option<Bytes> = None;
    let mut attachments: Vec<AttachmentData> = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(e.into()))?
    {
        let name = field.name().unwrap_or("").trim().to_string();
        let file_name = field.file_name().map(|s| s.to_string());
        let content_type = field.content_type().map(|s| s.to_string());

        let bytes = field
            .bytes()
            .await
            .map_err(|e| AppError::bad_request(e.into()))?;

        info!(
            "Champ multipart reçu: name='{}', file_name={:?}, content_type={:?}, size={} bytes",
            name,
            file_name,
            content_type,
            bytes.len()
        );

        match name.as_str() {
            "pullcontext" => {
                let raw = String::from_utf8_lossy(&bytes);
                debug!("Raw pullcontext JSON: {}", raw);

                let parsed: PullContext =
                    serde_json::from_slice(&bytes).map_err(|e| AppError::bad_request(e.into()))?;

                info!("PullContext moderne reçu: {:#?}", parsed);
                raw_context_bytes = Some(bytes);
                modern_pullcontext = Some(parsed);
            }
            "context" => {
                let raw = String::from_utf8_lossy(&bytes);
                debug!("Raw legacy context JSON: {}", raw);

                let parsed: ProxyPullContext =
                    serde_json::from_slice(&bytes).map_err(|e| AppError::bad_request(e.into()))?;

                info!("ProxyPullContext legacy reçu: {:#?}", parsed);
                raw_context_bytes = Some(bytes);
                legacy_context = Some(parsed);
            }
            _ => {
                info!(
                    "Pièce jointe reçue: field={}, filename={:?}, content_type={:?}, size={} bytes",
                    name,
                    file_name,
                    content_type,
                    bytes.len()
                );

                attachments.push(AttachmentData {
                    field_name: name,
                    file_name,
                    content_type,
                    bytes,
                });
            }
        }
    }

    info!("Nombre de pièces jointes: {}", attachments.len());

    let (pullcontext, input_mode) = if let Some(pc) = modern_pullcontext {
        (pc, InputMode::Modern)
    } else if let Some(proxy_ctx) = legacy_context {
        info!("Conversion ProxyPullContext -> PullContext");
        (convert_proxy_context(proxy_ctx), InputMode::LegacyProxy)
    } else {
        return Err(AppError::bad_request(anyhow::anyhow!(
            "missing multipart field 'pullcontext' or 'context'"
        )));
    };

    let raw_context_bytes = raw_context_bytes.unwrap_or_default();

    info!("Mode d'entrée: {:?}", input_mode);
    info!("PullContext normalisé: {:#?}", pullcontext);

    upsert_pull(&state.pool, &pullcontext).await?;
    insert_missing_digests(&state.pool, &pullcontext).await?;

    let state_value = match pullcontext.phase {
        Phase::Initial => {
            info!("Phase INITIAL pour pull_id={}", pullcontext.pull_id);
            handle_initial_phase(&state.pool, &state.http, &pullcontext).await?
        }
        Phase::Final => {
            info!("Phase FINAL pour pull_id={}", pullcontext.pull_id);
            handle_final_phase(
                &state.pool, &state.http, &pullcontext,
                &raw_context_bytes, &attachments,
                &state.quarantine_base, &state.cache_base,
            ).await?
        }
    };

    info!(
        "Décision retournée au proxy: pull_id={}, state={}",
        pullcontext.pull_id, state_value
    );

    let response = match input_mode {
        InputMode::Modern => {
            (StatusCode::OK, Json(DecisionResponse { decision: state_value })).into_response()
        }
        InputMode::LegacyProxy => (
            StatusCode::OK,
            Json(LegacyOrchestratorResponse {
                pull_id: pullcontext.pull_id,
                state: state_value,
            }),
        )
            .into_response(),
    };

    Ok(response)
}

fn convert_proxy_context(proxy: ProxyPullContext) -> PullContext {
    info!("Conversion legacy context: uuid={}", proxy.uuid);

    let phase = if proxy.scan_final_done {
        Phase::Final
    } else {
        Phase::Initial
    };

    let mut digests = Vec::new();

    for d in &proxy.manifest_digests {
        digests.push(DigestInput {
            digest_value: d.as_prefixed(),
            digest_type: Some("manifests".to_string()),
            digest_algo: Some(d.algorithm.clone()),
        });
    }

    for d in &proxy.blob_digests {
        digests.push(DigestInput {
            digest_value: d.as_prefixed(),
            digest_type: Some("blobs".to_string()),
            digest_algo: Some(d.algorithm.clone()),
        });
    }

    for d in &proxy.referrers_digests {
        digests.push(DigestInput {
            digest_value: d.as_prefixed(),
            digest_type: Some("referrers".to_string()),
            digest_algo: Some(d.algorithm.clone()),
        });
    }

    if let Some(root) = &proxy.manifest_racine_digest {
        let root_prefixed = root.as_prefixed();
        let already = digests.iter().any(|d| d.digest_value == root_prefixed);

        if !already {
            digests.push(DigestInput {
                digest_value: root_prefixed,
                digest_type: Some("manifests".to_string()),
                digest_algo: Some(root.algorithm.clone()),
            });
        }
    }

    info!(
        "Conversion terminée: phase={:?}, digests_count={}",
        phase,
        digests.len()
    );

    PullContext {
        pull_id: proxy.uuid,
        phase,
        ip_client: proxy.ip_client,
        registry: proxy.registry,
        repository: proxy.repository,
        tag: Some(proxy.tag),
        os: Some(proxy.os),
        arch: Some(proxy.arch),
        client_type: Some(proxy.client_type),
        digests,
        metadata: json!({
            "source": "proxy_context",
            "pull_completed": proxy.pull_completed,
            "scan_final_done": proxy.scan_final_done,
            "check_if_verify_digest_completed": proxy.check_if_verify_digest_completed,
            "scan_status": proxy.scan_status,
            "in_whitelist": proxy.in_whitelist,
            "in_blacklist": proxy.in_blacklist,
            "in_cache": proxy.in_cache,
            "digests_possible_count": proxy.digests_possible.len(),
            "digests_expected_count": proxy.digests_expected.len(),
        }),
    }
}

async fn get_decision(
    State(state): State<Arc<AppState>>,
    Path(pull_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    info!("GET /v1/decision/{} reçu", pull_id);

    let row = sqlx::query(
        r#"
        SELECT uuid, scan_completed, decision_final, started_at, last_activity
        FROM pulls
        WHERE uuid = $1
        "#,
    )
    .bind(pull_id)
    .fetch_optional(&state.pool)
    .await?;

    match row {
        Some(row) => {
            let scan_completed: bool = row.try_get("scan_completed")?;
            let decision_final: Option<String> = row.try_get("decision_final")?;

            let decision = if !scan_completed {
                "PENDING".to_string()
            } else {
                decision_final.unwrap_or_else(|| "PENDING".to_string())
            };

            info!(
                "Décision consultée: pull_id={}, completed={}, decision={}",
                pull_id, scan_completed, decision
            );

            Ok((
                StatusCode::OK,
                Json(DecisionStatusResponse {
                    pull_id: row.try_get("uuid")?,
                    scan_completed,
                    decision,
                    started_at: row.try_get("started_at")?,
                    last_activity: row.try_get("last_activity")?,
                }),
            ))
        }
        None => {
            warn!("Pull introuvable: {}", pull_id);

            Ok((
                StatusCode::NOT_FOUND,
                Json(DecisionStatusResponse {
                    pull_id,
                    scan_completed: false,
                    decision: "PENDING".to_string(),
                    started_at: Utc::now(),
                    last_activity: Utc::now(),
                }),
            ))
        }
    }
}

async fn scanner_callback(
    State(state): State<Arc<AppState>>,
    Path(scanner_type): Path<String>,
    Json(payload): Json<ScannerCallbackPayload>,
) -> Result<impl IntoResponse, AppError> {
    info!("========== Callback scanner reçu ==========");
    info!("Scanner type: {}", scanner_type);
    info!("Pull ID: {}", payload.pull_id);
    info!(
        "Payload scanner: {}",
        serde_json::to_string_pretty(&payload.response_scanner)
            .unwrap_or_else(|_| "<json serialization error>".to_string())
    );

    let ia_decision_id = latest_ia_decision_id(&state.pool, payload.pull_id).await?;

    info!("Dernier ia_decision_id: {:?}", ia_decision_id);

    let result = sqlx::query(
        r#"
        INSERT INTO scan_events (id, pull_id, ia_decision_id, scanner_type, response_scanner, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(payload.pull_id)
    .bind(ia_decision_id)
    .bind(&scanner_type)
    .bind(&payload.response_scanner)
    .execute(&state.pool)
    .await?;

    info!(
        "DB insert scan_events OK: rows_affected={}",
        result.rows_affected()
    );

    try_finalize_pull(&state.pool, payload.pull_id).await?;

    let decision = current_decision(&state.pool, payload.pull_id).await?;

    info!(
        "Réponse callback scanner: pull_id={}, decision={}",
        payload.pull_id, decision
    );

    Ok((StatusCode::OK, Json(DecisionResponse { decision })))
}

async fn handle_initial_phase(
    pool: &PgPool,
    http: &Client,
    pullcontext: &PullContext,
) -> Result<String, AppError> {
    info!("Début handle_initial_phase: pull_id={}", pullcontext.pull_id);

    let high = high_level_decision(pool, http, pullcontext).await?;

    info!("HighLevelResult: {:#?}", high);

    sqlx::query(
        r#"
        INSERT INTO scan_events (id, pull_id, ia_decision_id, scanner_type, response_scanner, executed, llm_summary, created_at)
        VALUES ($1, $2, NULL, 'high-level', $3, true, NULL, NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(pullcontext.pull_id)
    .bind(json!({
        "decision":  high.state,
        "score":     high.score,
        "reasoning": high.reasoning_lines,
        "raw_text":  high.raw_text,
    }))
    .execute(pool)
    .await?;

    info!("DB insert scan_events high-level OK: pull_id={}", pullcontext.pull_id);

    let scan_completed = high.state != "PENDING";

    info!(
        "Mise à jour pulls: pull_id={}, scan_completed={}, decision_final={}",
        pullcontext.pull_id, scan_completed, high.state
    );

    let result = sqlx::query(
        r#"
        UPDATE pulls
        SET
            scan_completed = $2,
            decision_final = $3,
            last_activity = NOW()
        WHERE uuid = $1
        "#,
    )
    .bind(pullcontext.pull_id)
    .bind(scan_completed)
    .bind(&high.state)
    .execute(pool)
    .await?;

    info!("DB update pulls OK: rows_affected={}", result.rows_affected());

    Ok(high.state)
}

async fn high_level_decision(
    pool: &PgPool,
    http: &Client,
    pullcontext: &PullContext,
) -> Result<HighLevelResult, AppError> {
    info!("Début high_level_decision: pull_id={}", pullcontext.pull_id);

    info!(
        "DB check blacklist: registry={}, repository={}, tag={:?}",
        pullcontext.registry, pullcontext.repository, pullcontext.tag
    );

    let blacklisted = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM blacklist
        WHERE registry = $1
          AND repository = $2
          AND (tag = $3 OR tag IS NULL)
        "#,
    )
    .bind(&pullcontext.registry)
    .bind(&pullcontext.repository)
    .bind(pullcontext.tag.clone())
    .fetch_one(pool)
    .await?;

    info!("Résultat blacklist count={}", blacklisted);

    if blacklisted > 0 {
        warn!(
            "Image blacklistée: registry={}, repository={}, tag={:?}",
            pullcontext.registry, pullcontext.repository, pullcontext.tag
        );

        return Ok(HighLevelResult {
            state: "DENY".to_string(),
            reasoning_lines: vec!["Image présente en blacklist".to_string()],
            raw_text: "Image présente en blacklist.\nResultat : 0".to_string(),
            score: 0.0,
        });
    }

    let high_level_url =
        env::var("HIGH_LEVEL_URL").unwrap_or_else(|_| "http://127.0.0.1:4000/v1/high-level".to_string());

    let hl_payload = build_high_level_pullcontext(pullcontext);

    info!("Appel high-level URL: {}", high_level_url);
    info!(
        "Payload high-level envoyé:\n{}",
        serde_json::to_string_pretty(&hl_payload)
            .unwrap_or_else(|_| "<serialization error>".to_string())
    );

    let hl_result = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        async {
            let resp = http
                .post(&high_level_url)
                .json(&hl_payload)
                .send()
                .await
                .map_err(AppError::internal)?;

            info!("Réponse HTTP high-level status={}", resp.status());

            resp.error_for_status()
                .map_err(AppError::internal)?
                .json::<HighLevelServiceResponse>()
                .await
                .map_err(AppError::internal)
        },
    )
    .await;

    let hl_resp = match hl_result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!(
                "HL scanner erreur pour pull_id={}: {} → PENDING",
                pullcontext.pull_id, e.message
            );
            return Ok(HighLevelResult {
                state: "PENDING".to_string(),
                reasoning_lines: vec![format!("HL scanner erreur: {}", e.message)],
                raw_text: format!("Erreur HL scanner.\nResultat : 50"),
                score: 50.0,
            });
        }
        Err(_elapsed) => {
            warn!(
                "HL scanner timeout (>25s) pour pull_id={} → PENDING",
                pullcontext.pull_id
            );
            return Ok(HighLevelResult {
                state: "PENDING".to_string(),
                reasoning_lines: vec!["HL scanner timeout".to_string()],
                raw_text: "Timeout HL scanner.\nResultat : 50".to_string(),
                score: 50.0,
            });
        }
    };

    info!("Réponse high-level désérialisée: {:#?}", hl_resp);

    let text = hl_resp.opinion;
    let score = extract_score_from_text(&text).unwrap_or(50.0);
    let state = decision_from_high_level_score(score);

    let mut reasoning_lines = split_reasoning_lines(&text);

    if reasoning_lines.is_empty() {
        reasoning_lines.push(format!("Analyse haut niveau reçue. Score={score}"));
    }

    info!("Décision high-level calculée: score={}, state={}", score, state);

    Ok(HighLevelResult {
        state,
        reasoning_lines,
        raw_text: text,
        score,
    })
}

fn extract_score_from_text(text: &str) -> Option<f64> {
    let mut last: Option<f64> = None;
    let mut current = String::new();

    for ch in text.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            if let Ok(value) = current.parse::<f64>() {
                if (0.0..=100.0).contains(&value) {
                    last = Some(value);
                }
            }
            current.clear();
        }
    }

    if !current.is_empty() {
        if let Ok(value) = current.parse::<f64>() {
            if (0.0..=100.0).contains(&value) {
                last = Some(value);
            }
        }
    }

    debug!("Score extrait du texte high-level: {:?}", last);

    last
}

fn split_reasoning_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn decision_from_high_level_score(score: f64) -> String {
    let decision = if score < 30.0 {
        "DENY".to_string()
    } else {
        "PENDING".to_string()
    };

    debug!("Score {} => décision {}", score, decision);

    decision
}

async fn handle_final_phase(
    pool: &PgPool,
    http: &Client,
    pullcontext: &PullContext,
    raw_context_bytes: &Bytes,
    attachments: &[AttachmentData],
    quarantine_base: &str,
    cache_base: &str,
) -> Result<String, AppError> {
    info!("Début handle_final_phase: pull_id={}", pullcontext.pull_id);

    let llm_url = env::var("LLM_DECISION_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5000/v1/decision".to_string());
    let timeout_secs: u64 = env::var("LLM_DECISION_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    info!(
        "LLM-decision URL={}, timeout={}s, pull_id={}",
        llm_url, timeout_secs, pullcontext.pull_id
    );

    let ia_id = Uuid::new_v4();
    let (tx, rx) = oneshot::channel::<String>();

    // INSERT PENDING immédiat avec les infos du proxy — le proxy n'a pas encore répondu
    sqlx::query(
        r#"INSERT INTO ia_decisions (id, pull_id, created_at, decision, static_scan, compliance_scan, dynamic_scan)
           VALUES ($1, $2, NOW(), 'PENDING', false, false, false)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(ia_id)
    .bind(pullcontext.pull_id)
    .execute(pool)
    .await?;

    info!("DB insert ia_decisions PENDING: pull_id={}, ia_id={}", pullcontext.pull_id, ia_id);

    let task = PendingDecisionTask {
        pool: pool.clone(),
        http: http.clone(),
        pull_id: pullcontext.pull_id,
        ia_id,
        registry: pullcontext.registry.clone(),
        repository: pullcontext.repository.clone(),
        tag: pullcontext.tag.clone().unwrap_or_default(),
        digests: pullcontext.digests.clone(),
        raw_context_bytes: raw_context_bytes.clone(),
        attachments: attachments.to_vec(),
        llm_url,
        quarantine_base: quarantine_base.to_string(),
        cache_base: cache_base.to_string(),
        tx,
    };

    tokio::spawn(process_llm_decision_async(task));

    let decision = match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
        Ok(Ok(d)) => {
            info!(
                "LLM-decision répondu dans les {}s: pull_id={}, decision={}",
                timeout_secs, pullcontext.pull_id, d
            );
            d
        }
        Ok(Err(_)) => {
            warn!(
                "Canal LLM-decision fermé sans résultat: pull_id={} → PENDING",
                pullcontext.pull_id
            );
            "PENDING".to_string()
        }
        Err(_) => {
            warn!(
                "LLM-decision timeout (>{}s): pull_id={} → PENDING (traitement async en cours)",
                timeout_secs, pullcontext.pull_id
            );
            "PENDING".to_string()
        }
    };

    info!(
        "handle_final_phase retourne: pull_id={}, decision={}",
        pullcontext.pull_id, decision
    );

    Ok(decision)
}

fn build_llm_form(
    raw_context_bytes: &Bytes,
    attachments: &[AttachmentData],
) -> Result<reqwest::multipart::Form, AppError> {
    let mut form = reqwest::multipart::Form::new().part(
        "context",
        reqwest::multipart::Part::bytes(raw_context_bytes.to_vec())
            .file_name("context.json")
            .mime_str("application/json")
            .map_err(|e| AppError::internal(format!("mime context: {e}")))?,
    );

    for att in attachments {
        let mime = att.content_type.as_deref().unwrap_or("application/octet-stream");
        let part = reqwest::multipart::Part::bytes(att.bytes.to_vec())
            .file_name(att.file_name.clone().unwrap_or_else(|| att.field_name.clone()))
            .mime_str(mime)
            .map_err(|e| AppError::internal(format!("mime {}: {e}", att.field_name)))?;
        form = form.part(att.field_name.clone(), part);
    }

    Ok(form)
}

async fn process_llm_decision_async(task: PendingDecisionTask) {
    info!(
        "========== process_llm_decision_async: pull_id={} ==========",
        task.pull_id
    );

    // 1. Construire et envoyer le formulaire au LLM
    let form = match build_llm_form(&task.raw_context_bytes, &task.attachments) {
        Ok(f) => f,
        Err(e) => {
            warn!("Erreur construction form LLM: {} → PENDING", e.message);
            let _ = task.tx.send("PENDING".to_string());
            return;
        }
    };

    let llm_body: Option<Value> = match task.http.post(&task.llm_url).multipart(form).send().await {
        Err(e) => {
            warn!("LLM-decision unreachable pull_id={}: {}", task.pull_id, e);
            None
        }
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                warn!("LLM-decision HTTP {} pull_id={}", status, task.pull_id);
                None
            } else {
                let body: Value = resp.json().await.unwrap_or_else(|e| {
                    warn!("LLM-decision réponse non-JSON pull_id={}: {}", task.pull_id, e);
                    json!({})
                });
                info!(
                    "Réponse LLM-decision pull_id={}:\n{}",
                    task.pull_id,
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
                Some(body)
            }
        }
    };

    let decision = llm_body
        .as_ref()
        .map(|b| decision_from_llm_response(b))
        .unwrap_or_else(|| "PENDING".to_string());

    info!("Décision LLM: pull_id={}, decision={}", task.pull_id, decision);

    // 2. Signaler la décision au handle_final_phase (pour le chemin timeout)
    let _ = task.tx.send(decision.clone());

    // 3. Sans réponse LLM, rien à écrire en DB
    let Some(ref body) = llm_body else {
        warn!("Pas de réponse LLM, aucune écriture DB: pull_id={}", task.pull_id);
        return;
    };

    // 4. Mise à jour ia_decisions (ligne créée par le proxy, on l'update via pull_id)
    let verdict = body.get("verdict");
    let vuln_score = verdict.and_then(|v| v.get("vulnerability_score")).and_then(|v| v.as_f64());
    let confidence = verdict.and_then(|v| v.get("confidence")).and_then(|v| v.as_f64());
    let rationale = verdict.and_then(|v| v.get("rationale")).and_then(|v| v.as_str()).map(|s| s.to_string());
    let scan_reasoning = body.get("scan_reasoning").cloned();
    let decision_metadata = body.get("decision_metadata").cloned();
    let alternatives = body.get("alternatives").cloned();

    let scan_analysis = body.get("scan_analysis");
    let static_scan = scan_analysis.and_then(|s| s.get("static")).and_then(|s| s.get("executed")).and_then(|v| v.as_bool()).unwrap_or(false);
    let compliance_scan = scan_analysis.and_then(|s| s.get("compliance")).and_then(|s| s.get("executed")).and_then(|v| v.as_bool()).unwrap_or(false);
    let dynamic_scan = scan_analysis.and_then(|s| s.get("dynamic")).and_then(|s| s.get("executed")).and_then(|v| v.as_bool()).unwrap_or(false);

    info!("Scans exécutés: static={}, compliance={}, dynamic={}", static_scan, compliance_scan, dynamic_scan);

    let ia_id = task.ia_id;

    match sqlx::query(
        r#"
        UPDATE ia_decisions SET
            decision            = $2,
            vulnerability_score = $3,
            confidence          = $4,
            rationale           = $5,
            scan_reasoning      = $6,
            decision_metadata   = $7,
            alternatives        = $8,
            static_scan         = $9,
            compliance_scan     = $10,
            dynamic_scan        = $11,
            created_at          = NOW()
        WHERE id = $1
        "#,
    )
    .bind(ia_id).bind(&decision)
    .bind(vuln_score).bind(confidence).bind(rationale)
    .bind(scan_reasoning).bind(decision_metadata).bind(alternatives)
    .bind(static_scan).bind(compliance_scan).bind(dynamic_scan)
    .execute(&task.pool)
    .await
    {
        Ok(r) => info!("DB update ia_decisions OK: pull_id={}, ia_id={}, rows={}", task.pull_id, ia_id, r.rows_affected()),
        Err(e) => warn!("DB update ia_decisions ERREUR: {}", e),
    }

    // 5. Écriture scan_events
    if let Some(analysis) = body.get("scan_analysis").and_then(|v| v.as_object()) {
        for (scanner_type, scan_data) in analysis {
            let executed = scan_data.get("executed").and_then(|v| v.as_bool()).unwrap_or(false);
            let llm_summary = scan_data.get("llm_summary").and_then(|v| v.as_str()).map(|s| s.to_string());
            let raw_result = scan_data.get("raw_result").cloned().unwrap_or(json!(null));

            if let Err(e) = sqlx::query(
                r#"INSERT INTO scan_events (id, pull_id, ia_decision_id, scanner_type, response_scanner, executed, llm_summary, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())"#,
            )
            .bind(Uuid::new_v4()).bind(task.pull_id).bind(ia_id)
            .bind(scanner_type.as_str()).bind(raw_result).bind(executed).bind(llm_summary)
            .execute(&task.pool)
            .await
            {
                warn!("DB insert scan_events ERREUR ({}): {}", scanner_type, e);
            } else {
                info!("DB insert scan_events OK: scanner_type={}", scanner_type);
            }
        }
    }

    // 6. Whitelist / blacklist + opérations fichiers
    match decision.as_str() {
        "ALLOW" => {
            if let Err(e) = sqlx::query(
                "INSERT INTO whitelist (id, registry, repository, tag) VALUES ($1::uuid, $2, $3, $4) ON CONFLICT DO NOTHING",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&task.registry).bind(&task.repository).bind(&task.tag)
            .execute(&task.pool)
            .await
            {
                warn!("DB insert whitelist ERREUR: {}", e);
            } else {
                info!("Whitelist ajouté: {}/{}/{}", task.registry, task.repository, task.tag);
            }

            move_digests_to_cache(
                &task.pool, &task.registry, &task.repository,
                &task.digests, &task.quarantine_base, &task.cache_base,
            ).await;
        }
        "DENY" => {
            if let Err(e) = sqlx::query(
                "INSERT INTO blacklist (id, registry, repository, tag) VALUES ($1::uuid, $2, $3, $4) ON CONFLICT DO NOTHING",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&task.registry).bind(&task.repository).bind(&task.tag)
            .execute(&task.pool)
            .await
            {
                warn!("DB insert blacklist ERREUR: {}", e);
            } else {
                info!("Blacklist ajouté: {}/{}/{}", task.registry, task.repository, task.tag);
            }

            delete_digests_from_quarantine(
                &task.pool, &task.registry, &task.repository,
                &task.digests, &task.quarantine_base,
            ).await;
        }
        _ => {}
    }

    // 7. Mise à jour decision_final dans pulls
    let scan_completed = decision != "PENDING";
    match sqlx::query(
        "UPDATE pulls SET scan_completed=$2, decision_final=$3, last_activity=NOW() WHERE uuid=$1",
    )
    .bind(task.pull_id).bind(scan_completed).bind(&decision)
    .execute(&task.pool)
    .await
    {
        Ok(r) => info!(
            "DB update pulls final: pull_id={}, decision={}, rows={}",
            task.pull_id, decision, r.rows_affected()
        ),
        Err(e) => warn!("DB update pulls ERREUR pull_id={}: {}", task.pull_id, e),
    }
}

async fn move_digests_to_cache(
    pool: &PgPool,
    registry: &str,
    repository: &str,
    digests: &[DigestInput],
    quarantine_base: &str,
    cache_base: &str,
) {
    for digest in digests {
        let hex = normalize_digest(&digest.digest_value);
        let dtype = digest.digest_type.as_deref().unwrap_or("manifests");

        let (q_path, c_path, db_type) = match dtype {
            "blobs" => (
                format!("{}/{}/{}/blobs/sha256/{}", quarantine_base, registry, repository, hex),
                format!("{}/{}/{}/blobs/sha256/{}", cache_base, registry, repository, hex),
                "blob",
            ),
            "referrers" => (
                format!("{}/{}/{}/referrers/sha256/{}.json", quarantine_base, registry, repository, hex),
                format!("{}/{}/{}/referrers/sha256/{}.json", cache_base, registry, repository, hex),
                "referrer",
            ),
            _ => (
                format!("{}/{}/{}/manifests/sha256/{}.json", quarantine_base, registry, repository, hex),
                format!("{}/{}/{}/manifests/sha256/{}.json", cache_base, registry, repository, hex),
                "manifest",
            ),
        };

        match tokio::fs::try_exists(&q_path).await {
            Ok(false) | Err(_) => {
                debug!("Fichier quarantine inexistant, skip: {}", q_path);
                continue;
            }
            Ok(true) => {}
        }

        if let Some(parent) = std::path::Path::new(&c_path).parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                warn!("Impossible de créer le répertoire cache {}: {}", parent.display(), e);
                continue;
            }
        }

        let size = match tokio::fs::copy(&q_path, &c_path).await {
            Ok(bytes) => bytes as i64,
            Err(e) => {
                warn!("Erreur copie {} → {}: {}", q_path, c_path, e);
                continue;
            }
        };

        info!("Copié quarantine→cache: {}", hex);

        let digest_with_prefix = format!("sha256:{}", hex);

        if let Err(e) = sqlx::query(
            r#"INSERT INTO cache (id, registry, repository, digest, type, digest_algo, file_path, size_bytes, added_at)
               VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, NOW())
               ON CONFLICT (registry, repository, digest, type)
               DO UPDATE SET file_path=EXCLUDED.file_path, size_bytes=EXCLUDED.size_bytes, added_at=NOW()"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(registry).bind(repository).bind(&digest_with_prefix)
        .bind(db_type).bind("sha256").bind(&c_path).bind(size)
        .execute(pool)
        .await
        {
            warn!("DB upsert cache ERREUR ({}): {}", hex, e);
        }

        if let Err(e) = tokio::fs::remove_file(&q_path).await {
            warn!("Erreur suppression quarantine {}: {}", q_path, e);
        }

        if let Err(e) = sqlx::query(
            "DELETE FROM quarantine WHERE registry=$1 AND repository=$2 AND digest=$3 AND type=$4",
        )
        .bind(registry).bind(repository).bind(&digest_with_prefix).bind(db_type)
        .execute(pool)
        .await
        {
            warn!("DB delete quarantine ERREUR ({}): {}", hex, e);
        }
    }
}

async fn delete_digests_from_quarantine(
    pool: &PgPool,
    registry: &str,
    repository: &str,
    digests: &[DigestInput],
    quarantine_base: &str,
) {
    for digest in digests {
        let hex = normalize_digest(&digest.digest_value);
        let dtype = digest.digest_type.as_deref().unwrap_or("manifests");

        let (q_path, db_type) = match dtype {
            "blobs" => (
                format!("{}/{}/{}/blobs/sha256/{}", quarantine_base, registry, repository, hex),
                "blob",
            ),
            "referrers" => (
                format!("{}/{}/{}/referrers/sha256/{}.json", quarantine_base, registry, repository, hex),
                "referrer",
            ),
            _ => (
                format!("{}/{}/{}/manifests/sha256/{}.json", quarantine_base, registry, repository, hex),
                "manifest",
            ),
        };

        if tokio::fs::try_exists(&q_path).await.unwrap_or(false) {
            match tokio::fs::remove_file(&q_path).await {
                Ok(_) => info!("Supprimé quarantine: {}", q_path),
                Err(e) => warn!("Erreur suppression quarantine {}: {}", q_path, e),
            }
        }

        let digest_with_prefix = format!("sha256:{}", hex);

        if let Err(e) = sqlx::query(
            "DELETE FROM quarantine WHERE registry=$1 AND repository=$2 AND digest=$3 AND type=$4",
        )
        .bind(registry).bind(repository).bind(&digest_with_prefix).bind(db_type)
        .execute(pool)
        .await
        {
            warn!("DB delete quarantine ERREUR ({}): {}", hex, e);
        }
    }
}

fn decision_from_llm_response(body: &Value) -> String {
    // Format structuré : verdict.decision
    if let Some(d) = body
        .get("verdict")
        .and_then(|v| v.get("decision"))
        .and_then(|v| v.as_str())
    {
        let upper = d.to_uppercase();
        if upper == "ALLOW" || upper == "DENY" || upper == "PENDING" {
            return upper;
        }
    }

    // Format plat : decision (fallback Qwen)
    if let Some(d) = body.get("decision").and_then(|v| v.as_str()) {
        let upper = d.to_uppercase();
        if upper == "ALLOW" || upper == "DENY" || upper == "PENDING" {
            return upper;
        }
    }

    // Format plat : score numérique (fallback Qwen)
    if let Some(score) = body.get("score").and_then(|v| v.as_f64()) {
        return if score >= 50.0 {
            "ALLOW".to_string()
        } else {
            "DENY".to_string()
        };
    }

    if body.get("error").is_some() {
        return "PENDING".to_string();
    }

    "PENDING".to_string()
}

async fn try_finalize_pull(pool: &PgPool, pull_id: Uuid) -> Result<(), AppError> {
    info!("========== Tentative finalisation ==========");
    info!("pull_id={}", pull_id);

    let row = sqlx::query(
        r#"
        SELECT id, dynamic_scan, compliance_scan, static_scan
        FROM ia_decisions
        WHERE pull_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(pull_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        warn!("Impossible de finaliser: aucune ia_decision pour pull_id={}", pull_id);
        return Ok(());
    };

    let ia_decision_id: Uuid = row.try_get("id")?;
    let dynamic_scan: bool = row.try_get("dynamic_scan")?;
    let compliance_scan: bool = row.try_get("compliance_scan")?;
    let static_scan: bool = row.try_get("static_scan")?;

    info!(
        "Scans requis: ia_decision_id={}, static={}, dynamic={}, compliance={}",
        ia_decision_id, static_scan, dynamic_scan, compliance_scan
    );

    let scan_rows = sqlx::query(
        r#"
        SELECT scanner_type, response_scanner
        FROM scan_events
        WHERE pull_id = $1
        "#,
    )
    .bind(pull_id)
    .fetch_all(pool)
    .await?;

    info!("Nombre de scan_events trouvés: {}", scan_rows.len());

    let mut seen_static = false;
    let mut seen_dynamic = false;
    let mut seen_compliance = false;

    let mut deny = false;
    let mut reasons = Vec::new();

    for row in scan_rows {
        let scanner_type: Option<String> = row.try_get("scanner_type")?;
        let response_scanner: Option<Value> = row.try_get("response_scanner")?;

        let scanner_type = scanner_type.unwrap_or_default();
        let response_scanner = response_scanner.unwrap_or_else(|| json!({}));

        info!(
            "Scan event: scanner_type={}, response={}",
            scanner_type,
            serde_json::to_string_pretty(&response_scanner).unwrap_or_default()
        );

        match scanner_type.as_str() {
            "static" => seen_static = true,
            "dynamic" => seen_dynamic = true,
            "compliance" => seen_compliance = true,
            _ => {}
        }

        if response_scanner
            .get("decision")
            .and_then(|v| v.as_str())
            .map(|v| v.eq_ignore_ascii_case("DENY"))
            .unwrap_or(false)
        {
            deny = true;
            reasons.push(format!("Le scanner {} a demandé un refus", scanner_type));
        }

        if response_scanner
            .get("critical")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            > 0
        {
            deny = true;
            reasons.push(format!(
                "Le scanner {} a remonté des éléments critiques",
                scanner_type
            ));
        }
    }

    let all_required_done = (!static_scan || seen_static)
        && (!dynamic_scan || seen_dynamic)
        && (!compliance_scan || seen_compliance);

    info!(
        "Scans vus: static={}, dynamic={}, compliance={}, all_required_done={}",
        seen_static, seen_dynamic, seen_compliance, all_required_done
    );

    if !all_required_done {
        info!(
            "Pull toujours en attente: pull_id={}, décision=PENDING",
            pull_id
        );

        let result = sqlx::query(
            r#"
            UPDATE pulls
            SET scan_completed = false, decision_final = 'PENDING', last_activity = NOW()
            WHERE uuid = $1
            "#,
        )
        .bind(pull_id)
        .execute(pool)
        .await?;

        info!(
            "DB update pulls PENDING OK: rows_affected={}",
            result.rows_affected()
        );

        return Ok(());
    }

    let final_decision = if deny { "DENY" } else { "ALLOW" };

    if reasons.is_empty() {
        reasons.push("Tous les scanners requis ont répondu sans blocage".to_string());
    }

    info!("Décision finale: pull_id={} => {}", pull_id, final_decision);
    info!("Raisons: {:?}", reasons);

    sqlx::query(
        r#"
        UPDATE ia_decisions
        SET
            decision   = $2,
            rationale  = $3,
            created_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(ia_decision_id)
    .bind(final_decision)
    .bind(reasons.join("\n"))
    .execute(pool)
    .await?;

    info!("DB update ia_decisions final OK: id={}", ia_decision_id);

    let result = sqlx::query(
        r#"
        UPDATE pulls
        SET scan_completed = true, decision_final = $2, last_activity = NOW()
        WHERE uuid = $1
        "#,
    )
    .bind(pull_id)
    .bind(final_decision)
    .execute(pool)
    .await?;

    info!(
        "DB update pulls final OK: rows_affected={}",
        result.rows_affected()
    );

    Ok(())
}

async fn current_decision(pool: &PgPool, pull_id: Uuid) -> Result<String, AppError> {
    info!("Lecture décision courante: pull_id={}", pull_id);

    let row = sqlx::query(
        r#"
        SELECT scan_completed, decision_final
        FROM pulls
        WHERE uuid = $1
        "#,
    )
    .bind(pull_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(row) => {
            let scan_completed: bool = row.try_get("scan_completed")?;
            let decision_final: Option<String> = row.try_get("decision_final")?;

            let decision = if !scan_completed {
                "PENDING".to_string()
            } else {
                decision_final.unwrap_or_else(|| "PENDING".to_string())
            };

            info!(
                "Décision courante: pull_id={}, scan_completed={}, decision={}",
                pull_id, scan_completed, decision
            );

            Ok(decision)
        }
        None => {
            warn!("Aucun pull trouvé pour décision courante: {}", pull_id);
            Ok("PENDING".to_string())
        }
    }
}

async fn latest_ia_decision_id(pool: &PgPool, pull_id: Uuid) -> Result<Option<Uuid>, AppError> {
    info!("Recherche dernière ia_decision: pull_id={}", pull_id);

    let row = sqlx::query(
        r#"
        SELECT id
        FROM ia_decisions
        WHERE pull_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(pull_id)
    .fetch_optional(pool)
    .await?;

    let result = row.map(|r| r.try_get("id")).transpose()?;

    info!("latest_ia_decision_id result={:?}", result);

    Ok(result)
}

async fn upsert_pull(pool: &PgPool, pullcontext: &PullContext) -> Result<(), AppError> {
    info!(
        "DB upsert pulls: uuid={}, ip={}, registry={}, repo={}, tag={:?}, phase={:?}, os={:?}, arch={:?}, client_type={:?}",
        pullcontext.pull_id,
        pullcontext.ip_client,
        pullcontext.registry,
        pullcontext.repository,
        pullcontext.tag,
        pullcontext.phase,
        pullcontext.os,
        pullcontext.arch,
        pullcontext.client_type
    );

    let result = sqlx::query(
        r#"
        INSERT INTO pulls (
            uuid,
            ip_client,
            registry,
            repository,
            tag,
            os,
            arch,
            client_type,
            started_at,
            last_activity,
            scan_completed,
            decision_final
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), false, 'PENDING')
        ON CONFLICT (uuid)
        DO UPDATE SET
            ip_client = EXCLUDED.ip_client,
            registry = EXCLUDED.registry,
            repository = EXCLUDED.repository,
            tag = EXCLUDED.tag,
            os = EXCLUDED.os,
            arch = EXCLUDED.arch,
            client_type = EXCLUDED.client_type,
            last_activity = NOW()
        "#,
    )
    .bind(pullcontext.pull_id)
    .bind(&pullcontext.ip_client)
    .bind(&pullcontext.registry)
    .bind(&pullcontext.repository)
    .bind(&pullcontext.tag)
    .bind(&pullcontext.os)
    .bind(&pullcontext.arch)
    .bind(&pullcontext.client_type)
    .execute(pool)
    .await?;

    info!("DB upsert pulls OK: rows_affected={}", result.rows_affected());

    Ok(())
}

fn normalize_digest(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

async fn insert_missing_digests(pool: &PgPool, pullcontext: &PullContext) -> Result<(), AppError> {
    info!(
        "Insertion digests: pull_id={}, count={}",
        pullcontext.pull_id,
        pullcontext.digests.len()
    );

    for digest in &pullcontext.digests {
        let normalized = normalize_digest(&digest.digest_value);

        debug!(
            "Digest: pull_id={}, value={}, type={:?}, algo={:?}",
            pullcontext.pull_id, normalized, digest.digest_type, digest.digest_algo
        );

        sqlx::query(
            r#"
            INSERT INTO pull_digests (id, pull_id, digest_value, digest_type, received_at, digest_algo)
            VALUES ($1, $2, $3, $4, NOW(), $5)
            ON CONFLICT (pull_id, digest_value, digest_type) DO NOTHING
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(pullcontext.pull_id)
        .bind(normalized)
        .bind(&digest.digest_type)
        .bind(&digest.digest_algo)
        .execute(pool)
        .await?;
    }

    Ok(())
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(err: anyhow::Error) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
        }
    }

    fn internal<E: std::fmt::Display>(err: E) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        AppError::internal(value)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::internal(value)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        AppError::internal(value)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!(
            "Erreur HTTP retournée: status={}, message={}",
            self.status, self.message
        );

        (
            self.status,
            [(header::CONTENT_TYPE, "application/json")],
            Json(json!({
                "error": self.message
            })),
        )
            .into_response()
    }
}

fn split_digest_value(full: &str, algo_hint: Option<&str>) -> Option<HighLevelDigest> {
    if let Some((algo, value)) = full.split_once(':') {
        if !value.is_empty() {
            return Some(HighLevelDigest {
                algorithm: algo.to_string(),
                value: value.to_string(),
            });
        }
    }

    if !full.is_empty() {
        return Some(HighLevelDigest {
            algorithm: algo_hint.unwrap_or("sha256").to_string(),
            value: full.to_string(),
        });
    }

    None
}

fn to_high_level_digest(d: &DigestInput) -> Option<HighLevelDigest> {
    split_digest_value(&d.digest_value, d.digest_algo.as_deref())
}

fn build_high_level_pullcontext(pullcontext: &PullContext) -> HighLevelPullContext {
    info!(
        "Construction HighLevelPullContext depuis pull_id={}",
        pullcontext.pull_id
    );

    let mut manifest_digests = Vec::new();
    let mut blob_digests = Vec::new();
    let mut referrers_digests = Vec::new();

    for d in &pullcontext.digests {
        let Some(hd) = to_high_level_digest(d) else {
            warn!("Digest ignoré car invalide: {:?}", d);
            continue;
        };

        match d.digest_type.as_deref() {
            Some("blobs") => blob_digests.push(hd),
            Some("referrers") => referrers_digests.push(hd),
            _ => manifest_digests.push(hd),
        }
    }

    let manifest_racine_digest = manifest_digests.first().cloned();

    info!(
        "HighLevel digests: manifests={}, blobs={}, referrers={}, root_present={}",
        manifest_digests.len(),
        blob_digests.len(),
        referrers_digests.len(),
        manifest_racine_digest.is_some()
    );

    HighLevelPullContext {
        uuid: pullcontext.pull_id,
        ip_client: pullcontext.ip_client.clone(),
        registry: pullcontext.registry.clone(),
        repository: pullcontext.repository.clone(),
        tag: pullcontext.tag.clone().unwrap_or_else(|| "latest".to_string()),
        manifest_digests: manifest_digests.clone(),
        blob_digests,
        referrers_digests,
        manifest_racine_digest,
        digests_possible: manifest_digests.clone(),
        digests_expected: manifest_digests,
        os: pullcontext.os.clone().unwrap_or_else(|| "unknown".to_string()),
        arch: pullcontext.arch.clone().unwrap_or_else(|| "unknown".to_string()),
        pull_completed: false,
        scan_final_done: false,
        in_whitelist: None,
        in_blacklist: None,
        in_cache: None,
        check_if_verify_digest_completed: false,
        scan_status: Some("PENDING".to_string()),
        client_type: pullcontext
            .client_type
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
    }
}