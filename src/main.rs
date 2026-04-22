use axum::{
    body::Bytes,
    extract::{Multipart, Path, State,DefaultBodyLimit},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{env, net::SocketAddr, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
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

#[derive(Debug, Serialize, Deserialize)]
struct PlannedScans {
    dynamic_scan: bool,
    compliance_scan: bool,
    static_scan: bool,
    reasoning_scan_choice: Vec<String>,
    score: f64,
}

#[derive(Debug)]
struct AttachmentMeta {
    field_name: String,
    file_name: Option<String>,
    content_type: Option<String>,
    size_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Modern,
    LegacyProxy,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://docdockgo_admin:docdockgo@127.0.0.1:5432/docdockgo".to_string());

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    let state = Arc::new(AppState { pool });

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

    info!("orchestrator listening on http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing() {
    let filter = env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=info".to_string());
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();

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
    handle_multipart_decision(&state.pool, headers, multipart).await
}

async fn handle_multipart_decision(
    pool: &PgPool,
    _headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let mut modern_pullcontext: Option<PullContext> = None;
    let mut legacy_context: Option<ProxyPullContext> = None;
    let mut attachments: Vec<AttachmentMeta> = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(e.into()))?
    {
        let name = field.name().unwrap_or("").trim().to_string();
        let file_name = field.file_name().map(|s| s.to_string());
        let content_type = field.content_type().map(|s| s.to_string());
        let bytes: Bytes = field
            .bytes()
            .await
            .map_err(|e| AppError::bad_request(e.into()))?;

        match name.as_str() {
            "pullcontext" => {
                let parsed: PullContext = serde_json::from_slice(&bytes)
                    .map_err(|e| AppError::bad_request(e.into()))?;
                modern_pullcontext = Some(parsed);
            }
            "context" => {
                let parsed: ProxyPullContext = serde_json::from_slice(&bytes)
                    .map_err(|e| AppError::bad_request(e.into()))?;
                legacy_context = Some(parsed);
            }
            _ => {
                attachments.push(AttachmentMeta {
                    field_name: name,
                    file_name,
                    content_type,
                    size_bytes: bytes.len(),
                });
            }
        }
    }

    let (pullcontext, input_mode) = if let Some(pc) = modern_pullcontext {
        (pc, InputMode::Modern)
    } else if let Some(proxy_ctx) = legacy_context {
        (convert_proxy_context(proxy_ctx), InputMode::LegacyProxy)
    } else {
        return Err(AppError::bad_request(anyhow::anyhow!(
            "missing multipart field 'pullcontext' or 'context'"
        )));
    };

    upsert_pull(pool, &pullcontext).await?;
    insert_missing_digests(pool, &pullcontext).await?;

    let state = match pullcontext.phase {
        Phase::Initial => {
            handle_initial_phase(pool, &pullcontext).await?;
            "PENDING".to_string()
        }
        Phase::Final => {
            handle_final_phase(pool, &pullcontext, &attachments).await?;
            current_decision(pool, pullcontext.pull_id).await?
        }
    };

    let response = match input_mode {
        InputMode::Modern => {
            (StatusCode::OK, Json(DecisionResponse { decision: state })).into_response()
        }
        InputMode::LegacyProxy => (
            StatusCode::OK,
            Json(LegacyOrchestratorResponse {
                pull_id: pullcontext.pull_id,
                state,
            }),
        )
            .into_response(),
    };

    Ok(response)
}

fn convert_proxy_context(proxy: ProxyPullContext) -> PullContext {
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
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(DecisionStatusResponse {
                pull_id,
                scan_completed: false,
                decision: "PENDING".to_string(),
                started_at: Utc::now(),
                last_activity: Utc::now(),
            }),
        )),
    }
}

async fn scanner_callback(
    State(state): State<Arc<AppState>>,
    Path(scanner_type): Path<String>,
    Json(payload): Json<ScannerCallbackPayload>,
) -> Result<impl IntoResponse, AppError> {
    let ia_decision_id = latest_ia_decision_id(&state.pool, payload.pull_id).await?;

    sqlx::query(
        r#"
        INSERT INTO scan_events (id, pull_id, ia_decision_id, scanner_type, response_scanner, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(payload.pull_id)
    .bind(ia_decision_id)
    .bind(scanner_type)
    .bind(payload.response_scanner)
    .execute(&state.pool)
    .await?;

    try_finalize_pull(&state.pool, payload.pull_id).await?;

    let decision = current_decision(&state.pool, payload.pull_id).await?;

    Ok((StatusCode::OK, Json(DecisionResponse { decision })))
}

async fn handle_initial_phase(pool: &PgPool, pullcontext: &PullContext) -> Result<(), AppError> {
    let planned = plan_scans(pullcontext);

    let existing = sqlx::query(
        r#"
        SELECT id
        FROM ia_decisions
        WHERE pull_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(pullcontext.pull_id)
    .fetch_optional(pool)
    .await?;

    match existing {
        Some(row) => {
            let id: Uuid = row.try_get("id")?;
            sqlx::query(
                r#"
                UPDATE ia_decisions
                SET
                    reasoning_scan_choice = $2,
                    decision = $3,
                    reasonning_decision = $4,
                    score = $5,
                    dynamic_scan = $6,
                    compliance_scan = $7,
                    static_scan = $8,
                    created_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(&planned.reasoning_scan_choice)
            .bind(vec!["PENDING".to_string()])
            .bind(Vec::<String>::new())
            .bind(planned.score)
            .bind(planned.dynamic_scan)
            .bind(planned.compliance_scan)
            .bind(planned.static_scan)
            .execute(pool)
            .await?;
        }
        None => {
            sqlx::query(
                r#"
                INSERT INTO ia_decisions (
                    id,
                    pull_id,
                    created_at,
                    reasoning_scan_choice,
                    decision,
                    reasonning_decision,
                    score,
                    dynamic_scan,
                    compliance_scan,
                    static_scan
                )
                VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(pullcontext.pull_id)
            .bind(&planned.reasoning_scan_choice)
            .bind(vec!["PENDING".to_string()])
            .bind(Vec::<String>::new())
            .bind(planned.score)
            .bind(planned.dynamic_scan)
            .bind(planned.compliance_scan)
            .bind(planned.static_scan)
            .execute(pool)
            .await?;
        }
    }

    sqlx::query(
        r#"
        UPDATE pulls
        SET
            scan_completed = false,
            decision_final = 'PENDING',
            last_activity = NOW()
        WHERE uuid = $1
        "#,
    )
    .bind(pullcontext.pull_id)
    .execute(pool)
    .await?;

    Ok(())
}

async fn handle_final_phase(
    pool: &PgPool,
    pullcontext: &PullContext,
    attachments: &[AttachmentMeta],
) -> Result<(), AppError> {
    let ia_decision_id = latest_ia_decision_id(pool, pullcontext.pull_id).await?;

    let summary = json!({
        "phase": "FINAL",
        "attachment_count": attachments.len(),
        "attachments": attachments.iter().map(|a| json!({
            "field_name": a.field_name,
            "file_name": a.file_name,
            "content_type": a.content_type,
            "size_bytes": a.size_bytes
        })).collect::<Vec<_>>(),
        "metadata": pullcontext.metadata
    });

    sqlx::query(
        r#"
        INSERT INTO scan_events (id, pull_id, ia_decision_id, scanner_type, response_scanner, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(pullcontext.pull_id)
    .bind(ia_decision_id)
    .bind("final-input")
    .bind(summary)
    .execute(pool)
    .await?;

    try_finalize_pull(pool, pullcontext.pull_id).await?;

    Ok(())
}

fn plan_scans(pullcontext: &PullContext) -> PlannedScans {
    let repo = pullcontext.repository.to_lowercase();
    let registry = pullcontext.registry.to_lowercase();

    let static_scan = true;
    let compliance_scan = registry.contains("docker.io") || registry.contains("ghcr.io");
    let dynamic_scan = repo.contains("api") || repo.contains("web") || repo.contains("service");

    let mut reasoning = vec![
        "Analyse initiale reçue depuis le proxy".to_string(),
        "Un scan statique est toujours demandé par défaut".to_string(),
    ];

    if compliance_scan {
        reasoning.push("Le registre justifie un contrôle de conformité".to_string());
    }

    if dynamic_scan {
        reasoning.push("Le nom du repository suggère un service exécutable".to_string());
    }

    PlannedScans {
        dynamic_scan,
        compliance_scan,
        static_scan,
        reasoning_scan_choice: reasoning,
        score: if dynamic_scan { 0.7 } else { 0.4 },
    }
}

async fn try_finalize_pull(pool: &PgPool, pull_id: Uuid) -> Result<(), AppError> {
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
        return Ok(());
    };

    let ia_decision_id: Uuid = row.try_get("id")?;
    let dynamic_scan: bool = row.try_get("dynamic_scan")?;
    let compliance_scan: bool = row.try_get("compliance_scan")?;
    let static_scan: bool = row.try_get("static_scan")?;

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

    if !all_required_done {
        sqlx::query(
            r#"
            UPDATE pulls
            SET scan_completed = false, decision_final = 'PENDING', last_activity = NOW()
            WHERE uuid = $1
            "#,
        )
        .bind(pull_id)
        .execute(pool)
        .await?;
        return Ok(());
    }

    let final_decision = if deny { "DENY" } else { "ALLOW" };

    if reasons.is_empty() {
        reasons.push("Tous les scanners requis ont répondu sans blocage".to_string());
    }

    sqlx::query(
        r#"
        UPDATE ia_decisions
        SET
            decision = $2,
            reasonning_decision = $3,
            created_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(ia_decision_id)
    .bind(vec![final_decision.to_string()])
    .bind(reasons)
    .execute(pool)
    .await?;

    sqlx::query(
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

    Ok(())
}

async fn current_decision(pool: &PgPool, pull_id: Uuid) -> Result<String, AppError> {
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

            if !scan_completed {
                Ok("PENDING".to_string())
            } else {
                Ok(decision_final.unwrap_or_else(|| "PENDING".to_string()))
            }
        }
        None => Ok("PENDING".to_string()),
    }
}

async fn latest_ia_decision_id(pool: &PgPool, pull_id: Uuid) -> Result<Option<Uuid>, AppError> {
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

    Ok(row.map(|r| r.try_get("id")).transpose()?)
}

async fn upsert_pull(pool: &PgPool, pullcontext: &PullContext) -> Result<(), AppError> {
    sqlx::query(
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

    Ok(())
}

async fn insert_missing_digests(pool: &PgPool, pullcontext: &PullContext) -> Result<(), AppError> {
    for digest in &pullcontext.digests {
        let exists = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM pull_digests
            WHERE pull_id = $1 AND digest_value = $2
            "#,
        )
        .bind(pullcontext.pull_id)
        .bind(&digest.digest_value)
        .fetch_one(pool)
        .await?;

        if exists == 0 {
            sqlx::query(
                r#"
                INSERT INTO pull_digests (
                    id,
                    pull_id,
                    digest_value,
                    digest_type,
                    received_at,
                    digest_algo
                )
                VALUES ($1, $2, $3, $4, NOW(), $5)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(pullcontext.pull_id)
            .bind(&digest.digest_value)
            .bind(&digest.digest_type)
            .bind(&digest.digest_algo)
            .execute(pool)
            .await?;
        }
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
        error!("request failed: {}", self.message);
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