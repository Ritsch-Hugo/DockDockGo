use axum::extract::DefaultBodyLimit;
use axum::{
    extract::Multipart,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
mod auth;
use bytes::Bytes;
use reqwest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::net::SocketAddr;
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;

// ===================
// URLs des services
// ===================

/// Analyse haut niveau (réputation, popularité) — module externe.
const HL_URL: &str = "http://127.0.0.1:4000/v1/high-level";

/// llm-decision : analyse des artefacts + exécution des scans via MCP.
/// Port 3005 pour éviter le conflit avec le scanner CVE (port 3002).
const LLM_DECISION_URL: &str = "http://127.0.0.1:3005/v1/decision";

// ===================
// PullContext — identique à la définition dans llm-common
// ===================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Digest {
    algorithm: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PullContext {
    uuid: Uuid,
    ip_client: String,
    registry: String,
    repository: String,
    tag: String,

    manifest_digests: Vec<Digest>,
    blob_digests: Vec<Digest>,
    referrers_digests: Vec<Digest>,

    manifest_racine_digest: Option<Digest>,
    digests_possible: Vec<Digest>,
    digests_expected: Vec<Digest>,

    os: String,
    arch: String,
    pull_completed: bool,
}

// ===================
// Réponse de llm-decision (ScanDecision)
// ===================

/// Décision de scan retournée par llm-decision.
/// Contient les votes LLM + résultats des scans exécutés via MCP.
#[derive(Deserialize)]
struct ScanDecision {
    #[allow(dead_code)]
    pull_id: Uuid,
    run_static_scan: bool,
    run_compliance_scan: bool,
    #[allow(dead_code)]
    run_dynamic_scan: bool,
    #[allow(dead_code)]
    final_confidence: f32,
    arbiter_rationale: String,

    /// Résultat du scan CVE (Trivy). None si non lancé.
    static_scan_result: Option<serde_json::Value>,
    /// Résultat du scan compliance. None si non lancé.
    compliance_scan_result: Option<serde_json::Value>,
    /// Résultat du scan dynamique (stub). None si non lancé.
    #[allow(dead_code)]
    dynamic_scan_result: Option<serde_json::Value>,
}

// ===================
// Réponse de l'analyse haut niveau
// ===================

#[derive(Deserialize)]
struct HighLevelResp {
    pull_id: Uuid,
    opinion: String,
}

// ===================
// Réponse du decide handler
// ===================

#[derive(Serialize)]
struct DecisionResp {
    pull_id: Uuid,
    state: &'static str, // "PENDING" | "ALLOW" | "DENY"
}

// ===================
// Helpers
// ===================

fn sha256_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

fn extract_result_score(opinion: &str) -> Option<u8> {
    let last = opinion.lines().rev().find(|l| !l.trim().is_empty())?.trim();
    let rest = last.strip_prefix("Resultat :")?.trim();
    let n: u16 = rest.parse().ok()?;
    if n <= 100 { Some(n as u8) } else { None }
}

/// Détermine ALLOW / DENY à partir d'un ScanDecision.
///
/// Logique de décision :
/// - Si aucun scan n'était nécessaire (image propre selon LLM) → ALLOW
/// - Si le scan compliance a des findings FAIL → DENY
/// - Si le scan statique a des CVEs critiques (severity CRITICAL) → DENY
/// - Sinon → ALLOW
fn evaluate_scan_decision(decision: &ScanDecision) -> &'static str {
    // Aucun scan déclenché — LLM a jugé l'image propre
    if !decision.run_static_scan && !decision.run_compliance_scan {
        println!("[ORCH][LLM] aucun scan requis, image considérée propre");
        return "ALLOW";
    }

    // Vérifier le scan compliance : summary.fail > 0 → DENY
    if let Some(ref result) = decision.compliance_scan_result {
        let fail_count = result
            .get("summary")
            .and_then(|s| s.get("fail"))
            .and_then(|f| f.as_u64())
            .unwrap_or(0);

        if fail_count > 0 {
            println!("[ORCH][LLM] compliance: {} règle(s) échouée(s) → DENY", fail_count);
            return "DENY";
        }

        // Erreur du scanner → prudence
        if result.get("status").and_then(|s| s.as_str()) == Some("ERROR") {
            println!("[ORCH][LLM] compliance scanner en erreur → DENY");
            return "DENY";
        }

        println!("[ORCH][LLM] compliance OK (0 FAIL)");
    }

    // Vérifier le scan statique CVE : présence de vulnérabilités CRITICAL → DENY
    if let Some(ref result) = decision.static_scan_result {
        if result.get("status").and_then(|s| s.as_str()) == Some("ERROR") {
            println!("[ORCH][LLM] scanner CVE en erreur → DENY");
            return "DENY";
        }

        // Chercher un compteur CRITICAL dans le résultat JSON
        let has_critical = result
            .get("Results")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter().any(|res| {
                    res.get("Vulnerabilities")
                        .and_then(|v| v.as_array())
                        .map(|vulns| {
                            vulns.iter().any(|vuln| {
                                vuln.get("Severity")
                                    .and_then(|s| s.as_str())
                                    .map(|s| s == "CRITICAL")
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        if has_critical {
            println!("[ORCH][LLM] CVE CRITICAL détecté → DENY");
            return "DENY";
        }

        println!("[ORCH][LLM] scan statique : pas de CVE CRITICAL");
    }

    "ALLOW"
}

// ===================
// Handler principal
// ===================

async fn decide(mut mp: Multipart) -> impl IntoResponse {
    let mut decision_state: &'static str = "PENDING";
    let mut ctx: Option<PullContext> = None;
    let mut files_received = false;

    // Lire tous les champs multipart
    while let Some(field) = match mp.next_field().await {
        Ok(f) => f,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("multipart read error: {e}")).into_response();
        }
    } {
        let name = field.name().unwrap_or("").to_string();

        if name == "context" {
            let text = match field.text().await {
                Ok(t) => t,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("context read error: {e}")).into_response();
                }
            };
            match serde_json::from_str::<PullContext>(&text) {
                Ok(parsed) => ctx = Some(parsed),
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("context json invalid: {e}")).into_response();
                }
            }
            continue;
        }

        // Détecter si des fichiers sont présents (manifests, blobs, referrers)
        match name.as_str() {
            "manifests" | "manifest" | "blobs" | "blob" | "referrers" | "referrer" => {
                let bytes: Bytes = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return (StatusCode::BAD_REQUEST, format!("file read error: {e}")).into_response();
                    }
                };
                let digest = sha256_digest(&bytes);
                println!(
                    "[ORCH] fichier reçu | kind={} digest={} size={}",
                    name, digest, bytes.len()
                );
                files_received = true;
                // Les fichiers sont déjà dans la quarantaine (peuplée par le proxy).
                // llm-decision lit directement depuis la quarantaine — pas besoin de les
                // transférer ici.
            }
            _ => {
                // Consommer le champ pour ne pas bloquer le multipart
                let _ = field.bytes().await;
            }
        }
    }

    let ctx = match ctx {
        Some(c) => c,
        None => {
            return (StatusCode::BAD_REQUEST, "champ multipart 'context' manquant").into_response();
        }
    };

    println!(
        "[ORCH] pull_id={} image={}/{}:{} completed={} files={}",
        ctx.uuid, ctx.registry, ctx.repository, ctx.tag, ctx.pull_completed, files_received
    );

    if files_received {
        if !ctx.pull_completed {
            // Pull en cours — la quarantaine n'est pas encore complète.
            // On retourne PENDING ; l'orchestrateur sera rappelé avec pull_completed=true.
            println!("[ORCH] pull en cours, quarantaine incomplète → PENDING");
            decision_state = "PENDING";
        } else {
            // Pull terminé — appeler llm-decision pour analyse + exécution des scans.
            println!("[ORCH] pull complet → appel llm-decision sur {}", LLM_DECISION_URL);

            let http = reqwest::Client::new();
            match http.post(LLM_DECISION_URL).json(&ctx).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        match resp.json::<ScanDecision>().await {
                            Ok(scan_decision) => {
                                println!(
                                    "[ORCH] ScanDecision reçu — static={} compliance={} dynamic={}",
                                    scan_decision.run_static_scan,
                                    scan_decision.run_compliance_scan,
                                    scan_decision.run_dynamic_scan,
                                );
                                println!("[ORCH] Rationale: {}", scan_decision.arbiter_rationale);
                                decision_state = evaluate_scan_decision(&scan_decision);
                                println!("[ORCH] décision finale : {}", decision_state);
                            }
                            Err(e) => {
                                println!("[ORCH] erreur parsing ScanDecision: {e} → DENY");
                                decision_state = "DENY";
                            }
                        }
                    } else {
                        println!("[ORCH] llm-decision HTTP {} → DENY", status);
                        decision_state = "DENY";
                    }
                }
                Err(e) => {
                    println!("[ORCH] llm-decision injoignable: {e} → DENY");
                    decision_state = "DENY";
                }
            }
        }
    } else {
        // Aucun fichier → requête HEAD du client Docker, analyse haut niveau.
        println!("[ORCH] HEAD détecté → analyse haut niveau");

        let http = reqwest::Client::new();
        match http.post(HL_URL).json(&ctx).send().await {
            Ok(r) => {
                println!("[ORCH][HIGH] status={}", r.status());
                match r.json::<HighLevelResp>().await {
                    Ok(body) => {
                        println!("[ORCH][HIGH] pull_id={}", body.pull_id);
                        println!("[ORCH][HIGH] opinion:\n{}", body.opinion);
                        match extract_result_score(&body.opinion) {
                            Some(score) => {
                                println!("[ORCH][HIGH] score={}", score);
                                decision_state = if score > 75 { "PENDING" } else { "DENY" };
                                println!("[ORCH][HIGH] decision={}", decision_state);
                            }
                            None => {
                                println!("[ORCH][HIGH] score absent/invalide → DENY");
                                decision_state = "DENY";
                            }
                        }
                    }
                    Err(e) => {
                        println!("[ORCH][HIGH] erreur json: {e}");
                        decision_state = "DENY";
                    }
                }
            }
            Err(e) => {
                println!("[ORCH][HIGH] scanner injoignable: {e}");
                decision_state = "DENY";
            }
        }
    }

    (
        StatusCode::OK,
        Json(DecisionResp {
            pull_id: ctx.uuid,
            state: decision_state,
        }),
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/v1/decision", post(decide))
        .route("/", get(auth::login_page))
        .route("/login", post(auth::login_submit))
        .route("/dashboard/dev", get(auth::dev_dashboard))
        .route("/dashboard/rssi", get(auth::rssi_dashboard))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024)); // 1 GB

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    println!("Orchestrateur listening on http://{addr}");
    println!("llm-decision URL : {}", LLM_DECISION_URL);

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}
