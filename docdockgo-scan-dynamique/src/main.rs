use std::thread;
use std::time::{Duration, SystemTime, Instant};
use std::process::Command;
use std::path::Path;
use std::collections::HashMap;
use std::io::{self, Write};
use anyhow::{Context, Result};
use serde_json::Value;
use axum::{routing::{post, get}, Router, Json};
use serde::{Deserialize, Serialize};

mod sandbox;
use sandbox::docker::{
    connect,
    run_sandbox_container,
    ensure_analysis_network,
    wait_container,
    cleanup_container,
    wait_container_removal,
    SandboxMode,
};

// ─────────────────────────────────────────────
// STRUCTURES API
// ─────────────────────────────────────────────
#[derive(Deserialize)]
struct ScanRequest {
    image: String,
    /// "vm" = Firecracker (défaut), "docker" = sandbox Docker directe
    #[serde(default = "default_mode")]
    mode: String,
}
fn default_mode() -> String { "vm".to_string() }

#[derive(Serialize, Deserialize, Clone)]
struct ScanResponse {
    image:    String,
    score:    u32,
    critical: bool,
    verdict:  String,
    allowed:  bool,
    mode:     String,
    /// Compteur par règle pour transparence du scoring
    rule_counts: HashMap<String, u32>,
    details:  Vec<String>,
}

// ─────────────────────────────────────────────
// VÉRIFICATION ENVIRONNEMENT
// ─────────────────────────────────────────────
fn check_environment() {
    let mut issues = false;

    match Command::new("systemctl")
        .args(["is-active", "falco-ddg"])
        .output()
    {
        Ok(output) => {
            let status = String::from_utf8_lossy(&output.stdout);
            if !status.trim().contains("active") {
                println!("[!] Falco DDG non actif sur l'hôte");
            } else {
                println!("[✓] Falco DDG actif sur l'hôte");
            }
        }
        Err(_) => println!("[!] Falco non détecté sur l'hôte"),
    }

    if !Path::new("/usr/local/bin/firecracker").exists() {
        println!("[!] Firecracker non installé → lancez : sudo bash setup_firecracker.sh");
        issues = true;
    } else {
        println!("[✓] Firecracker présent");
    }

    if !Path::new("/opt/firecracker/ddg-rootfs.ext4").exists() {
        println!("[!] Rootfs VM absent → lancez : sudo bash setup_firecracker.sh");
        issues = true;
    } else {
        println!("[✓] Rootfs VM présent");
    }

    if !Path::new("/dev/kvm").exists() {
        println!("[!] /dev/kvm absent — activez VT-x/AMD-V dans le BIOS");
        issues = true;
    } else {
        println!("[✓] KVM disponible");
    }

    if issues {
        println!("\n[!] Problèmes détectés — certains modes peuvent échouer");
        println!("[!] Setup complet : sudo bash setup_firecracker.sh");
    }
}

// ─────────────────────────────────────────────
// SCAN VIA FIRECRACKER
// ─────────────────────────────────────────────
async fn run_scan_firecracker(image: &str) -> Result<ScanResponse> {
    println!("[FC] Démarrage scan Firecracker : {}", image);
    let script = find_script("scan_vm.sh")?;

    let output = tokio::process::Command::new("sudo")
        .args(["bash", &script, image])
        .output()
        .await
        .context("Impossible de lancer scan_vm.sh")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !stderr.is_empty() {
        println!("[FC] stderr: {}", stderr);
    }

    parse_vm_result(&stdout, image)
}

fn parse_vm_result(output: &str, _image: &str) -> Result<ScanResponse> {
    // Strip ANSI codes et caractères non-ASCII
    let clean: String = output
        .lines()
        .map(|line| {
            // Retire les codes ANSI (\x1b[...m)
            let mut result = String::new();
            let mut chars = line.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    // Skip jusqu'à la fin du code ANSI
                    while let Some(&nc) = chars.peek() {
                        chars.next();
                        if nc.is_ascii_alphabetic() { break; }
                    }
                } else {
                    result.push(c);
                }
            }
            result
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Cherche le JSON ligne par ligne
    for line in clean.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            if let Ok(response) = serde_json::from_str::<ScanResponse>(trimmed) {
                return Ok(response);
            }
        }
    }

    // Fallback : cherche le JSON entre { et }
    if let Some(start) = clean.find('{') {
        if let Some(end) = clean.rfind('}') {
            let json_str = &clean[start..=end];
            if let Ok(response) = serde_json::from_str::<ScanResponse>(json_str) {
                return Ok(response);
            }
        }
    }

    anyhow::bail!(
        "Impossible de parser le résultat VM.\nSortie reçue:\n{}",
        &output[..output.len().min(500)]
    )
}

fn find_script(name: &str) -> Result<String> {
    let candidates = vec![
        format!("./{}", name),
        format!("/opt/firecracker/{}", name),
        format!("/home/{}/{}", std::env::var("USER").unwrap_or_default(), name),
    ];

    for path in &candidates {
        if Path::new(path).exists() {
            return Ok(path.clone());
        }
    }

    anyhow::bail!("Script '{}' introuvable.", name)
}

// ─────────────────────────────────────────────
// SCAN VIA DOCKER DIRECT
// ─────────────────────────────────────────────
async fn run_scan_docker(image: &str) -> Result<ScanResponse> {
    println!("[Docker] Scan direct (sans VM) : {}", image);

    let docker = connect().await?;
    ensure_analysis_network(&docker).await?;

    if docker.inspect_image(image).await.is_err() {
        println!("[+] Pull : {}", image);
        let status = tokio::process::Command::new("docker")
            .args(["pull", image])
            .status().await?;
        if !status.success() {
            anyhow::bail!("docker pull échoué pour '{}'", image);
        }
    } else {
        println!("[✓] Image locale : {}", image);
    }

    let (max_rt, warmup, inactivity) = estimate_timeouts(&docker, image).await;

    // Vide les logs
    let _ = std::fs::write("/var/log/falco.log", "");
    let start_time = SystemTime::now();

    let container_name = run_sandbox_container(
        &docker, image, SandboxMode::Observe
    ).await?;
    println!("[+] Container : {}", container_name);

    // Récupère le container_id complet pour matching alternatif
    let container_id = match docker.inspect_container(&container_name, None).await {
        Ok(info) => info.id.unwrap_or_default(),
        Err(_)   => String::new(),
    };

    monitor_container(&docker, &container_name, max_rt, warmup, inactivity).await;

    let logs = std::fs::read_to_string("/var/log/falco.log")
        .unwrap_or_default();

    let (score, critical, rule_counts, details) =
        analyze_logs(&logs, start_time, &container_name, &container_id);

    wait_container(&docker, &container_name).await;
    cleanup_container(&docker, &container_name).await;
    wait_container_removal(&docker, &container_name).await;

    let verdict = score_to_verdict(score);
    let allowed = score < 60 && !critical;

    Ok(ScanResponse {
        image:   image.to_string(),
        score,
        critical,
        verdict,
        allowed,
        mode:    "docker".to_string(),
        rule_counts,
        details: details.values().flatten().cloned().collect(),
    })
}

async fn run_scan_pipeline(image: &str, mode: &str) -> Result<ScanResponse> {
    match mode {
        "docker" => run_scan_docker(image).await,
        _        => {
            if Path::new("/usr/local/bin/firecracker").exists()
            && Path::new("/opt/firecracker/ddg-rootfs.ext4").exists() {
                run_scan_firecracker(image).await
            } else {
                println!("[!] Firecracker indisponible → fallback Docker");
                run_scan_docker(image).await
            }
        }
    }
}

// ─────────────────────────────────────────────
// SCORING — Plus précis et granulaire
// ─────────────────────────────────────────────

/// Score de base par règle (avant bonus de fréquence)
///
/// Logique :
/// - 60+ : règles critiques (modification système, fork bomb, accès root)
/// - 30-50 : règles importantes (mount, accès fichiers sensibles)
/// - 15-25 : règles d'observation (shell, réseau)
/// - 10 : par défaut
fn base_score_for_rule(rule: &str) -> u32 {
    // CRITICAL — comportements clairement malveillants
    if rule.contains("System File Modification")    { return 70; }  // /etc/passwd, /etc/shadow modifié
    if rule.contains("Fork Bomb")                   { return 65; }  // attaque DoS
    if rule.contains("Privilege Escalation")        { return 60; }
    if rule.contains("Container Escape")            { return 75; }

    // HIGH — comportements suspects
    if rule.contains("Sensitive File Access")       { return 45; }  // lecture /etc/shadow, etc.
    if rule.contains("Read sensitive file")         { return 40; }  // règle Falco par défaut
    if rule.contains("Mount")                       { return 35; }  // montage de filesystems
    if rule.contains("Crypto")                      { return 50; }  // mining crypto
    if rule.contains("Reverse Shell")               { return 70; }
    if rule.contains("Clear Log")                   { return 55; }  // anti-forensic

    // MEDIUM — comportements à surveiller
    if rule.contains("Outbound")                    { return 25; }  // connexion sortante
    if rule.contains("Suspicious Network")          { return 30; }
    if rule.contains("Package Management")          { return 20; }  // apt, apk dans container

    // LOW — observations
    if rule.contains("Shell Spawn")                 { return 15; }
    if rule.contains("Process")                     { return 12; }

    // Par défaut
    10
}

/// Indique si une règle déclenche le flag critical
fn is_critical_rule(rule: &str) -> bool {
    rule.contains("System File Modification")
        || rule.contains("Fork Bomb")
        || rule.contains("Privilege Escalation")
        || rule.contains("Container Escape")
        || rule.contains("Reverse Shell")
        || rule.contains("Crypto")
}

fn score_to_verdict(score: u32) -> String {
    match score {
        0       => "CLEAN",
        1..=29  => "LOW",
        30..=59 => "MODERATE",
        60..=89 => "HIGH",
        _       => "CRITICAL",
    }.to_string()
}

/// Analyse les logs Falco JSON et calcule le score.
///
/// Match container par :
///   - container_name (long)
///   - container_id (12 premiers chars Docker)
///
/// Cela évite de rater les alertes qui apparaissent avec
/// container=<NA> mais qui ont bien le bon container_id.
fn analyze_logs(
    logs: &str,
    start_time: SystemTime,
    container_name: &str,
    container_id: &str,
) -> (u32, bool, HashMap<String, u32>, HashMap<String, Vec<String>>) {
    let mut total_score: f32 = 0.0;
    let mut critical = false;
    let mut counters: HashMap<String, u32>         = HashMap::new();
    let mut details:  HashMap<String, Vec<String>> = HashMap::new();

    let start_unix = start_time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Container ID court (Docker affiche 12 chars dans les logs Falco)
    let cid_short = if container_id.len() >= 12 {
        &container_id[..12]
    } else {
        container_id
    };

    for line in logs.lines() {
        let json: Value = match serde_json::from_str(line) {
            Ok(v)  => v,
            Err(_) => continue,
        };

        // Match par container_name OU container_id court
        let output = match json["output"].as_str() {
            Some(o) if o.contains(container_name)
                    || (!cid_short.is_empty() && o.contains(cid_short)) => o,
            _ => continue,
        };

        // Filtre temporel : on ignore les alertes antérieures au scan
        if let Some(time_str) = json["time"].as_str() {
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(time_str) {
                if (t.timestamp() as u64) < start_unix { continue; }
            }
        }

        if let Some(rule) = json["rule"].as_str() {
            *counters.entry(rule.to_string()).or_insert(0) += 1;

            if is_critical_rule(rule) {
                critical = true;
            }

            let entry = details.entry(rule.to_string()).or_default();
            if entry.len() < 5 {
                entry.push(output.to_string());
            }
        }
    }

    // Calcul du score : base + bonus log de fréquence (plafonné)
    for (rule, &count) in &counters {
        let base       = base_score_for_rule(rule) as f32;
        let freq_bonus = if count > 1 {
            (count as f32).log2() * 5.0
        } else {
            0.0
        };
        total_score += base + freq_bonus.min(20.0);
    }

    let final_score = (total_score as u32).min(100);

    // Résumé console
    println!("\n===== FALCO ALERT SUMMARY =====");
    println!("{:<45} {:>12} {:>10}", "Règle", "Occurrences", "Score");
    println!("{}", "-".repeat(70));
    let mut sorted: Vec<_> = counters.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (rule, count) in &sorted {
        let base       = base_score_for_rule(rule) as f32;
        let freq_bonus = if **count > 1 {
            (**count as f32).log2() * 5.0
        } else {
            0.0
        };
        let rule_score = base + freq_bonus.min(20.0);
        println!("[!] {:<42} × {:>4}   +{:>5.1}", rule, count, rule_score);
    }
    println!("{}", "-".repeat(70));
    println!("    TOTAL : {} (cappé à 100)", final_score);
    println!("==============================\n");

    (final_score, critical, counters, details)
}

// ─────────────────────────────────────────────
// ESTIMATION TIMEOUTS
// ─────────────────────────────────────────────
async fn estimate_timeouts(
    docker: &bollard::Docker,
    image: &str,
) -> (Duration, Duration, Duration) {
    let size_mb = match docker.inspect_image(image).await {
        Ok(info) => info.size.unwrap_or(0) as u64 / (1024 * 1024),
        Err(_)   => 200,
    };

    let (max_s, warm_s, inact_s) = match size_mb {
        0..=100    => (120,  5, 10),
        101..=500  => (240, 15, 20),
        501..=1024 => (360, 30, 25),
        _          => (600, 60, 30),
    };

    (
        Duration::from_secs(max_s),
        Duration::from_secs(warm_s),
        Duration::from_secs(inact_s),
    )
}

// ─────────────────────────────────────────────
// MONITORING
// ─────────────────────────────────────────────
#[derive(Debug, PartialEq)]
enum MonitorState { WarmingUp, WaitingForFirstActivity, Watching }

async fn monitor_container(
    docker: &bollard::Docker,
    container: &str,
    max_runtime: Duration,
    warmup: Duration,
    inactivity: Duration,
) {
    let start             = Instant::now();
    let mut last_activity = Instant::now();
    let mut last_log_size = std::fs::metadata("/var/log/falco.log")
                                .map(|m| m.len() as usize)
                                .unwrap_or(0);
    let mut state         = MonitorState::WarmingUp;

    loop {
        thread::sleep(Duration::from_secs(2));

        if let Ok(info) = docker.inspect_container(container, None).await {
            if let Some(s) = info.state {
                if !s.running.unwrap_or(true) {
                    println!("[+] Container terminé");
                    break;
                }
            }
        }

        if start.elapsed() > max_runtime {
            println!("[!] Timeout global");
            break;
        }

        let cur = std::fs::metadata("/var/log/falco.log")
            .map(|m| m.len() as usize).unwrap_or(0);

        if cur > last_log_size {
            println!("[~] Activité Falco +{} octets", cur - last_log_size);
            last_log_size = cur;
            last_activity = Instant::now();
            if state != MonitorState::Watching {
                state = MonitorState::Watching;
            }
        }

        match state {
            MonitorState::WarmingUp => {
                if start.elapsed() >= warmup {
                    state = if last_log_size > 0 {
                        MonitorState::Watching
                    } else {
                        MonitorState::WaitingForFirstActivity
                    };
                }
            }
            MonitorState::WaitingForFirstActivity => {}
            MonitorState::Watching => {
                if last_activity.elapsed() > inactivity {
                    println!("[+] Inactivité → fin observation");
                    break;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────
// AFFICHAGE SCORE (CLI)
// ─────────────────────────────────────────────
fn print_score_legend(response: &ScanResponse) {
    println!("\n========== SCORE : {}/100 [mode: {}] ==========",
             response.score, response.mode);

    let (label, desc) = match response.score {
        0       => ("✅ PROPRE",    "Aucun comportement suspect."),
        1..=29  => ("🟡 FAIBLE",   "Comportement mineur."),
        30..=59 => ("🟠 MODÉRÉ",   "Analyse manuelle recommandée."),
        60..=89 => ("🔴 ÉLEVÉ",    "Comportements malveillants avérés."),
        _       => ("💀 CRITIQUE", "Image hautement malveillante."),
    };

    println!("  Niveau  : {}", label);
    println!("  Verdict : {}", desc);

    if response.critical {
        println!("  ⚠️  FLAG CRITIQUE détecté !");
    }

    if !response.rule_counts.is_empty() {
        println!("\n  Règles déclenchées :");
        let mut sorted: Vec<_> = response.rule_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (rule, count) in sorted {
            println!("    • {} × {}", rule, count);
        }
    }

    println!("================================================\n");
}

// ─────────────────────────────────────────────
// HANDLER HTTP
// ─────────────────────────────────────────────
async fn handle_scan(Json(req): Json<ScanRequest>) -> Json<ScanResponse> {
    println!("\n[HTTP] Scan : {} (mode: {})", req.image, req.mode);

    match run_scan_pipeline(&req.image, &req.mode).await {
        Ok(r) => {
            if r.allowed {
                println!("[HTTP] ✅ {} — score: {}", r.image, r.score);
            } else {
                println!("[HTTP] ❌ {} BLOQUÉE — score: {}", r.image, r.score);
            }
            Json(r)
        }
        Err(e) => {
            println!("[HTTP] ❌ Erreur : {}", e);
            Json(ScanResponse {
                image:    req.image,
                score:    100,
                critical: true,
                verdict:  "ERROR".to_string(),
                allowed:  false,
                mode:     req.mode,
                rule_counts: HashMap::new(),
                details:  vec![format!("Erreur : {}", e)],
            })
        }
    }
}

async fn start_api_server() -> Result<()> {
    let app = Router::new()
        .route("/scan",   post(handle_scan))
        .route("/health", get(|| async { "DockDockGo OK" }));

    let addr = "0.0.0.0:8080";
    println!("[+] Scanner HTTP : http://{}", addr);
    println!("[+] POST /scan  → lancer un scan");
    println!("[+] GET  /health → healthcheck");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn run_cli_scan(image: &str, mode: &str) -> Result<()> {
    let response = run_scan_pipeline(image, mode).await?;
    print_score_legend(&response);

    print!("Voir les détails Falco ? (y/n) : ");
    io::stdout().flush().unwrap();

    let mut answer = String::new();
    io::stdin().read_line(&mut answer).unwrap();

    if answer.trim().eq_ignore_ascii_case("y") {
        println!("\n===== DÉTAILS =====");
        for (i, d) in response.details.iter().enumerate() {
            println!("  {}. {}", i + 1, d);
        }
        println!("===================\n");
    }

    println!("========== END OF SCAN ==========\n");
    Ok(())
}

// ─────────────────────────────────────────────
// POINT D'ENTRÉE
// ─────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    println!("\n══════════════════════════════════════");
    println!("  DockDockGo Dynamic Scanner v2");
    println!("══════════════════════════════════════\n");

    check_environment();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("--server") => {
            start_api_server().await?;
        }
        Some(image) => {
            let mode = if args.contains(&"--docker".to_string()) {
                "docker"
            } else {
                "vm"
            };
            println!("[+] Image : {} | Mode : {}", image, mode);
            run_cli_scan(image, mode).await?;
        }
        None => {
            println!("Usage:");
            println!("  cargo run -- <image>           → scan via Firecracker VM");
            println!("  cargo run -- <image> --docker  → scan via Docker direct");
            println!("  cargo run -- --server          → HTTP server");
            println!("\nExemples :");
            println!("  cargo run -- nginx:latest");
            println!("  cargo run -- dockdockgo-evil");
            println!("  cargo run -- python:3.11-slim --docker");
        }
    }

    Ok(())
}