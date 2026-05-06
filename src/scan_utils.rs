use crate::models::{PullContext, PullContextList, ScanDecision};
use crate::utils::{is_safe_digest_component, quarantine_base};
use reqwest::multipart;
use std::time::Duration;
use uuid::Uuid;

/// 🔐 Politique de sécurité (async)
/// ALLOW ou PENDING => true (on continue)
/// DENY => false (on bloque direct)
pub async fn launch_final_scan(
    pull_contexts: &PullContextList,
    uuid: Uuid,
    path: &str,
) -> Option<ScanDecision> {
    // 1️⃣ récupérer le contexte
    let mut ctx_clone;
    {
        let mut list = pull_contexts.lock().await;
        let ctx = list.iter_mut().find(|c| c.uuid == uuid)?;

        // sécurité : scan déjà lancé ?
        if ctx.scan_final_done {
            return None;
        }

        ctx.scan_final_done = true;
        ctx_clone = ctx.clone();
    }
    // 🔴 on sort du mutex ici

    println!("[SCAN FINAL] lancement pour uuid={}", uuid);

    // 2️⃣ appel scanner
    let state = match is_allowed(&mut ctx_clone, path, "scan_final").await {
        Err(e) => {
            eprintln!("[ORCH ERROR] {}", e);
            return None; // ← fail closed
        }
        Ok(s) => s,
    };

    let mut list = pull_contexts.lock().await;
    let _ctx = list.iter_mut().find(|c| c.uuid == uuid)?;

    if state == "ALLOW" {
        return Some(ScanDecision::ALLOW);
    }

    if state == "PENDING" {
        return Some(ScanDecision::PENDING);
    }

    if state == "DENY" {
        return Some(ScanDecision::DENY);
    }

    println!("[SCAN FINAL] état inconnu");
    None
}

pub async fn is_allowed(ctx: &mut PullContext, path: &str, flag: &str) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct OrchestratorResp {
        pull_id: uuid::Uuid,
        state: String, // "PENDING" | "ALLOW" | "DENY"
    }

    let orch_url = std::env::var("ORCH_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000/v1/decision".to_string());

    println!("============================== APPEL ORCHESTRATEUR ==============================");
    println!("uuid={} repo={}:{}", ctx.uuid, ctx.repository, ctx.tag);

    // 1) context inchangé
    let mut form = multipart::Form::new().text(
        "context",
        serde_json::to_string(ctx).unwrap_or_else(|_| "{}".to_string()),
    );

    async fn add_file_if_exists(
        form: multipart::Form,
        field_name: &'static str,
        filename: String,
        path: String,
    ) -> multipart::Form {
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                if bytes.is_empty() {
                    println!("[ORCH WARN] fichier vide: {}", path);
                    return form;
                }

                //println!("[ORCH INFO] ajout fichier: {}", path);

                let mime = if path.contains("/manifests/") || path.contains("/referrers/") {
                    "application/json"
                } else {
                    "application/octet-stream"
                };

                // Renommer le fichier pour éviter les ':' dans le nom
                let safe_filename = filename.replace(":", "_");

                let part = multipart::Part::bytes(bytes)
                    .file_name(safe_filename)
                    .mime_str(mime)
                    .unwrap();

                form.part(field_name, part)
            }
            Err(e) => {
                println!("[ORCH WARN] fichier introuvable: {} ({})", path, e);
                form
            }
        }
    }

    let base_dir = format!("{}/{}/{}", quarantine_base(), ctx.registry, ctx.repository);

    // =====================================================================
    // SCAN FINAL → envoyer TOUS les digests de l'image
    // =====================================================================
    println!("flag : {} : ", flag);

    if flag == "scan_final" {
        println!("[ORCH] SCAN FINAL -> envoi de tous les digests de l'image");

        // ---------------- manifests ----------------
        for d in &ctx.manifest_digests {
            let digest = d.as_str();
            let parts: Vec<&str> = digest.split(':').collect();
            if parts.len() == 2 {
                let algo = parts[0];
                let value = parts[1];

                if !is_safe_digest_component(algo) || !is_safe_digest_component(value) {
                    eprintln!("[SECURITY] Digest manifest invalide ignoré: {}", digest);
                    return Err(format!("Digest invalide détecté: {}", digest));
                }

                let filename = digest.clone();
                let file_path = format!("{}/manifests/{}/{}.json", base_dir, algo, value);

                form = add_file_if_exists(form, "manifests", filename, file_path).await;
            }
        }

        // ---------------- blobs ----------------
        for d in &ctx.blob_digests {
            let digest = d.as_str();
            let parts: Vec<&str> = digest.split(':').collect();
            if parts.len() == 2 {
                let algo = parts[0];
                let value = parts[1];

                if !is_safe_digest_component(algo) || !is_safe_digest_component(value) {
                    eprintln!("[SECURITY] Digest manifest invalide ignoré: {}", digest);
                    return Err(format!("Digest invalide détecté: {}", digest));
                }

                let filename = digest.clone();
                let file_path = format!("{}/blobs/{}/{}", base_dir, algo, value);

                form = add_file_if_exists(form, "blobs", filename, file_path).await;
            }
        }

        // ---------------- referrers ----------------
        for d in &ctx.referrers_digests {
            let digest = d.as_str();
            let parts: Vec<&str> = digest.split(':').collect();
            if parts.len() == 2 {
                let algo = parts[0];
                let value = parts[1];

                if !is_safe_digest_component(algo) || !is_safe_digest_component(value) {
                    eprintln!("[SECURITY] Digest manifest invalide ignoré: {}", digest);
                    return Err(format!("Digest invalide détecté: {}", digest));
                }

                let filename = digest.clone();
                let file_path = format!("{}/referrers/{}/{}.json", base_dir, algo, value);

                form = add_file_if_exists(form, "referrers", filename, file_path).await;
            }
        }

        println!("[ORCH] SCAN FINAL -> tous les fichiers ajoutés au multipart");
    }
    //Cas scan haut niveau podman (sur le GET /manifest/<tag>)
    else if path.contains("/manifests/") && !path.contains("sha256:") {
        if flag != "scan_haut_niveau" {
            // ← ne pas joindre le manifest pour le premier call
            if let Some(racine) = &ctx.manifest_racine_digest {
                let digest = racine.as_str();
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];
                    let file_path = format!("{}/manifests/{}/{}.json", base_dir, algo, value);
                    println!("[ORCH] manifest racine (par tag) détecté: {}", file_path);
                    form = add_file_if_exists(form, "manifests", digest.clone(), file_path).await;
                }
            }
        }
    }
    // ------------------------------------------------------------------
    // On envoie uniquement le digest demandé dans l'URL
    // ------------------------------------------------------------------
    else {
        if let Some(pos) = path.find("sha256:") {
            let digest = &path[pos..];
            println!("[ORCH] digest courant détecté: {}", digest);

            if path.contains("/manifests/") {
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];

                    let filename = digest.to_string();
                    let file_path = format!("{}/manifests/{}/{}.json", base_dir, algo, value);

                    form = add_file_if_exists(form, "manifests", filename, file_path).await;
                }
            } else if path.contains("/blobs/") {
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];

                    let filename = digest.to_string();
                    let file_path = format!("{}/blobs/{}/{}", base_dir, algo, value);

                    println!("[ORCH] fichier blob attendu: {}", file_path);

                    form = add_file_if_exists(form, "blobs", filename, file_path).await;
                }
            } else if path.contains("/referrers/") {
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];

                    let filename = digest.to_string();
                    let file_path = format!("{}/referrers/{}/{}.json", base_dir, algo, value);

                    form = add_file_if_exists(form, "referrers", filename, file_path).await;
                }
            }
        }
        // ← CAS PODMAN : path par tag, pas de sha256: dans le path
        else if path.contains("/manifests/")
            && !path.contains("sha256:")
            && flag != "scan_haut_niveau"
        {
            // Utiliser le manifest_racine_digest du contexte
            if let Some(racine) = &ctx.manifest_racine_digest {
                let digest = racine.as_str(); // "sha256:d1e2e92c..."
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];

                    let filename = digest.clone();
                    let file_path = format!("{}/manifests/{}/{}.json", base_dir, algo, value);

                    println!("[ORCH] manifest racine (par tag) détecté: {}", file_path);
                    form = add_file_if_exists(form, "manifests", filename, file_path).await;
                }
            }
        }
    }

    println!("file_path : {}", base_dir);

    // 5) POST multipart
    let client = reqwest::Client::new();

    let state: Result<String, String> = match tokio::time::timeout(
        Duration::from_secs(std::env::var("ORCH_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(120)),
        client.post(orch_url).multipart(form).send(),
    )
    .await
    {
        Err(_) => {
            // ← Err du timeout (elapsed)
            eprintln!("[ORCH TIMEOUT] Orchestrateur ne répond pas");
            return Err("Timeout orchestrateur".to_string());
        }
        Ok(Err(e)) => {
            // ← Err réseau
            eprintln!("[ORCH CALL] request error: {:?}", e);
            return Err(format!("Erreur réseau: {}", e));
        }
        Ok(Ok(r)) => {
            let status = r.status();
            println!("[ORCH CALL] status={}", status);
            let text = r.text().await.unwrap_or_default();
            println!("[ORCH RAW RESP] {}", text);

            if !status.is_success() {
                println!("[ORCH ERROR] orchestrateur a renvoyé non-200");
                return Ok("PENDING".to_string());
            }

            match serde_json::from_str::<OrchestratorResp>(&text) {
                Ok(body) => {
                    println!("[ORCH RESP] pull_id={} state={}", body.pull_id, body.state);
                    Ok(body.state.trim().to_uppercase())
                }
                Err(e) => {
                    println!("[ORCH PARSE ERROR] {:?}", e);
                    Ok("PENDING".to_string())
                }
            }
        }
    };

    println!("==================================================================================");

    let state_str = match state {
        Ok(ref s) => s.clone(),
        Err(ref e) => return Err(e.clone()),
    };

    match state_str.as_str() {
        "ALLOW" => {
            println!("Pull autorisé par l'orchestrateur");
            ctx.scan_status = Some("ALLOW".to_string());
        }
        "PENDING" => {
            println!("Pull en attente, décision non finale");
            ctx.scan_status = Some("PENDING".to_string());
        }
        "DENY" => {
            println!("Pull refusé par l'orchestrateur");
            ctx.scan_status = Some("DENY".to_string());
        }
        other => {
            println!("[WARNING] État inattendu reçu: {}", other);
        }
    }

    Ok(state_str)
}
