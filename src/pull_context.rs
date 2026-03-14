
use hyper::{Body, Method, Request};
use reqwest::Client;
use uuid::Uuid;
use std::time::Instant;
use anyhow::Result;
use crate::registry_auth::RegistryClient;
use crate::{
    PullContext,
    PullContextList,
    PullContextError,
    Digest,
};

use crate::{
    store_digest,
    get_os_arch_for_digest,
    predict_digests_docker,
    is_allowed,
    add_context_to_blacklist_or_whitelist,
    cleanup_tmp_for_uuid,
    check_manifest_in_list,
    predict_digests_podman,
};


/// 🔄 Récupération ou création du contexte PullContext
pub async fn get_pull_context(
    req: &Request<Body>,
    parts: &[&str],
    client_ip: &str,
    pull_contexts: &PullContextList,
    client: &Client, 
    path: &str,
    client_type: &str,
    pool: &sqlx::PgPool

)-> Result<Option<Uuid>, PullContextError> //Retourne soit l'uuid du contexte trouvé (cas success) soit une erreur PullContextError
{

    // 🔹 Extraire le registre de la requete 
    //let registry = "registry-1.docker.io".to_string(); // Par défaut pour Docker Hub
    let registry = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("registry-1.docker.io")
        .to_string();

    // 🔹 Déterminer le type de ressource et son index
    let (resource_type, idx) = if let Some(i) = parts.iter().position(|p| *p == "manifests") {
        ("manifests", i)
    } else if let Some(i) = parts.iter().position(|p| *p == "blobs") {
        ("blobs", i)
    } else if let Some(i) = parts.iter().position(|p| *p == "referrers") {
        ("referrers", i)
    } else {
        println!("[PullContext] Type de ressource inconnu, aucun traitement possible");
        return Err(PullContextError::InvalidPath);
    };

    // 🔹 Vérifier que l'index est valide pour accéder à la valeur suivante (digest ou tag)
    if idx + 1 >= parts.len() {
        println!("[PullContext] Path invalide, digest ou tag manquant");
        return Err(PullContextError::InvalidPath);
    }

    // Extraire le repository
    let repository = parts[..idx].join("/");

    let tag_ou_digest = parts[parts.len() - 1];
    let ip_client = client_ip.to_string();

    // 🔹 HEAD → création d’un nouveau contexte pour un tag
    if req.method() == Method::HEAD {

        let uuid = create_context_from_tag(
            client, &registry, &repository, tag_ou_digest,
            &ip_client, pull_contexts, path, client_type
        ).await?;

        // ✅ Vérif whitelist/blacklist + scan haut niveau (inchangé)
        let in_whitelist = check_manifest_in_list(uuid, pull_contexts, Method::HEAD, "whitelist", &pool).await;
        let in_blacklist = check_manifest_in_list(uuid, pull_contexts, Method::HEAD, "blacklist", &pool).await;

        {
            let mut list = pull_contexts.lock().await;
            if in_whitelist.is_some() || in_blacklist.is_some() {
                println!("[GetPullContext] Déjà en whitelist/blacklist, scan skippé");
                // ← mettre à jour le scan_status pour éviter le scan par digest dans handle
                if let Some(ctx) = list.iter_mut().find(|c| c.uuid == uuid) {
                    if in_blacklist.is_some() {
                        ctx.scan_status = Some("DENY".to_string());
                    } else {
                        ctx.scan_status = Some("ALLOW".to_string());
                    }
                }
                return Ok(Some(uuid));
            }
        }

        // Scan haut niveau (inchangé)
        let mut list = pull_contexts.lock().await;
        let ctx = list.iter_mut().find(|c| c.uuid == uuid)
            .ok_or(PullContextError::ContextMismatch)?;

        match is_allowed(ctx, path, "scan_haut_niveau").await 
        {
            Err(e) => {
                eprintln!("[ORCH ERROR] {}", e);
                return Err(PullContextError::BlockingFromTheScanner);
            }
            Ok(state) => match state.as_str() 
            {

                "ALLOW" => {
                    ctx.scan_status = Some("ALLOW".to_string());
                    if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist", &pool).await {
                        eprintln!("[WHITELIST ERROR] {}", e);
                    }
                    return Ok(Some(uuid));
                }
                "PENDING" => return Ok(Some(uuid)),
                "DENY" => {
                    if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist", &pool).await {
                        eprintln!("[BLACKLIST ERROR] {}", e);
                    }
                    cleanup_tmp_for_uuid(&ctx.uuid);
                    list.retain(|c| c.uuid != uuid);
                    return Err(PullContextError::BlockingFromTheScanner);
                }
                _ => return Err(PullContextError::BlockingFromTheScanner),
            }
        }
    }


    // 🔹 GET → vérifier un digest existant
    else if req.method() == Method::GET 
    {
        let digest_str = parts[idx + 1];

        // 🔑 Podman peut envoyer un GET par tag sans HEAD préalable
        if !digest_str.starts_with("sha256:") && client_type == "podman" {
            println!("[PullContext] GET par tag détecté (Podman?) → création contexte à la volée");

            // Même fonction que HEAD → UUID déterministe, pas de doublon
            let uuid = create_context_from_tag(
                client, &registry, &repository, digest_str,
                &ip_client, pull_contexts, path, client_type
            ).await?;

            // ✅ Vérif whitelist/blacklist + scan haut niveau (inchangé)
            let in_whitelist = check_manifest_in_list(uuid, pull_contexts, Method::HEAD, "whitelist", &pool).await;
            let in_blacklist = check_manifest_in_list(uuid, pull_contexts, Method::HEAD, "blacklist", &pool).await;

            {
                let mut list = pull_contexts.lock().await;
                if in_whitelist.is_some() || in_blacklist.is_some() {
                    println!("[GetPullContext] Déjà en whitelist/blacklist, scan skippé");
                    if let Some(ctx) = list.iter_mut().find(|c| c.uuid == uuid) {
                        if in_blacklist.is_some() {
                            ctx.scan_status = Some("DENY".to_string());
                        } else {
                            ctx.scan_status = Some("ALLOW".to_string());
                        }
                    }
                    return Ok(Some(uuid));
                }
            }

            // Scan haut niveau (inchangé)
            let mut list = pull_contexts.lock().await;
            let ctx = list.iter_mut().find(|c| c.uuid == uuid)
                .ok_or(PullContextError::ContextMismatch)?;

            match is_allowed(ctx, path, "scan_haut_niveau").await {
                Err(e) => {
                    eprintln!("[ORCH ERROR] {}", e);
                    return Err(PullContextError::BlockingFromTheScanner);
                }
                Ok(state) => match state.as_str() 
                {
                    "ALLOW" => {
                        ctx.scan_status = Some("ALLOW".to_string());
                        if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist", &pool).await {
                            eprintln!("[BLACKLIST ERROR] {}", e);
                        }
                        return Ok(Some(uuid));
                    }
                    "PENDING" => 
                    {
                        ctx.scan_status = Some("PENDING".to_string());
                        return Ok(Some(uuid));
                    }
                    "DENY" => {
                        if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist", &pool).await {
                            eprintln!("[BLACKLIST ERROR] {}", e);
                        }
                        cleanup_tmp_for_uuid(&ctx.uuid);
                        list.retain(|c| c.uuid != uuid);
                        return Err(PullContextError::BlockingFromTheScanner);
                    }
                    _ => return Err(PullContextError::BlockingFromTheScanner),
            }
            }

        }

        // ✅ Cas normal : GET par digest sha256 (Docker et Podman après le HEAD)
        let digest_value = digest_str.trim_start_matches("sha256:").to_string();
        
        // 🔹 Rechercher le contexte correspondant et vérifier le digest
        let mut list = pull_contexts.lock().await;
        //parcours de la liste de context
        for ctx in list.iter_mut() 
        {
            //Verifier si le contexte correspond au client ip, registry, repository et digest possible
            if ctx.ip_client == ip_client
                && ctx.registry == registry
                && ctx.repository == repository
                && (
                    // Tant qu’on n’a qu’un seul digest attendu → mode tolérant
                    (ctx.digests_expected.len() <= 1
                        && ctx.digests_possible.iter().any(|d| d.value == digest_value))
                    ||
                    // Dès qu’on a plusieurs digests attendus → mode strict
                    (ctx.digests_expected.len() > 1
                        && ctx.digests_expected.iter().any(|d| d.value == digest_value))
                )
            {

                println!("[PullContext] Correspondance trouvée pour le digest GET | uuid={}", ctx.uuid);

                //Mise a jour de l'activité pour le timeout
                ctx.last_activity = Instant::now();


                // Déterminer dans quel vecteur stocker le digest selon le type de ressource
                let digest_struct = Digest {
                    algorithm: "sha256".to_string(),
                    value: digest_value.clone(),
                };

                // Ajouter le digest dans le vecteur approprié en garantissant l'unicité
                match resource_type {
                    "manifests" => {
                        if !ctx.manifest_digests.contains(&digest_struct) {
                            ctx.manifest_digests.push(digest_struct.clone());
                            println!("[PullContext] Digest ajouté à manifest_digests: {}", digest_struct.as_str());
                        }
                    }
                    "blobs" => {
                        if !ctx.blob_digests.contains(&digest_struct) {
                            ctx.blob_digests.push(digest_struct.clone());
                            println!("[PullContext] Digest ajouté à blob_digests: {}", digest_struct.as_str());
                        }
                    }
                    "referrers" => {
                        if !ctx.referrers_digests.contains(&digest_struct) {
                            ctx.referrers_digests.push(digest_struct.clone());
                            println!("[PullContext] Digest ajouté à referrers_digests: {}", digest_struct.as_str());
                        }
                    }
                    _ => {
                        println!("[PullContext] Type de ressource inconnu pour stockage des digests");
                    }
                }



                //si le digest racine est defini
                if let Some(racine) = &ctx.manifest_racine_digest
                {
                    //si le digest de la requete n'est pas le digest racine -> ajouter les digests contenus dans le manifest demandé
                    if racine.value != digest_value {

                        let manifest_path = format!(
                            "tmp/{}/{}.json",
                            ctx.uuid,
                            racine.value
                        );

                        
                        let manifest_bytes = std::fs::read(&manifest_path)
                            .map_err(|_| PullContextError::StorageError)?;

                        let manifest_racine_json: serde_json::Value =
                            serde_json::from_slice(&manifest_bytes)
                                .map_err(|_| PullContextError::StorageError)?;

                        // Récupérer OS/ARCH si non défini ou inconnu
                        if ctx.os.is_empty() || ctx.arch.is_empty() || ctx.os == "unknown" || ctx.arch == "unknown" {
                            // Récupérer OS/ARCH pour le digest GET
                            let (os, arch) = get_os_arch_for_digest(&manifest_racine_json, &digest_value);

                            // Stocker dans PullContext
                            ctx.os = os;
                            ctx.arch = arch;

                            println!(
                                "[GET] Digest {} → OS={}, ARCH={}",
                                digest_value, ctx.os, ctx.arch
                            );

                            // Utilisation de predict_digests avec OS/ARCH specifique 
                            let manifest_racine_digest = ctx.manifest_racine_digest.as_ref().unwrap();

                            //On appelle la bonne fonction de prediction (podman ou docker)
                            let predicted_digests = match ctx.client_type.as_str() {
                                "docker" => {
                                    match predict_digests_docker(
                                        &client,
                                        &ctx.uuid,
                                        &registry,
                                        &repository,
                                        &tag_ou_digest,
                                        &ctx.os,
                                        &ctx.arch,
                                        manifest_racine_digest,
                                    ).await {
                                        Ok(d) => d,
                                        Err(e) => {
                                            eprintln!("[PullContext] predict_digests failed: {:?}", e);
                                            return Err(PullContextError::StorageError);
                                        }
                                    }
                                }
                                "podman" => {
                                    match predict_digests_podman(
                                        &client,
                                        &ctx.uuid,
                                        &registry,
                                        &repository,
                                        &ctx.os,
                                        &ctx.arch,
                                        manifest_racine_digest,
                                    ).await {
                                        Ok(d) => d,
                                        Err(e) => {
                                            eprintln!("[PullContext] predict_digests_podman failed: {:?}", e);
                                            return Err(PullContextError::StorageError);
                                        }
                                    }
                                }
                                _ => {
                                    eprintln!("[PullContext] client_type inconnu: {}", ctx.client_type);
                                    return Err(PullContextError::StorageError);
                                }
                            };

                            //Ajout des digests attendus au contexte
                            ctx.digests_expected = predicted_digests;

                            //println!("[PullContext] Digests expected : {:?}", ctx.digests_expected);
                        }



                    }
                    else {
                        //cas ou le digest GET est le digest racine (normal, ne rien faire)
                        return Ok(Some(ctx.uuid));
                    }   
                } 
                //si le digest racine n'est pas defini  
                else 
                {
                    println!("[PullContext] Aucun digest racine défini pour ce contexte → bloqué");
                    return Err(PullContextError::DigestNotAllowed);
                }

                // Ici tu es sûr :
                // - bon client
                // - bon registry
                // - bon repository
                // - bon digest GET existant
                return Ok(Some(ctx.uuid));
            }
        }
        // Aucun contexte trouvé en parcourant la liste
        println!("[PullContext] Aucun contexte trouvé pour le digest GET demandé");

        //Le contexte n'est pas trouvé on peut donc se trouver dans le cas d'une première requete podman
        //Verifier si la requete est caracteristique d'une requete podman


        //Sinon retourner context Mismatch
        return Err(PullContextError::ContextMismatch);
    }

    //Methode ne correspond pas a HEAD ou GET
    return Err(PullContextError::ContextMismatch);
}

/// 🔹 Partie HEAD pour récupérer le manifest et stocker le digest racine
/// 🔹 Récupère uniquement le digest racine d’un tag/manifest, sans stocker le manifest
pub async fn digest_process_for_head(
    client: &Client,
    registry: &str,
    repository: &str,
    tag: &str,
) -> Result<Digest, anyhow::Error> {

    println!("[HEAD] Récupération du digest racine pour {}/{}", repository, tag);
    //On recupère pas le token de la meme façon en fonction des registres 
    let token = RegistryClient::from_registry(registry)
    .get_token(client, repository)
    .await?;

    println!("[HEAD] Token Docker récupéré");

    // 2️⃣ Télécharger le manifest associé au tag
    let manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repository, tag);

    let manifest_resp = client
        .get(&manifest_url)
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json,\
            application/vnd.docker.distribution.manifest.v2+json,\
            application/vnd.oci.image.index.v1+json,\
            application/vnd.oci.image.manifest.v1+json",
        )
        .send()
        .await?;

    if manifest_resp.status() == 404 || manifest_resp.status() == 401 {
        anyhow::bail!("[HEAD] Image introuvable: {}/{}", repository, tag);
    }
    if manifest_resp.status() == 403 {
        anyhow::bail!("[HEAD] Accès refusé: {}/{}", repository, tag);
    }

    // Extraire les headers AVANT de consommer le body
    let headers = manifest_resp.headers().clone();

    // Rate limit (depuis le clone déjà fait)
    if let Some(limit) = headers.get("ratelimit-limit") {
        println!("[RATE-LIMIT] limit = {}", limit.to_str().unwrap_or("invalid"));
    }
    if let Some(remaining) = headers.get("ratelimit-remaining") {
        let remaining_str = remaining.to_str().unwrap_or("invalid");
        println!("[RATE-LIMIT] remaining = {}", remaining_str);
        if remaining_str.starts_with('0') {
            anyhow::bail!("Docker Hub rate-limit atteint (remaining=0)");
        }
    }
    if let Some(src) = headers.get("docker-ratelimit-source") {
        println!("[RATE-LIMIT] source = {}", src.to_str().unwrap_or("invalid"));
    }

    // Digest racine
    let manifest_digest = headers
        .get("Docker-Content-Digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Docker-Content-Digest manquant"))?;

    let digest_clean = manifest_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("Digest inattendu"))?;

    let racine_digest = Digest {
        algorithm: "sha256".to_string(),
        value: digest_clean.to_string(),
    };

    println!("[HEAD] Digest racine prêt: {}", digest_clean);

    Ok(racine_digest)
}

/// Crée un nouveau PullContext à partir d'un tag (appelé depuis HEAD ou GET par tag)
/// Retourne l'UUID du contexte créé ou déjà existant
async fn create_context_from_tag(
    client: &Client,
    registry: &str,
    repository: &str,
    tag: &str,
    ip_client: &str,
    pull_contexts: &PullContextList,
    _path: &str,
    client_type: &str,
) -> Result<Uuid, PullContextError> {

    // 1️⃣ Récupérer le digest racine upstream
    let manifest_racine_digest = digest_process_for_head(
        client, registry, repository, tag,
    )
    .await
    .map_err(|e| {
        eprintln!("[PullContext] Erreur HEAD: {}", e);
        let msg = e.to_string();
        if msg.contains("introuvable") || msg.contains("DENIED") || msg.contains("Token manquant") {
            PullContextError::MissingDigestOrTag
        } else if msg.contains("refusé") {
            PullContextError::DigestNotAllowed
        } else {
            PullContextError::StorageError
        }
    })?;

    // 2️⃣ UUID déterministe — même formule que l'ancien bloc HEAD
    let uuid_input = format!(
        "{}|{}|{}|{}|{}",
        registry, repository, &manifest_racine_digest.value, ip_client, client_type
    );
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_URL, uuid_input.as_bytes());

    // 3️⃣ Contexte déjà existant → on le retourne directement
    {
        let mut list = pull_contexts.lock().await;
        if list.iter().any(|c| c.uuid == uuid) {
            println!("[PullContext] UUID déjà présent (appel depuis GET tag) uuid={}", uuid);
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == uuid) {
                ctx.last_activity = Instant::now();
            }
            return Ok(uuid);
        }
    }

    // 4️⃣ Construire le contexte
    let digest_clean = manifest_racine_digest.value.trim_start_matches("sha256:").to_string();

    let mut ctx = PullContext::new(
        uuid,
        ip_client.to_string(),
        registry.to_string(),
        repository.to_string(),
        tag.to_string(),
    );

    ctx.client_type = client_type.to_string(); // ← stocker le type de client

    ctx.manifest_racine_digest = Some(manifest_racine_digest.clone());

    if !ctx.manifest_digests.contains(&manifest_racine_digest) 
    {
        ctx.manifest_digests.push(manifest_racine_digest.clone());
    }

    if !ctx.digests_possible.contains(&manifest_racine_digest) {
        ctx.digests_possible.push(manifest_racine_digest.clone());
    }
    if !ctx.digests_expected.contains(&manifest_racine_digest) {
        ctx.digests_expected.push(manifest_racine_digest.clone());
    }

    // 5️⃣ Stocker le manifest dans tmp/<uuid>/
    let _ = store_digest(client, registry, repository, tag, &uuid)
        .await
        .map_err(|_| PullContextError::StorageError)?;

    // 6️⃣ Récupérer tous les digests possible depuis le manifest list
    let token = RegistryClient::from_registry(registry)
        .get_token(client, repository)
        .await
        .map_err(|_| PullContextError::MissingDigestOrTag)?;

    let manifest_url = format!(
        "https://{}/v2/{}/manifests/sha256:{}",
        registry, repository, digest_clean
    );

    let resp = client
        .get(&manifest_url)
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json,\
            application/vnd.docker.distribution.manifest.v2+json,\
            application/vnd.oci.image.index.v1+json,\
            application/vnd.oci.image.manifest.v1+json",
        )
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|_| PullContextError::MissingDigestOrTag)?;

    let manifest_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|_| PullContextError::MissingDigestOrTag)?;

    if let Some(manifests) = manifest_json.get("manifests").and_then(|m| m.as_array()) {
        for m in manifests {
            if let Some(digest) = m.get("digest").and_then(|d| d.as_str()) {
                let d = Digest {
                    algorithm: "sha256".to_string(),
                    value: digest.trim_start_matches("sha256:").to_string(),
                };
                if !ctx.digests_possible.contains(&d) {
                    ctx.digests_possible.push(d);
                }
            }
        }
    }

    ctx.last_activity = Instant::now();

    // 7️⃣ Insérer dans la liste
    {
        let mut list = pull_contexts.lock().await;
        list.push(ctx.clone());
    }

    println!(
        "[PullContext] Contexte créé | uuid={} client_type={} registry={} repo={} tag={}",
        uuid, client_type, registry, repository, tag
    );

    Ok(uuid)
}