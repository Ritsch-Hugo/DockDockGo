
use hyper::{Body, Method, Request};
use reqwest::Client;
use uuid::Uuid;
use std::time::Instant;
use anyhow::Result;

use crate::{
    PullContext,
    PullContextList,
    PullContextError,
    Digest,
};

use crate::{
    store_digest,
    get_dockerhub_token,
    get_os_arch_for_digest,
    predict_digests,
    is_allowed,
    add_context_to_blacklist_or_whitelist,
    cleanup_tmp_for_uuid,
};


/// 🔄 Récupération ou création du contexte PullContext
pub async fn get_pull_context(
    req: &Request<Body>,
    parts: &[&str],
    client_ip: &str,
    pull_contexts: &PullContextList,
    client: &Client, 
)-> Result<Option<Uuid>, PullContextError> //Retourne soit l'uuid du contexte trouvé (cas success) soit une erreur PullContextError
{

    // 🔹 Construire les variables principales à partir de parts
    let registry = "registry-1.docker.io".to_string(); // Par défaut pour Docker Hub

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

    // 🔹 Extraire la valeur (digest ou tag)
    let value = parts[idx + 1];

    /*println!(
        "[PullContext] Resource type={}, index={}, value={}",
        resource_type, idx, value
    );*/


    // Extraire le repository
    let repository = parts[..idx].join("/");

    let tag_ou_digest = parts[parts.len() - 1];
    let ip_client = client_ip.to_string();

    /*println!(
        "[PullContext] registry={}, repository={}, tag/digest={}, client_ip={}\n",
        registry, repository, tag_ou_digest, ip_client
    );*/

    // 🔹 HEAD → création d’un nouveau contexte pour un tag
    if req.method() == Method::HEAD 
    {
        // Récupérer l’index de "manifests"

        // Vérifier que l'index trouvé est valide pour accéder au digest ou tag
        if idx + 1 >= parts.len() {
            println!("[PullContext] Path invalide, digest ou tag manquant");
            return Err(PullContextError::MissingDigestOrTag);
        }

        // Extraire la valeur suivante : digest ou tag selon le type
        let value = parts[idx + 1];
        /*println!(
            "[PullContext] Resource type={}, index={}, value={}",
            resource_type, idx, value
        );*/


        let digest_cmd = format!("{}:{}", repository, tag_ou_digest);
        let mut manifest_racine_digest: Option<String> = None;


        // 🔹 Appeler digest_process_for_head pour récupérer le digest racine

        let manifest_racine_digest = digest_process_for_head(
            client,
            &registry,
            &repository,
            &tag_ou_digest,
        )
        .await
        .map_err(|e| {
            eprintln!("[PullContext] Erreur lors de digest_process_for_head: {:?}", e);
            PullContextError::MissingDigestOrTag
        })?;


        let digest_clean = manifest_racine_digest.value.trim_start_matches("sha256:").to_string();


        println!("[PullContext] Digest racine récupéré: {}", manifest_racine_digest.value);

        // 🔹 Construction de l’UUID déterministe (sans le tag, mais avec digest possible)
        let uuid_input = format!(
            "{}|{}|{}|{}",
            registry,
            repository,
            &manifest_racine_digest.value,
            ip_client
        );

        let uuid = Uuid::new_v5(&Uuid::NAMESPACE_URL, uuid_input.as_bytes());

        // 🔹 Vérifier si l'UUID existe déjà
        let mut list = pull_contexts.lock().await;
        if list.iter().any(|c| c.uuid == uuid) {
            println!("[PullContext] UUID déjà présent, pas de création d'un nouveau contexte");

            //Met a jour l'activité pour le timer
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == uuid) {
                ctx.last_activity = Instant::now();
            }

            return Ok(Some(uuid));//retourner l'uuid existant

        }
    
        // 🔹 Création du contexte PullContext
        let mut ctx = PullContext::new(
            uuid,
            ip_client.clone(),
            registry.clone(),
            repository.clone(),
            tag_ou_digest.to_string(),//ici c'est le tag
        );

        // 🔹 Après création du PullContext et mise à jour du digest racine
        //Si le digest racine n'est pas déjà dans digests_possible, l'ajouter
        ctx.manifest_racine_digest = Some(manifest_racine_digest.clone());
        if !ctx.digests_possible.contains(&manifest_racine_digest) {
            ctx.digests_possible.push(manifest_racine_digest.clone());
        }

        ctx.manifest_racine_digest = Some(manifest_racine_digest.clone());
        if !ctx.digests_expected.contains(&manifest_racine_digest) {
            ctx.digests_expected.push(manifest_racine_digest.clone());
        }

        // 🔹 Stockage du manifest dans tmp/<uuid>/
        let _ = store_digest(client, &registry, &repository, &tag_ou_digest, &uuid)
            .await
            .map_err(|e| {
                eprintln!("[PullContext] Erreur lors de store_digest: {:?}", e);
                PullContextError::StorageError
            })?;

        //Ajout du manifest racine digest au contexte
        ctx.manifest_racine_digest = Some(manifest_racine_digest.clone());



        // 🔹 Récupération de tout les digests pour le manifest list
         
        let token = get_dockerhub_token(&client, &repository)
            .await
            .map_err(|_| PullContextError::MissingDigestOrTag)?;

        let manifest_url = format!(
            "https://registry-1.docker.io/v2/{}/manifests/sha256:{}",
            repository,
            digest_clean
        );

        let resp = client
            .get(&manifest_url)
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.list.v2+json",
            )
            .bearer_auth(token)
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
                    let digest = Digest {
                        algorithm: "sha256".to_string(),
                        value: digest.trim_start_matches("sha256:").to_string(),
                    };

                    if !ctx.digests_possible.contains(&digest) {
                        ctx.digests_possible.push(digest);
                    }
                }
            }
        }

        //mise a jour de l'activité pour le timer (nouveau contexte)
        ctx.last_activity = Instant::now();

        list.push(ctx.clone());

        //[Appel API] : déclencher scan de haut niveau

        //Proxy -> API -> Scanner

        //Proxy <- API <- Scanner

        //Si accepté (pour le moment) on retourne l'uuid
        println!("[GetPullContext] - Call API pour scan Haut Niveau");
        match is_allowed(&mut ctx).await.as_str() 
        {
            "ALLOW" => 
            {
                //println!("[GetPullContext] - Scan Haut Niveau accepté, pull autorisé");
                //Ajout a la whitelist 
                if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist") {
                    eprintln!("[WHITELIST ERROR] {}", e);     
                }

                return Ok(Some(uuid));
            }
            "PENDING" => 
            {
                //println!("[GetPullContext] - Scan Haut Niveau en attente, pull en attente");
                return Ok(Some(uuid));
            }
            "DENY" => 
            {
                //println!("[GetPullContext] - Scan Haut Niveau refusé, pull refusé");
                //Ajout a la blacklist
                if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist") {
                    eprintln!("[BLACKLIST ERROR] {}", e);     
                }

                //Supprimer dossier temporaire
                cleanup_tmp_for_uuid(&ctx.uuid);

                // 🔹 Libérer le contexte PullContext
                list.retain(|c| c.uuid != ctx.uuid);

                return Err(PullContextError::BlockingFromTheScanner);
            }
            _ => 
            {
                eprintln!("[GetPullContext] - Erreur lors du scan Haut Niveau");
                return Err(PullContextError::BlockingFromTheScanner);
            }
        }
    }


    // 🔹 GET → vérifier un digest existant
    else if req.method() == Method::GET 
    {

        // Extraire le digest de la requête
        let digest_str = parts[idx + 1];
        if !digest_str.starts_with("sha256:") {
            return Err(PullContextError::DigestNotAllowed);
        }
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

                            //On recupère les exacts digests attendus (ni plus ni moin)
                            let predicted_digests = match predict_digests(
                                &client,            // reqwest::Client
                                &ctx.uuid,          // UUID du contexte
                                &registry,          // "registry-1.docker.io"
                                &repository,        // ex: "library/ubuntu"
                                &tag_ou_digest,     // tag ou digest
                                &ctx.os,            // ✅ OS dynamique
                                &ctx.arch,          // ✅ ARCH dynamique
                                manifest_racine_digest,
                            )
                            .await
                            {
                                Ok(d) => d,
                                Err(e) => {
                                    eprintln!("[PullContext] predict_digests failed: {:?}", e);
                                    return Err(PullContextError::StorageError);
                                }
                            };

                            // Mettre à jour les digests attendus
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

    // 1️⃣ Récupération du token Docker
    let token_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repository
    );

    let token_resp = client.get(&token_url).send().await?;
    let token_json: serde_json::Value = token_resp.json().await?;
    let token = token_json
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Token Docker manquant"))?;

    println!("[HEAD] Token Docker récupéré");

    // 2️⃣ Télécharger le manifest associé au tag
    let manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repository, tag);

    let manifest_resp = client
        .get(&manifest_url)
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json,\
             application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await?;

        
    let headers = manifest_resp.headers().clone();

    // 🔍 LOG RATE-LIMIT
    let headers = manifest_resp.headers();

    if let Some(limit) = headers.get("ratelimit-limit") {
        println!(
            "[RATE-LIMIT] limit = {}",
            limit.to_str().unwrap_or("invalid")
        );
    }

    if let Some(remaining) = headers.get("ratelimit-remaining") {
        let remaining_str = remaining.to_str().unwrap_or("invalid");
        println!("[RATE-LIMIT] remaining = {}", remaining_str);

        if remaining_str.starts_with('0') {
            anyhow::bail!("Docker Hub rate-limit atteint (remaining=0)");
        }
    }

    if let Some(src) = headers.get("docker-ratelimit-source") {
        println!(
            "[RATE-LIMIT] source = {}",
            src.to_str().unwrap_or("invalid")
        );
    }


    // 3️⃣ Extraire le digest racine depuis l'en-tête
    // /!\ Attention le Header docker-content-digest n'est pas toujours envoyé /!\
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