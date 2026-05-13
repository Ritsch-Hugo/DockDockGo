use anyhow::Result;
use hyper::server::conn::Http;
use hyper::{service::service_fn, Body, Method, Request, Response, StatusCode};
use reqwest::Client;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::{convert::Infallible, fs::File, io::BufReader, sync::Arc};
use tokio::net::TcpListener;
use tokio::sync::Mutex as TokioMutex;
use tokio_rustls::TlsAcceptor;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tokio::time::Duration;

mod db;
mod models;
mod predict_digests_utils;
mod pull_context;
mod registry_auth;
mod scan_utils;
mod utils;
mod validation;

use models::{
    Digest, DigestVerificationState, MultiCertResolver, PullContext, PullContextError,
    PullContextList, RateLimiter, ScanDecision,
};

use pull_context::{digest_process_for_head, get_pull_context};

use scan_utils::{is_allowed, launch_final_scan};

use predict_digests_utils::{
    get_os_arch_for_digest, predict_digests_docker, predict_digests_podman,
    verify_downloaded_digests,
};

use utils::{
    add_context_to_blacklist_or_whitelist, all_expected_in_cache, canonicalize_path_components,
    check_blob_authorized, check_blob_size, check_manifest_in_list, check_timout,
    cleanup_tmp_for_uuid, copy_ctx_from_quarantine_to_cache, dec_active,
    get_response_from_upstream, is_registry_allowed, manifest_list_has_linux_amd64,
    prefetch_expected_to_quarantine, quarantine_base, remove_ctx_digests_from_quarantine,
    save_to_cache, serve_from_quarantine, store_digest, try_serve_from_cache,
    validate_manifest_list, verify_content_digest,
};

async fn handle(
    req: Request<Body>,
    client: Client,
    pull_contexts: PullContextList,
    pool: sqlx::PgPool,
    rate_limiter: Arc<RateLimiter>,
) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    //let headers = req.headers().clone();

    // Normaliser sha256- → sha256: pour les registres OCI
    let path = path.replace("sha256-", "sha256:");
    println!("============================================================");
    println!("[REQ] {} {}", method, path);

    // Découper le path pour extraire repo, tag, digest
    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();

    // Health check avec vérification de la base de données
    if path == "/health" {
        if req.method() != Method::GET {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
                .unwrap();
        }

        // On tente d'acquérir une connexion du pool pour vérifier la santé de la BDD
        let db_status = match pool.acquire().await {
            Ok(_) => "ok",
            Err(e) => {
                eprintln!("[HEALTH] Erreur base de données : {}", e);
                "error"
            }
        };

        let status_code = if db_status == "ok" {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE // 503 si la BDD est tombée
        };

        let body_str = format!(r#"{{"status":"{}","database":"{}"}}"#, 
            if db_status == "ok" { "ok" } else { "degraded" },
            db_status
        );

        return Response::builder()
            .status(status_code)
            .header("Content-Type", "application/json")
            .body(Body::from(body_str))
            .unwrap();
    }

    //VALIDATION HEADERS — avant tout, y compris /v2/
    if let Err(e) = validation::validate_headers(&req) {
        let client_ip = req
            .extensions()
            .get::<std::net::SocketAddr>()
            .map(|a| a.to_string())
            .unwrap_or_default();
        eprintln!("[SECURITY] Headers invalides | ip={} err={}", client_ip, e);
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Requête invalide"))
            .unwrap();
    }

    //RATE LIMITING
    let client_ip_for_rate = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();

    if !rate_limiter.check(&client_ip_for_rate).await {
        eprintln!("[RATE-LIMIT] Limite atteinte | ip={}", client_ip_for_rate);
        return Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .body(Body::from("Rate-limit : Trop de requêtes"))
            .unwrap();
    }

    // Ping registry
    if path == "/v2/" {
        if req.method() != Method::GET {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
                .unwrap();
        }
        return Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
    }

    if req.method() != Method::GET && req.method() != Method::HEAD {
        eprintln!("[SECURITY] Méthode non autorisée: {} {}", method, path);
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Méthode non autorisée"))
            .unwrap();
    }

    // Redirection des requêtes /token vers le vrai registre
    if path.starts_with("/token") {
        let upstream = match get_response_from_upstream(req, client).await {
            Ok(resp) => resp,
            Err(resp) => return resp,
        };
        let status = upstream.status();
        let headers = upstream.headers().clone();
        let bytes = upstream.bytes().await.unwrap_or_default();
        let mut resp = Response::builder().status(status);
        for (k, v) in headers.iter() {
            resp = resp.header(k, v);
        }
        return resp.body(Body::from(bytes)).unwrap();
    }

    //recupère l'ip du client
    let client_ip = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .unwrap()
        .ip()
        .to_string();

    //exctation de l'host depuis la requete
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Vérifier si le registre est autorisé
    if !is_registry_allowed(&host) {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Registre non autorisé"))
            .unwrap();
    }

    //VÉRIFICATION IP — l'IP doit être connue dans la table users du dashboard
    if !db::is_ip_allowed(&pool, &client_ip).await {
        eprintln!("[SECURITY] Pull refusé — IP non autorisee : {}", client_ip);
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Acces refuse : IP non autorisee"))
            .unwrap();
    }

    //VALIDATION DES INPUTS
    if path.contains("..") || path.contains('\\') {
        eprintln!("[SECURITY] Path traversal détecté: {}", path);
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Requête invalide"))
            .unwrap();
    }

    // Extraire repository et tag/digest depuis parts pour valider
    let repo_and_tag_valid = (|| -> Result<(), &'static str> {
        // Trouver l'index de "manifests", "blobs" ou "referrers"
        let idx = parts
            .iter()
            .position(|p| *p == "manifests" || *p == "blobs" || *p == "referrers")
            .ok_or("resource type manquant")?;

        if idx + 1 >= parts.len() {
            return Err("tag ou digest manquant");
        }

        let repository = parts[..idx].join("/");
        let tag_or_digest = parts[parts.len() - 1];

        //appel de la fonction de validation
        validation::validate_request_components(&host, &repository, tag_or_digest)
            .map_err(|_| "composants invalides")?;

        Ok(())
    })();

    //Si validation echoue
    if let Err(e) = repo_and_tag_valid {
        eprintln!("[SECURITY] Validation échouée: {}", e);
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Requête invalide"))
            .unwrap();
    }

    //CANONICALISATION DES COMPOSANTS DE CHEMIN
    let (_registry, _repository) = match canonicalize_path_components(&host, &parts) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[SECURITY] Composants de chemin invalides: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Requête invalide"))
                .unwrap();
        }
    };

    let client_type = detect_client_type(&req);
    println!("[CLIENT] type détecté: {}", client_type);

    //recupère le contexte du pull en cours
    let context_uuid = match get_pull_context(
        &req,
        &parts,
        &client_ip,
        &pull_contexts,
        &client,
        &path,
        client_type,
        &pool,
    )
    .await
    {
        Ok(Some(uuid)) => {
            println!("[Main] Contexte trouvé / créé avec UUID: {}", uuid);
            uuid // tu peux continuer à utiliser uuid
        }
        Ok(None) => {
            eprintln!("[Main] Pas d'UUID retourné → pull échoué");

            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("PullContext non trouvé"))
                .unwrap();
        }
        Err(PullContextError::DigestNotAllowed) => {
            eprintln!("[Main] Accès refusé au registre");
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from(
                    "Accès refusé : image privée ou credentials manquants",
                ))
                .unwrap();
        }
        Err(PullContextError::MissingDigestOrTag) => {
            eprintln!("[Main] L'image n'existe pas dans le registre ou est privée");
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Image inexistante ou privée"))
                .unwrap();
        }
        Err(PullContextError::ServerError) => {
            eprintln!("[Main] Erreur server");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Erreur Server"))
                .unwrap();
        }
        Err(PullContextError::BlockingFromTheScanner) => {
            eprintln!(
                "[Main] Pull bloqué et image blacklisté car scan de haut niveau n'est pas passé"
            );
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Image refusée par le scan de sécurité"))
                .unwrap();
        }
        Err(PullContextError::StorageError) => {
            eprintln!("[Main] Erreur de stockage");
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Body::from("Erreur de stockage, réessayez plus tard"))
                .unwrap();
        }
        Err(PullContextError::Overload) => {
            eprintln!("[Main] Surcharge du système");
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Body::from("Système surchargé, réessayez plus tard"))
                .unwrap();
        }
        Err(e) => {
            eprintln!("[Main] Erreur lors de la récupération du contexte: {:?}", e);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Erreur PullContext"))
                .unwrap();
        }
    };

    //Ajoute la requete courrante au context dans active_request- Mechanisme anti race conditions
    {
        let mut list = pull_contexts.lock().await;
        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
            // Incrémente atomiquement
            let _atomic_count_request: usize =
                ctx.active_requests.fetch_add(1, Ordering::SeqCst) + 1;

            println!(
                "[CTX] +1 active_requests={:?} uuid={}",
                ctx.active_requests.load(Ordering::SeqCst),
                ctx.uuid
            );
        }
    }

    //Un blob ne peut pas être demandé sans manifest arch préalable
    if path.contains("/blobs/") && req.method() == Method::GET {
        let check_result = {
            let list = pull_contexts.lock().await;
            list.iter()
                .find(|c| c.uuid == context_uuid)
                .map(|ctx| check_blob_authorized(&path, ctx))
                .unwrap_or_else(|| Err("Contexte introuvable".to_string()))
        };

        if let Err(reason) = check_result {
            eprintln!(
                "[SECURITY] Blob refusé | ip={} path={} reason={}",
                client_ip, path, reason
            );
            dec_active(&pull_contexts, context_uuid).await;
            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Accès refusé"))
                .unwrap();
        }
    }

    // Vérifier le cache avant d'aller en upstream
    //si le digest est present dans le cache on retourne la réponse a partir du cache
    {
        if req.method() == Method::GET {
            let mut list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                let is_manifest_list = ctx.digests_expected.len() <= 1;
                //Verifie que tous les digests expected sont dans le cache
                //Si c'est un manifest list on laisse passer vu qu'on ne connais pas l'arch/os
                let cache_complete = all_expected_in_cache(ctx);
                if cache_complete || is_manifest_list {
                    if let Some(resp) = try_serve_from_cache(&req, ctx) {
                        //Si le digest est dans le cache on retourne a partir du digest stocké

                        ctx.in_cache = Some(true);

                        println!("[CACHE] Image trouvée en cache");

                        //Appeler la fonction verify_downloaded_digests pour libèrer le contexte au bon moment

                        // On ne déclenche le "Pull COMPLET" que si la requête est un GET pour laisser passer les HEAD
                        // et que digests_expected contient plus d'un élément
                        let mut should_cleanup = false;
                        if ctx.digests_expected.len() > 1 {
                            //On compare les digests expected et ceux réellement téléchargés

                            match verify_downloaded_digests(ctx) {
                                Ok(DigestVerificationState::InProgress) => {
                                    // pull normal, on laisse continuer
                                }
                                Ok(DigestVerificationState::Completed) => {
                                    println!("[PullContext] Pull COMPLET pour uuid={}", ctx.uuid);
                                    //Mettre la variable scan_completed a true
                                    ctx.pull_completed = true;

                                    sqlx::query("UPDATE pulls SET scan_completed = true, decision_final = 'ALLOW', last_activity = NOW() WHERE uuid = $1::uuid")
                                        .bind(context_uuid.to_string())
                                        .execute(&pool)
                                        .await
                                        .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });

                                    cleanup_tmp_for_uuid(&ctx.uuid);
                                    remove_ctx_digests_from_quarantine(ctx, &pool);

                                    should_cleanup = true;
                                }
                                Err(_) => {
                                    eprintln!("[PullContext] Pull invalide");
                                    //
                                    cleanup_tmp_for_uuid(&ctx.uuid);
                                    remove_ctx_digests_from_quarantine(ctx, &pool);
                                    drop(list);
                                    dec_active(&pull_contexts, context_uuid).await;

                                    let mut list = pull_contexts.lock().await;
                                    list.retain(|c| c.uuid != context_uuid);
                                    return Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .body(Body::from("Digest mismatch detected"))
                                        .unwrap();
                                }
                            }
                        }

                        //On clone le notify AVANT de sortir du lock
                        let notify = {
                            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                                ctx.notify_zero.clone()
                            } else {
                                return Response::builder()
                                    .status(StatusCode::FORBIDDEN)
                                    .body(Body::from("Digest mismatch detected"))
                                    .unwrap();
                            }
                        };

                        drop(list);
                        // Décrémenter le compteur AVANT de retirer le contexte
                        dec_active(&pull_contexts, context_uuid).await;

                        if should_cleanup {
                            let zero = {
                                let list = pull_contexts.lock().await;
                                if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                                    ctx.active_requests.load(Ordering::SeqCst) == 0
                                } else {
                                    true
                                }
                            };

                            if !zero {
                                notify.notified().await;
                            }

                            let mut list = pull_contexts.lock().await;
                            list.retain(|c| c.uuid != context_uuid);
                        }

                        return resp;
                    }
                } else {
                    println!("[CACHE] Image inexistante ou incomplete dans le cache : GET upstream -> quarantine ->  Scan");
                }
            }
        }
    }

    //Pas sur d'etre necessaire
    //A ce moment on sait que le digest n'est pas dans le cache
    {
        let mut list = pull_contexts.lock().await;
        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
            ctx.in_cache = Some(false);
        }
    }

    //On check blacklist
    if req.method() == Method::HEAD || req.method() == Method::GET {
        // Vérifier la blacklist
        if let Some(resp) = check_manifest_in_list(
            context_uuid,
            &pull_contexts,
            method.clone(),
            "blacklist",
            &pool,
        )
        .await
        {
            println!("Image dans blacklist");
            {
                let mut list = pull_contexts.lock().await;
                if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                    ctx.in_blacklist = Some(true);
                }
            }
            //Mise a jour bdd
            sqlx::query("UPDATE pulls SET scan_completed = true, decision_final = 'DENY', last_activity = NOW() WHERE uuid = $1::uuid")
                .bind(context_uuid.to_string())
                .execute(&pool)
                .await
                .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls blacklist: {}", e); Default::default() });
            //Les digests deja stockés en quarantaine ne sont pas supprimés
            dec_active(&pull_contexts, context_uuid).await;

            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
            return resp; // si dans blacklist, on renvoie la réponse FORBIDDEN
        }
    } else {
        //A ce moment on sait que le digest n'est pas en blacklist
        {
            let mut list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                ctx.in_blacklist = Some(false);
            }
        }
    }
    //Verifier dans la whitelist
    if let Some(_) = check_manifest_in_list(
        context_uuid,
        &pull_contexts,
        method.clone(),
        "whitelist",
        &pool,
    )
    .await
    {
        println!("Image dans whitelist");

        {
            let mut list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                ctx.in_whitelist = Some(true);
            }
        }

        //On redirige la requete vers le repo upstream
        let upstream = match get_response_from_upstream(req, client).await {
            Ok(resp) => resp, // upstream ok
            Err(resp) => {
                dec_active(&pull_contexts, context_uuid).await;
                return resp;
            } // upstream KO → renvoyer directement la réponse
        };

        //On extrait la reponse upstream
        let status = upstream.status();
        let headers = upstream.headers().clone();

        //LIMITE TAILLE DES BLOBS
        if let Err(e) = check_blob_size(&path, &headers) {
            eprintln!("[SECURITY] {} | ip={} path={}", e, client_ip, path);
            dec_active(&pull_contexts, context_uuid).await;
            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from("Blob trop volumineux"))
                .unwrap();
        }
        let bytes = upstream.bytes().await.unwrap_or_default(); // consomme `upstream`

        //VÉRIFICATION CRYPTOGRAPHIQUE
        let docker_content_digest = headers
            .get("Docker-Content-Digest")
            .and_then(|v| v.to_str().ok());

        if method == Method::GET {
            if let Err(e) = verify_content_digest(&path, &bytes, docker_content_digest) {
                eprintln!("[SECURITY] {} | ip={} path={}", e, client_ip, path);
                dec_active(&pull_contexts, context_uuid).await;
                let mut list = pull_contexts.lock().await;
                list.retain(|c| c.uuid != context_uuid);
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Digest mismatch"))
                    .unwrap();
            }
        }
        //On laisse tout passer
        let mut resp = Response::builder().status(status);
        for (k, v) in headers.iter() {
            resp = resp.header(k, v);
        }

        //Check si dernière requete
        let mut list = pull_contexts.lock().await;

        let mut should_cleanup = false;

        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
            if ctx.digests_expected.len() > 1 {
                //On compare les digests expected et ceux réellement téléchargés
                match verify_downloaded_digests(ctx) {
                    Ok(DigestVerificationState::InProgress) => {
                        // pull normal, on laisse continuer
                        //println!("Pull en cours ");
                    }
                    Ok(DigestVerificationState::Completed) => {
                        println!("[PullContext] Pull COMPLET pour uuid={}", ctx.uuid);

                        sqlx::query("UPDATE pulls SET scan_completed = true, decision_final = 'ALLOW', last_activity = NOW() WHERE uuid = $1::uuid")
                            .bind(context_uuid.to_string())
                            .execute(&pool)
                            .await
                            .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });

                        //Mettre la variable scan_completed a true
                        ctx.pull_completed = true;

                        should_cleanup = true;

                        cleanup_tmp_for_uuid(&ctx.uuid);
                    }
                    Err(_) => {
                        eprintln!("[PullContext] Pull invalide");
                        // Libérer le contexte si nécessaire
                        drop(list);
                        dec_active(&pull_contexts, context_uuid).await;

                        let mut list = pull_contexts.lock().await;
                        list.retain(|c| c.uuid != context_uuid);

                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from("Digest mismatch detected"))
                            .unwrap();
                    }
                }
            }
            //Sauvegarde en cache
            if method == Method::GET {
                if path.contains("/manifests/")
                    || path.contains("/blobs/")
                    || path.contains("/referrers/")
                {
                    //println!("Ecriture des fichiers en cache");

                    let ok = save_to_cache(&path, &bytes, ctx, &pool);
                    if !ok {
                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from("Digest Invalid"))
                            .unwrap();
                    }
                }
            }
        }

        //On clone le notify AVANT de sortir du lock
        let notify = {
            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                ctx.notify_zero.clone()
            } else {
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Digest mismatch detected"))
                    .unwrap();
            }
        };

        drop(list);
        dec_active(&pull_contexts, context_uuid).await;

        if should_cleanup {
            // 🔴 CHECK IMMÉDIAT
            let zero = {
                let list = pull_contexts.lock().await;
                if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                    ctx.active_requests.load(Ordering::SeqCst) == 0
                } else {
                    true
                }
            };

            if !zero {
                notify.notified().await;
            }

            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
        }

        return resp.body(Body::from(bytes)).unwrap();
    } else {
        //A ce moment on sait que le digest n'est pas en whitelist
        {
            let mut list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                ctx.in_whitelist = Some(false);
            }
        }
    }

    //-------------Cas ou le fichier n'est ni en cache, ni en whitelist, ni en blacklist-------------

    //On redirige la requete vers le repo upstream
    let upstream = match get_response_from_upstream(req, client.clone()).await {
        Ok(resp) => resp, // upstream ok
        Err(resp) => {
            //drop(list);
            dec_active(&pull_contexts, context_uuid).await;
            return resp; // upstream KO → renvoyer directement la réponse
        }
    };

    //On extrait la reponse upstream
    let status = upstream.status();
    let headers = upstream.headers().clone();

    //LIMITE TAILLE DES BLOBS
    if let Err(e) = check_blob_size(&path, &headers) {
        eprintln!("[SECURITY] {} | ip={} path={}", e, client_ip, path);
        dec_active(&pull_contexts, context_uuid).await;
        let mut list = pull_contexts.lock().await;
        list.retain(|c| c.uuid != context_uuid);
        return Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(Body::from("Blob trop volumineux"))
            .unwrap();
    }
    let bytes = upstream.bytes().await.unwrap_or_default(); // consomme `upstream`

    //VÉRIFICATION CRYPTOGRAPHIQUE DU DIGEST
    let docker_content_digest = headers
        .get("Docker-Content-Digest")
        .and_then(|v| v.to_str().ok());

    if method == Method::GET {
        if let Err(e) = verify_content_digest(&path, &bytes, docker_content_digest) {
            eprintln!("[SECURITY] {} | ip={} path={}", e, client_ip, path);
            dec_active(&pull_contexts, context_uuid).await;
            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Digest mismatch"))
                .unwrap();
        }
    }

    // Vérification architecture
    //On regarde si l'architecture linux/amd64 est présente dans la manifest list
    if method == Method::GET && path.contains("/manifests/") && !bytes.is_empty() {
        // Si c'est une manifest list (présence du champ "manifests")
        let is_manifest_list = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("manifests").cloned())
            .is_some();

        //blocage si linux/amd64 pas présent
        if is_manifest_list && !manifest_list_has_linux_amd64(&bytes) {
            //println!("[ARCH CHECK] Manifest list incompatible linux/amd64");

            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("No matching manifest for linux/amd64"))
                .unwrap();
        }

        if is_manifest_list {
            if let Err(reason) = validate_manifest_list(&bytes) {
                eprintln!(
                    "[MANIFEST VALIDATION] Manifest-list invalide: {} | path={}",
                    reason, path
                );
                dec_active(&pull_contexts, context_uuid).await;
                let mut list = pull_contexts.lock().await;
                list.retain(|c| c.uuid != context_uuid);
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Manifest-list non conforme"))
                    .unwrap();
            }
            println!("[MANIFEST VALIDATION] Manifest-list conforme: {}", path);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // POINT DE BLOCAGE : GET manifest arch-spécifique
    // À ce stade : os/arch connus, manifest-list déjà passé,
    // digests_expected vient d'être rempli dans get_pull_context.
    // On préfetch tout + scan final avant de répondre au client.
    // ═══════════════════════════════════════════════════════════════
    let scan_already_done = {
        let list = pull_contexts.lock().await;
        list.iter()
            .find(|c| c.uuid == context_uuid)
            .map(|c| c.scan_final_done)
            .unwrap_or(true)
    };

    if method == Method::GET
        && path.contains("/manifests/")
        && path.contains("sha256:")
        && !scan_already_done
    {
        // Vérifier qu'on est sur le manifest arch-spécifique :
        // digests_expected > 1 signifie que predict_digests vient de tourner
        // (rempli dans get_pull_context au GET du manifest arch-spécifique)
        let is_arch_manifest = {
            let list = pull_contexts.lock().await;
            list.iter()
                .find(|c| c.uuid == context_uuid)
                .map(|ctx| {
                    ctx.digests_expected.len() > 1
                        && ctx.os != "unknown"
                        && ctx.arch != "unknown"
                        && !ctx.check_if_verify_digest_completed
                })
                .unwrap_or(false)
        };

        if is_arch_manifest {
            println!(
                "[PREFETCH] Manifest arch-spécifique détecté — prefetch + scan final | uuid={}",
                context_uuid
            );

            // 1. Cloner le contexte pour le prefetch (hors lock)
            let ctx_for_prefetch = {
                let list = pull_contexts.lock().await;
                list.iter().find(|c| c.uuid == context_uuid).cloned()
            };

            if let Some(ctx_snapshot) = ctx_for_prefetch {
                // 2. Prefetch tous les artefacts en quarantaine
                if let Err(e) = prefetch_expected_to_quarantine(&client, &ctx_snapshot, &pool).await
                {
                    eprintln!("[PREFETCH] Erreur: {} | uuid={}", e, context_uuid);
                    dec_active(&pull_contexts, context_uuid).await;
                    let mut list = pull_contexts.lock().await;
                    list.retain(|c| c.uuid != context_uuid);
                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Erreur préchargement quarantaine"))
                        .unwrap();
                }

                // 3. Marquer tous les digests expected comme téléchargés dans le contexte
                //    (manifest_digests + blob_digests) pour que verify_downloaded_digests
                //    retourne Completed immédiatement après
                {
                    let mut list = pull_contexts.lock().await;
                    if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                        for d in ctx.digests_expected.clone() {
                            // On détermine le type via la présence du fichier en quarantaine
                            let q_manifest = format!(
                                "{}/{}/{}/manifests/sha256/{}.json",
                                quarantine_base(), ctx.registry, ctx.repository, d.value
                            );
                            let q_blob = format!(
                                "{}/{}/{}/blobs/sha256/{}",
                                quarantine_base(), ctx.registry, ctx.repository, d.value
                            );
                            if Path::new(&q_manifest).exists() {
                                if !ctx.manifest_digests.contains(&d) {
                                    ctx.manifest_digests.push(d.clone());
                                }
                            } else if Path::new(&q_blob).exists() {
                                if !ctx.blob_digests.contains(&d) {
                                    ctx.blob_digests.push(d.clone());
                                }
                            }
                        }
                        ctx.check_if_verify_digest_completed = true;
                    }
                }
                let ctx_snapshot = {
                    let list = pull_contexts.lock().await;
                    list.iter().find(|c| c.uuid == context_uuid).cloned()
                };

                let Some(ctx_snapshot) = ctx_snapshot else {
                    dec_active(&pull_contexts, context_uuid).await;
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from("Contexte introuvable"))
                        .unwrap();
                };

                // 4. Attendre que active_requests == 0 (pas d'autres requêtes en cours)
                //    puis lancer le scan final — même pattern que l'existant
                let notify = {
                    let list = pull_contexts.lock().await;
                    list.iter()
                        .find(|c| c.uuid == context_uuid)
                        .map(|c| c.notify_zero.clone())
                };

                if let Some(notify) = notify {
                    dec_active(&pull_contexts, context_uuid).await;

                    let already_zero = {
                        let list = pull_contexts.lock().await;
                        list.iter()
                            .find(|c| c.uuid == context_uuid)
                            .map(|c| c.active_requests.load(Ordering::SeqCst) == 0)
                            .unwrap_or(true)
                    };

                    if !already_zero {
                        notify.notified().await;
                    }

                    // 5. Scan final
                    let scan_result = launch_final_scan(&pull_contexts, context_uuid, &path).await;

                    match scan_result {
                        Some(ScanDecision::ALLOW) => {
                            println!("[SECURITY CHECK] Image conforme -> autorisation du pull");

                            sqlx::query("UPDATE pulls SET scan_completed = true, decision_final = 'ALLOW', last_activity = NOW() WHERE uuid = $1::uuid")
                            .bind(context_uuid.to_string())
                            .execute(&pool)
                            .await
                            .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });

                            {
                                let mut list = pull_contexts.lock().await;
                                if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid)
                                {
                                    ctx.scan_status = Some("ALLOW".to_string());
                                    ctx.pull_completed = false;
                                    ctx.check_if_verify_digest_completed = false;
                                    //ctx.manifest_digests.clear();
                                    ctx.blob_digests.clear();
                                    ctx.referrers_digests.clear();
                                }
                            }

                            //Ajouter a whitelist
                            if let Err(e) = add_context_to_blacklist_or_whitelist(
                                ctx_snapshot.clone(),
                                "whitelist",
                                &pool,
                            )
                            .await
                            {
                                eprintln!("[WHITELIST ERROR] {}", e);
                            }

                            // Servir le manifest courant arch-spécifique depuis la quarantaine
                            let response = match serve_from_quarantine(&path, &ctx_snapshot) {
                                Some(r) => r,
                                None => {
                                    eprintln!("[PREFETCH SCAN] serve_from_quarantine vide — fallback bytes upstream");
                                    let mut resp = Response::builder().status(status);
                                    for (k, v) in headers.iter() {
                                        resp = resp.header(k, v);
                                    }
                                    resp.body(Body::from(bytes)).unwrap()
                                }
                            };
                            //remove_ctx_digests_from_quarantine(&ctx_snapshot, &pool);
                            copy_ctx_from_quarantine_to_cache(&ctx_snapshot, &pool);
                            remove_ctx_digests_from_quarantine(&ctx_snapshot, &pool);
                            cleanup_tmp_for_uuid(&ctx_snapshot.uuid);
                            return response;
                        }
                        Some(ScanDecision::DENY) => {
                            println!("[SECURITY CHECK] Image non conforme -> bloquage du pull");
                            sqlx::query("UPDATE pulls SET scan_completed = true, decision_final = 'DENY', last_activity = NOW() WHERE uuid = $1::uuid")
                            .bind(context_uuid.to_string())
                            .execute(&pool)
                            .await
                            .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });

                            //Ajouter a blacklist
                            if let Err(e) = add_context_to_blacklist_or_whitelist(
                                ctx_snapshot.clone(),
                                "blacklist",
                                &pool,
                            )
                            .await
                            {
                                eprintln!("[BLACKLIST ERROR] {}", e);
                            }
                            cleanup_tmp_for_uuid(&ctx_snapshot.uuid);
                            remove_ctx_digests_from_quarantine(&ctx_snapshot, &pool);

                            {
                                let mut list = pull_contexts.lock().await;
                                list.retain(|c| c.uuid != context_uuid);
                            }

                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image refused by security scan"))
                                .unwrap();
                        }
                        Some(ScanDecision::PENDING) => {
                            cleanup_tmp_for_uuid(&ctx_snapshot.uuid);

                            //Image continue d'etre scanné puis est soit ajouté a la blacklist / whitelist ( + cache) coté orchestrateur
                            //Notify dashboard user quand image prete

                            println!("[SCAN FINAL] PENDING -> Scan en cours");

                            let mut list = pull_contexts.lock().await;

                            //Point d'attention : Le contexte est supprimé donc 
                            
                            list.retain(|c| c.uuid != context_uuid);
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image en cours de scan"))
                                .unwrap();
                        }
                        Some(ScanDecision::ERROR) => 
                        {
                            eprintln!("[SCAN FINAL] ERROR retourné par l'orchestrateur | uuid={}", context_uuid);

                            // Nettoyage : quarantaine + tmp, sans blacklist ni whitelist
                            cleanup_tmp_for_uuid(&ctx_snapshot.uuid);
                            remove_ctx_digests_from_quarantine(&ctx_snapshot, &pool);

                            // Suppression en BDD (pull non terminé, pas de decision_final définitive)
                            sqlx::query(
                                "DELETE FROM pulls WHERE uuid = $1::uuid AND scan_completed = false"
                            )
                            .bind(context_uuid.to_string())
                            .execute(&pool)
                            .await
                            .unwrap_or_else(|e| {
                                eprintln!("[DB] Erreur DELETE pulls ERROR: {}", e);
                                Default::default()
                            });

                            {
                                let mut list = pull_contexts.lock().await;
                                list.retain(|c| c.uuid != context_uuid);
                            }

                            return Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from("Erreur interne du scanner, veuillez réessayer"))
                                .unwrap();
                        }

                        None => {
                            println!("[SECURITY CHECK]- Scan deja en cours");

                            {
                                let mut list = pull_contexts.lock().await;
                                list.retain(|c| c.uuid != context_uuid);
                            }
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image refused by security scan"))
                                .unwrap();
                        }
                    }
                }
            }
        }
    }

    //------------- Cas HEAD et Manifest List -------------
    dec_active(&pull_contexts, context_uuid).await; //Appel is_allowed ici

    // Construire la réponse finale pour le client -> 200 OK
    let mut resp = Response::builder().status(status);
    for (k, v) in headers.iter() {
        resp = resp.header(k, v);
    }

    //LOG
    /*
    println!("[RESP] status={} headers:", status);
    for (k, v) in headers.iter() {
        println!("  {}: {}", k, v.to_str().unwrap_or("?"));
    }*/

    resp.body(Body::from(bytes)).unwrap()
}

#[tokio::main]
async fn main() -> Result<()> {
    //Gestion Multi-Certificats
    let content = std::fs::read_to_string("registry_whitelist.json")
        .expect("[TLS] registry_whitelist.json introuvable");
    let registries: Vec<String> =
        serde_json::from_str(&content).expect("[TLS] registry_whitelist.json invalide");

    let mut resolver = MultiCertResolver::new();
    for registry in &registries {
        resolver.add(registry)?;
    }

    let tls = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect(
        "[FATAL] DATABASE_URL non définie — le proxy ne peut pas démarrer sans base de données",
    );

    let pool = db::init_pool(&database_url).await?;

    let listener = TcpListener::bind(("0.0.0.0", 8443)).await?;

    //[HANDSHAKE]
    // 1 - Le client initie la connexion TLS
    // 2 - Le proxy envoie le certificat server (du bon registre)
    // 3 - Si le certificat est signé par la CA, le certificat est accepté car la CA du proxy est trust par le client
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let client = Client::builder().use_rustls_tls().build()?;

    // State partagé pour la liste de contexte pour chaques pull
    let pull_context: PullContextList = Arc::new(TokioMutex::new(Vec::new()));

    //Ajout de la fonction de timout
    check_timout(pull_context.clone(), &pool);

    println!("✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443");

    let rate_limiter = Arc::new(RateLimiter::new(100, 60));
    rate_limiter.clone().start_cleanup();




    // Canal shutdown : le sender déclenche l'arrêt, les receivers l'attendent
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Écoute SIGTERM en background
    let mut sigterm = signal(SignalKind::terminate())
        .expect("Impossible d'enregistrer SIGTERM");
    let mut sigint = signal(SignalKind::interrupt())
        .expect("Impossible d'enregistrer SIGINT");

    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => {
                eprintln!("[SHUTDOWN] SIGTERM reçu — arrêt gracieux en cours");
            }
            _ = sigint.recv() => {
                eprintln!("[SHUTDOWN] SIGINT reçu — arrêt gracieux en cours");
            }
        }
        let _ = shutdown_tx_clone.send(true);
    });

    loop {
        let mut shutdown_rx_loop = shutdown_rx.clone();

        tokio::select! {
            // Nouvelle connexion entrante
            result = listener.accept() => {
                let (stream, addr) = match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        eprintln!("[CONN] Erreur accept: {}", e);
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let client = client.clone();
                let pull_contexts = pull_context.clone();
                let pool = pool.clone();
                let rate_limiter = rate_limiter.clone();
                let mut shutdown_rx_conn = shutdown_rx.clone();

                tokio::spawn(async move {
                    // Si shutdown déjà demandé, on rejette immédiatement
                    if *shutdown_rx_conn.borrow() {
                        return;
                    }

                    println!("[CONN] Client {:?}", addr);
                    if let Ok(tls) = acceptor.accept(stream).await {
                        let client = client.clone();
                        let pull_contexts = pull_contexts.clone();

                        let service = service_fn(move |mut req| {
                            let client = client.clone();
                            let addr = addr;
                            let pull_contexts = pull_contexts.clone();
                            let pool = pool.clone();
                            let rate_limiter = rate_limiter.clone();
                            async move {
                                req.extensions_mut().insert(addr);
                                Ok::<_, Infallible>(
                                    handle(req, client, pull_contexts, pool, rate_limiter).await,
                                )
                            }
                        });

                        tokio::select! {
                            _ = Http::new()
                                .max_buf_size(16 * 1024)
                                .serve_connection(tls, service) => {}
                            // Connexion coupée proprement si shutdown demandé
                            _ = shutdown_rx_conn.changed() => {
                                println!("[SHUTDOWN] Connexion {:?} interrompue", addr);
                            }
                        }
                    }
                });
            }

            // Signal shutdown reçu → on sort de la boucle accept
            _ = shutdown_rx_loop.changed() => {
                eprintln!("[SHUTDOWN] Arrêt du listener — plus de nouvelles connexions acceptées");
                break;
            }
        }
    }

    // Phase de drain : attendre que tous les pulls en cours se terminent
    eprintln!("[SHUTDOWN] Drain des contextes actifs en cours...");

    let drain_timeout = std::env::var("SHUTDOWN_DRAIN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(drain_timeout);

    loop {
        let active_count = {
            let list = pull_context.lock().await;
            list.iter()
                .map(|c| c.active_requests.load(std::sync::atomic::Ordering::SeqCst))
                .sum::<usize>()
        };

        if active_count == 0 {
            eprintln!("[SHUTDOWN] Aucune requête active — arrêt propre");
            break;
        }

        if tokio::time::Instant::now() >= deadline {
            eprintln!("[SHUTDOWN] Timeout drain ({} s) — {} requêtes encore actives, arrêt forcé",
                drain_timeout, active_count);
            break;
        }

        //eprintln!("[SHUTDOWN] {} requêtes actives, attente...", active_count);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // On récupère tous les contextes restants pour nettoyer leurs fichiers
    {
        let mut list = pull_context.lock().await;
        eprintln!("[SHUTDOWN] Nettoyage final de {} contextes...", list.len());

        for ctx in list.iter() {
            // On retire le .await ici
            utils::cleanup_tmp_for_uuid(&ctx.uuid); 
        }
        list.clear();
    }
    eprintln!("[SHUTDOWN] Proxy arrêté proprement");
    Ok(())
}




/// 🔑 Chargement des certificats TLS
fn load_certs(path: &str) -> Result<Vec<Certificate>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| Certificate(c.to_vec()))
        .collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKey> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);

    let keys: Vec<_> = pkcs8_private_keys(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].secret_pkcs8_der().to_vec()));
    }

    let mut reader = BufReader::new(File::open(path)?);
    let keys: Vec<_> = rsa_private_keys(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].secret_pkcs1_der().to_vec()));
    }

    Err(anyhow::anyhow!("No private keys found in {}", path))
}

pub fn detect_client_type(req: &Request<Body>) -> &'static str {
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if ua.contains("containers/") {
        "podman"
    } else if ua.to_lowercase().contains("docker") {
        "docker"
    } else {
        "unknown"
    }
}
