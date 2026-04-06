use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as TokioMutex, Notify};

use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

use rustls::server::ResolvesServerCert;
use rustls::sign::{any_supported_type, CertifiedKey};

use serde::{Deserialize, Serialize};

use crate::{load_certs, load_private_key};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest {
    pub algorithm: String, // ex: "sha256"
    pub value: String,     // hex
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PullContext {
    pub uuid: Uuid,
    pub ip_client: String,
    pub registry: String,   //ex: "registry-1.docker.io"
    pub repository: String, //ex: "library/ubuntu"
    pub tag: String,

    pub manifest_digests: Vec<Digest>,
    pub blob_digests: Vec<Digest>,
    pub referrers_digests: Vec<Digest>,

    pub manifest_racine_digest: Option<Digest>,
    pub digests_possible: Vec<Digest>,
    pub digests_expected: Vec<Digest>,

    pub os: String,   // ex: "linux"
    pub arch: String, // ex: "amd64"

    #[serde(skip_serializing, skip_deserializing, default = "Instant::now")]
    pub last_activity: Instant,
    pub pull_completed: bool,
    pub scan_final_done: bool,
    pub in_whitelist: Option<bool>,
    pub in_blacklist: Option<bool>,
    pub in_cache: Option<bool>,
    pub check_if_verify_digest_completed: bool,

    pub scan_status: Option<String>, // "ALLOW", "PENDING", "DENY" ou None si pas encore de scan

    pub active_requests: AtomicUsize,

    pub client_type: String, //podman ou docker

    #[serde(skip_serializing, skip_deserializing)]
    pub notify_zero: Arc<Notify>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDecision {
    PENDING,
    ALLOW,
    DENY,
}

// Erreurs possibles lors de la récupération du contexte PullContext2
#[derive(Debug)]
pub enum PullContextError {
    InvalidPath,
    MissingDigestOrTag,
    ContextMismatch,
    DigestNotAllowed,
    BlockingFromTheScanner,
    StorageError,
    Overload,
    ServerError,
}

#[derive(Debug, PartialEq)]
pub enum DigestVerificationState {
    InProgress,
    Completed,
}

//Structures pour predict_digests
#[derive(Debug, Deserialize)]
pub struct ManifestList {
    pub manifests: Vec<ManifestDescriptor>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestDescriptor {
    pub digest: String,
    pub platform: Platform,
    #[serde(default)]
    pub annotations: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
}

//Structure pour la gestion multi certificats
pub struct MultiCertResolver {
    certs: HashMap<String, Arc<CertifiedKey>>,
}

/// Entrée pour une IP : nombre de requêtes et début de la fenêtre
pub struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

pub struct RateLimiter {
    entries: Arc<TokioMutex<HashMap<String, RateLimitEntry>>>,
    max_requests: u32, // nombre max de requêtes par fenêtre
    window: Duration,  // durée de la fenêtre
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            entries: Arc::new(TokioMutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Retourne true si la requête est autorisée, false si le rate limit est atteint
    pub async fn check(&self, ip: &str) -> bool {
        let mut map = self.entries.lock().await;
        let now = Instant::now();

        match map.get_mut(ip) {
            Some(entry) => {
                // Si la fenêtre est expirée, on remet à zéro
                if now.duration_since(entry.window_start) > self.window {
                    entry.count = 1;
                    entry.window_start = now;
                    true
                } else if entry.count >= self.max_requests {
                    // Fenêtre active et limite atteinte
                    false
                } else {
                    entry.count += 1;
                    true
                }
            }
            None => {
                // Première requête de cette IP
                map.insert(
                    ip.to_string(),
                    RateLimitEntry {
                        count: 1,
                        window_start: now,
                    },
                );
                true
            }
        }
    }

    //Nettoyage périodique des entrées expirées pour éviter la fuite mémoire

    pub fn start_cleanup(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let mut map = self.entries.lock().await;
                let now = Instant::now();
                let before = map.len();
                map.retain(|_, entry| now.duration_since(entry.window_start) <= self.window);
                let removed = before - map.len();
                if removed > 0 {
                    //println!("[RATE-LIMIT] Nettoyage effectué, {} IPs supprimées ({} restantes)", removed, map.len());
                }
            }
        });
    }
}

impl MultiCertResolver {
    pub fn new() -> Self {
        Self {
            certs: HashMap::new(),
        }
    }

    pub fn add(&mut self, domain: &str) -> Result<()> {
        let crt_path = format!("certs-mitm/{}.crt", domain);
        let key_path = format!("certs-mitm/{}.key", domain);

        if !Path::new(&crt_path).exists() || !Path::new(&key_path).exists() {
            eprintln!("[TLS] Certificat manquant pour {}", domain);
            return Ok(());
        }

        let certs = load_certs(&crt_path)?;
        let key = load_private_key(&key_path)?;
        let signing_key = any_supported_type(&key)?;
        let certified = Arc::new(CertifiedKey::new(certs, signing_key));
        self.certs.insert(domain.to_string(), certified);
        println!("[TLS] Certificat chargé pour {}", domain);
        Ok(())
    }
}

impl ResolvesServerCert for MultiCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        self.certs.get(name).cloned()
    }
}

pub type PullContextList = Arc<TokioMutex<Vec<PullContext>>>;

impl Digest {
    pub fn as_str(&self) -> String {
        format!("{}:{}", self.algorithm, self.value)
    }
}

impl PullContext {
    pub fn new(
        uuid: Uuid,
        ip_client: String,
        registry: String,
        repository: String,
        tag: String,
    ) -> Self {
        Self {
            uuid,
            ip_client,
            registry,
            repository,
            tag,
            manifest_digests: Vec::new(),
            blob_digests: Vec::new(),
            referrers_digests: Vec::new(),
            digests_possible: Vec::new(),
            digests_expected: Vec::new(),
            manifest_racine_digest: None,
            last_activity: Instant::now(),
            os: "unknown".to_string(),
            arch: "unknown".to_string(),
            pull_completed: false,
            scan_final_done: false,
            in_blacklist: None,
            in_whitelist: None,
            in_cache: None,
            check_if_verify_digest_completed: false,
            scan_status: Some("PENDING".to_string()),
            active_requests: AtomicUsize::new(0),
            client_type: "unknown".to_string(),
            notify_zero: Arc::new(Notify::new()),
        }
    }
}
impl Clone for PullContext {
    fn clone(&self) -> Self {
        Self {
            uuid: self.uuid,
            ip_client: self.ip_client.clone(),
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            tag: self.tag.clone(),
            manifest_digests: self.manifest_digests.clone(),
            blob_digests: self.blob_digests.clone(),
            referrers_digests: self.referrers_digests.clone(),
            manifest_racine_digest: self.manifest_racine_digest.clone(),
            digests_possible: self.digests_possible.clone(),
            digests_expected: self.digests_expected.clone(),
            os: self.os.clone(),
            arch: self.arch.clone(),
            last_activity: self.last_activity,
            pull_completed: self.pull_completed,
            scan_final_done: self.scan_final_done,
            in_whitelist: self.in_whitelist,
            in_blacklist: self.in_blacklist,
            in_cache: self.in_cache,
            check_if_verify_digest_completed: self.check_if_verify_digest_completed,
            scan_status: self.scan_status.clone(),
            active_requests: AtomicUsize::new(self.active_requests.load(Ordering::SeqCst)),
            client_type: self.client_type.clone(),
            notify_zero: self.notify_zero.clone(),
        }
    }
}
