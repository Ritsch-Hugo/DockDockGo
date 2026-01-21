use crate::engine::{all_paths, Rule};
use crate::models::*;
use std::collections::HashMap;

pub struct FsSecretsRule;

impl Rule for FsSecretsRule {
    fn id(&self) -> &'static str {
        "FS_SECRETS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        if !image.has_fs {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::SKIP,
                message: "Filesystem not available yet (layers not assembled)".to_string(),
                evidence: HashMap::new(),
            };
        }

        let paths = all_paths(image);

        // ⚠️ V1: heuristiques simples
        // On évite les faux positifs courants sur bundles de certs publics (ex: Alpine)
        let allow_prefixes = [
            "etc/ssl/",
            "etc/ssl1.1/",
            "usr/share/ca-certificates/",
            "usr/local/share/ca-certificates/",
            "etc/apk/keys/",
            "usr/share/apk/keys/",
        ];
        let allow_exact_files = [
            "etc/ssl/cert.pem",
            "etc/ssl1.1/cert.pem",
            "etc/ssl/certs/ca-certificates.crt",
        ];

        let suspicious_suffixes = [".env", ".key", ".p12", ".pfx"]; // ✅ on retire .pem du FAIL direct
        let suspicious_exact = ["id_rsa", "id_ed25519", "kubeconfig", ".npmrc", ".pypirc"];

        let mut hits: Vec<String> = Vec::new();

        for p in paths {
            let lower = p.to_ascii_lowercase();

            // allowlist cert bundles / public keys locations
            if allow_exact_files.iter().any(|x| lower == *x) {
                continue;
            }
            if allow_prefixes.iter().any(|pref| lower.starts_with(pref)) && lower.ends_with(".pem") {
                continue;
            }

            if suspicious_exact.iter().any(|x| lower.ends_with(x) || lower.contains(x)) {
                hits.push(p);
                continue;
            }

            if suspicious_suffixes.iter().any(|s| lower.ends_with(s)) {
                hits.push(p);
                continue;
            }

            // ✅ cas vraiment suspects
            if lower.contains("/.ssh/") || lower.contains("/secrets/") {
                hits.push(p);
                continue;
            }

            // ⚠️ .pem ailleurs que les bundles connus => WARN (pas FAIL)
            if lower.ends_with(".pem") {
                hits.push(p);
                continue;
            }
        }

        if hits.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No obvious secret files detected in filesystem".to_string(),
                evidence: HashMap::new(),
            };
        }

        // V1: .pem hors allowlist => WARN, mais les autres patterns => FAIL
        // On fait simple: si un hit non-.pem existe => FAIL, sinon WARN.
        let mut non_pem = false;
        for h in &hits {
            if !h.to_ascii_lowercase().ends_with(".pem") {
                non_pem = true;
                break;
            }
        }

        let mut evidence = HashMap::new();
        for (i, h) in hits.iter().take(25).enumerate() {
            evidence.insert(format!("hit_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: if non_pem { Status::FAIL } else { Status::WARN },
            message: if non_pem {
                "Potential secret files detected in image filesystem".to_string()
            } else {
                "Potential sensitive PEM files detected (review recommended)".to_string()
            },
            evidence,
        }
    }
}
