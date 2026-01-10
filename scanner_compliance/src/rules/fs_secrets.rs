use crate::engine::{all_paths, Rule};
use crate::models::*;
use std::collections::HashMap;

pub struct FsSecretsRule;

impl Rule for FsSecretsRule {
    fn id(&self) -> &'static str {
        "FS_SECRETS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let paths = all_paths(image);

        let suspicious_suffixes = [".env", ".pem", ".key", ".p12", ".pfx"];
        let suspicious_exact = ["id_rsa", "id_ed25519", "kubeconfig", ".npmrc", ".pypirc"];

        let mut hits: Vec<String> = Vec::new();

        for p in paths {
            let lower = p.to_ascii_lowercase();

            if suspicious_exact.iter().any(|x| lower.ends_with(x) || lower.contains(x)) {
                hits.push(p);
                continue;
            }

            if suspicious_suffixes.iter().any(|s| lower.ends_with(s)) {
                hits.push(p);
                continue;
            }

            if lower.contains("/.ssh/") || lower.contains("/secrets/") {
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

        let mut evidence = HashMap::new();
        for (i, h) in hits.iter().take(25).enumerate() {
            evidence.insert(format!("hit_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::FAIL,
            message: "Potential secret files detected in image filesystem".to_string(),
            evidence,
        }
    }
}
