use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct SensitiveEnvRule;

impl SensitiveEnvRule {
    fn is_sensitive_key(key: &str) -> bool {
        let k = key.to_ascii_uppercase();

        let patterns = [
            "PASSWORD",
            "PASS",
            "TOKEN",
            "SECRET",
            "API_KEY",
            "AWS_SECRET",
            "PRIVATE_KEY",
            "ACCESS_KEY",
        ];

        patterns.iter().any(|p| k.contains(p))
    }

    fn mask_value(value: &str) -> String {
        if value.is_empty() {
            return "".to_string();
        }
        format!("*** (len={})", value.len())
    }
}

impl Rule for SensitiveEnvRule {
    fn id(&self) -> &'static str {
        "SENSITIVE_ENV_VARS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        if !image.has_config {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::SKIP,
                message: "Config blob not available yet (stage too early)".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut found: Vec<(String, String)> = Vec::new();

        for (k, v) in &image.config.env {
            if Self::is_sensitive_key(k) {
                found.push((k.clone(), Self::mask_value(v)));
            }
        }

        if found.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No sensitive environment variables detected".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (k, masked) in found {
            evidence.insert(format!("env.{k}"), masked);
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::FAIL,
            message: "Sensitive environment variables detected".to_string(),
            evidence,
        }
    }
}
