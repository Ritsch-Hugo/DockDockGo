use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct RequiredLabelsRule;

impl Rule for RequiredLabelsRule {
    fn id(&self) -> &'static str {
        "REQUIRED_OCI_LABELS"
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

        // Liste minimale (tu pourras l'étendre)
        let required = [
            "org.opencontainers.image.source",
            "org.opencontainers.image.revision",
        ];

        let labels = &image.config.labels;

        let mut missing: Vec<&str> = Vec::new();
        for key in required {
            if !labels.contains_key(key) {
                missing.push(key);
            }
        }

        let mut evidence = HashMap::new();
        evidence.insert("missing_labels".to_string(), missing.join(", "));

        if labels.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::FAIL,
                message: "No OCI labels found: image is not traceable".to_string(),
                evidence,
            };
        }

        if !missing.is_empty() {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::WARN,
                message: "Some required OCI labels are missing".to_string(),
                evidence,
            }
        } else {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "Required OCI labels are present".to_string(),
                evidence: HashMap::new(),
            }
        }
    }
}
