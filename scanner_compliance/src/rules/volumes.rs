use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct VolumesRule;

impl Rule for VolumesRule {
    fn id(&self) -> &'static str {
        "VOLUMES_POLICY"
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

        if image.config.volumes.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No volumes declared in image".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (i, v) in image.config.volumes.iter().enumerate() {
            evidence.insert(format!("volume_{i}"), v.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::WARN,
            message: "Image declares volumes (review persistence and access)".to_string(),
            evidence,
        }
    }
}
