use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct NonRootUserRule;

impl Rule for NonRootUserRule {
    fn id(&self) -> &'static str {
        "NON_ROOT_USER"
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

        let mut evidence = HashMap::new();

        let user = image.config.user.clone().unwrap_or_default();
        evidence.insert("config.user".to_string(), user.clone());

        let is_root = user.is_empty() || user == "root" || user == "0";

        if is_root {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::FAIL,
                message: "Container runs as root (config.user is empty/root/0)".to_string(),
                evidence,
            }
        } else {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "Container runs as non-root user".to_string(),
                evidence,
            }
        }
    }
}
