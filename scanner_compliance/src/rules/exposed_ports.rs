use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct ExposedPortsRule;

impl Rule for ExposedPortsRule {
    fn id(&self) -> &'static str {
        "EXPOSED_PORTS_POLICY"
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

        let sensitive_ports = ["22", "23", "3306", "5432", "6379"];

        let mut hits = Vec::new();
        for p in &image.config.exposed_ports {
            for s in &sensitive_ports {
                if p.starts_with(s) {
                    hits.push(p.clone());
                }
            }
        }

        if hits.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No sensitive exposed ports detected".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (i, p) in hits.iter().enumerate() {
            evidence.insert(format!("port_{i}"), p.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::WARN,
            message: "Sensitive ports exposed (review required)".to_string(),
            evidence,
        }
    }
}
