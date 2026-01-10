use crate::engine::{all_paths, Rule};
use crate::models::*;
use std::collections::HashMap;

pub struct FsWeakConfigsRule;

impl Rule for FsWeakConfigsRule {
    fn id(&self) -> &'static str {
        "FS_WEAK_CONFIGS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let paths = all_paths(image);

        let weak_configs = ["/etc/ssh/sshd_config"];
        let hits: Vec<String> = paths
            .into_iter()
            .filter(|p| weak_configs.contains(&p.as_str()))
            .collect();

        if hits.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No weak configuration files detected".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut ev = HashMap::new();
        for (i, h) in hits.iter().enumerate() {
            ev.insert(format!("config_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::WARN,
            message: "Potentially weak configuration files present".to_string(),
            evidence: ev,
        }
    }
}

