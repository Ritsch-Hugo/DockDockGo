use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct WorkingDirRule;

impl Rule for WorkingDirRule {
    fn id(&self) -> &'static str {
        "WORKING_DIR_PRESENT"
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

        if image.config.working_dir.is_none() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::WARN,
                message: "Working directory is not defined".to_string(),
                evidence: HashMap::new(),
            };
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::PASS,
            message: "Working directory is defined".to_string(),
            evidence: HashMap::new(),
        }
    }
}
