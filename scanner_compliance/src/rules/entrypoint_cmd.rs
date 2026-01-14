use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct EntrypointCmdRule;

impl Rule for EntrypointCmdRule {
    fn id(&self) -> &'static str {
        "ENTRYPOINT_CMD_PRESENT"
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

        let has_entrypoint = !image.config.entrypoint.is_empty();
        let has_cmd = !image.config.cmd.is_empty();

        if !has_entrypoint && !has_cmd {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::FAIL,
                message: "Neither entrypoint nor cmd is defined (non-deterministic startup)".to_string(),
                evidence: HashMap::new(),
            };
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::PASS,
            message: "Entrypoint or cmd is defined".to_string(),
            evidence: HashMap::new(),
        }
    }
}
