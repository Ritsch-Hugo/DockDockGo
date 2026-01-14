use crate::engine::{all_paths, Rule};
use crate::models::*;
use std::collections::HashMap;

pub struct ForbiddenBinariesRule;

impl Rule for ForbiddenBinariesRule {
    fn id(&self) -> &'static str {
        "FORBIDDEN_BINARIES"
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

        let forbidden_names = [
            "sshd",
            "dropbear",
            "nc",
            "netcat",
            "socat",
            "telnet",
            "gcc",
            "g++",
            "clang",
            "make",
            "perl",
            "python",
        ];

        let mut hits: Vec<String> = Vec::new();

        for p in paths {
            let base = p.rsplit('/').next().unwrap_or(&p);
            let b = base.to_ascii_lowercase();

            if forbidden_names.iter().any(|name| b == *name) {
                hits.push(p);
            }
        }

        if hits.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No forbidden binaries detected (by filename)".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (i, h) in hits.iter().take(25).enumerate() {
            evidence.insert(format!("bin_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::WARN,
            message: "Forbidden binaries detected (hardening recommended)".to_string(),
            evidence,
        }
    }
}
