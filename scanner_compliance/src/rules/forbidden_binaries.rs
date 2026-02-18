use crate::engine::Rule;
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

        // Liste V1 volontairement simple
        let forbidden = [
            "/bin/nc",
            "/usr/bin/nc",
            "/bin/netcat",
            "/usr/bin/netcat",
            "/bin/telnet",
            "/usr/bin/telnet",
        ];

        let mut hits: Vec<String> = Vec::new();

if !image.fs_entries.is_empty() {
    for e in &image.fs_entries {
        let kind = e.kind.as_deref().unwrap_or("other");
        if kind != "file" {
            continue;
        }

        let path = format!("/{}", e.path.trim_start_matches('/'));
        if forbidden.iter().any(|f| path == *f) {
            hits.push(e.path.clone());
        }
    }
} else {
    // Legacy fallback: fs_paths
    for p in &image.fs_paths {
        let path = format!("/{}", p.trim_start_matches('/'));
        if forbidden.iter().any(|f| path == *f) {
            hits.push(p.clone());
        }
    }
}

        if hits.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No forbidden binaries detected".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (i, h) in hits.iter().take(10).enumerate() {
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
