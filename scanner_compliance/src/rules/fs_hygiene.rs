use crate::engine::{all_paths, Rule};
use crate::models::*;
use std::collections::HashMap;

pub struct FsHygieneRule;

impl Rule for FsHygieneRule {
    fn id(&self) -> &'static str {
        "FS_HYGIENE"
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

        let bad_dirs = ["/var/cache/", "/var/log/", "/tmp/", "/var/tmp/"];
        let mut hits = Vec::new();

        for p in paths {
            if bad_dirs.iter().any(|d| p.starts_with(d)) {
                hits.push(p);
            }
        }

        if hits.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No cache/log/temp files detected".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut ev = HashMap::new();
        for (i, h) in hits.iter().take(20).enumerate() {
            ev.insert(format!("path_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::WARN,
            message: "Cache/log/temp files present in image".to_string(),
            evidence: ev,
        }
    }
}
