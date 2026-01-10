use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct ManifestAnnotationsRule;

impl Rule for ManifestAnnotationsRule {
    fn id(&self) -> &'static str {
        "MANIFEST_ANNOTATIONS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let manifest = match &image.manifest {
            Some(m) => m,
            None => {
                return Finding {
                    rule_id: self.id().to_string(),
                    status: Status::SKIP,
                    message: "Manifest data not provided".to_string(),
                    evidence: HashMap::new(),
                }
            }
        };

        if manifest.annotations.is_empty() {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::WARN,
                message: "No annotations present in manifest".to_string(),
                evidence: HashMap::new(),
            }
        } else {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "Manifest annotations present".to_string(),
                evidence: HashMap::new(),
            }
        }
    }
}
