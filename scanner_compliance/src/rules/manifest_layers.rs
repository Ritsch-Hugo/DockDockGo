use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct ManifestLayersCountRule;

impl Rule for ManifestLayersCountRule {
    fn id(&self) -> &'static str {
        "MANIFEST_LAYERS_COUNT"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let manifest = match &image.manifest {
            Some(m) => m,
            none => {
                return Finding {
                    rule_id: self.id().to_string(),
                    status: Status::SKIP,
                    message: "Manifest data not provided".to_string(),
                    evidence: HashMap::new(),
                }
            }
        };

        let count = match manifest.layers_count {
            Some(c) => c,
            none => {
                return Finding {
                    rule_id: self.id().to_string(),
                    status: Status::SKIP,
                    message: "Layers count missing in manifest".to_string(),
                    evidence: HashMap::new(),
                }
            }
        };

        if count <= 20 {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "Reasonable number of layers".to_string(),
                evidence: HashMap::new(),
            }
        } else {
            let mut ev = HashMap::new();
            ev.insert("layers_count".to_string(), count.to_string());

            Finding {
                rule_id: self.id().to_string(),
                status: Status::WARN,
                message: "High number of layers (image complexity)".to_string(),
                evidence: ev,
            }
        }
    }
}
