use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct ManifestMediaTypeRule;

impl Rule for ManifestMediaTypeRule {
    fn id(&self) -> &'static str {
        "MANIFEST_MEDIA_TYPE"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let _m = match &image.manifest {
            Some(m) if image.has_manifest => m,
            _ => {
                return Finding {
                    rule_id: self.id().to_string(),
                    status: Status::SKIP,
                    message: "Manifest not available".to_string(),
                    evidence: HashMap::new(),
                }
            }
        };

        let manifest = match &image.manifest {
            Some(m) => m,
            _none => {
                return Finding {
                    rule_id: self.id().to_string(),
                    status: Status::SKIP,
                    message: "Manifest data not provided".to_string(),
                    evidence: HashMap::new(),
                }
            }
        };

        let mt = match &manifest.media_type {
            Some(v) => v,
            _none => {
                return Finding {
                    rule_id: self.id().to_string(),
                    status: Status::SKIP,
                    message: "Manifest mediaType missing".to_string(),
                    evidence: HashMap::new(),
                }
            }
        };

        let allowed = [
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ];

        if allowed.iter().any(|a| mt == a) {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "Manifest mediaType is valid".to_string(),
                evidence: HashMap::new(),
            }
        } else {
            let mut ev = HashMap::new();
            ev.insert("media_type".to_string(), mt.clone());

            Finding {
                rule_id: self.id().to_string(),
                status: Status::WARN,
                message: "Unexpected manifest mediaType".to_string(),
                evidence: ev,
            }
        }
    }
}
