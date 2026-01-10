use crate::engine::{path_modes, Rule};
use crate::models::*;
use std::collections::HashMap;

pub struct DangerousPermissionsRule;

impl Rule for DangerousPermissionsRule {
    fn id(&self) -> &'static str {
        "DANGEROUS_PERMISSIONS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let pairs = path_modes(image);

        if pairs.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::SKIP,
                message:
                    "No file modes provided (fs_entries.mode missing), cannot evaluate permissions"
                        .to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut world_writable: Vec<String> = Vec::new();
        let mut suid_sgid: Vec<String> = Vec::new();

        for (path, mode) in pairs {
            // world-writable : bit o+w (0o002)
            if (mode & 0o002) != 0 {
                world_writable.push(format!("{path} (mode={:#o})", mode));
            }

            // suid (0o4000) / sgid (0o2000)
            if (mode & 0o4000) != 0 || (mode & 0o2000) != 0 {
                suid_sgid.push(format!("{path} (mode={:#o})", mode));
            }
        }

        if world_writable.is_empty() && suid_sgid.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No dangerous permissions detected (world-writable/SUID/SGID)".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();

        for (i, h) in world_writable.iter().take(15).enumerate() {
            evidence.insert(format!("world_writable_{i}"), h.clone());
        }

        for (i, h) in suid_sgid.iter().take(15).enumerate() {
            evidence.insert(format!("suid_sgid_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::WARN,
            message: "Dangerous permissions detected (world-writable and/or SUID/SGID)".to_string(),
            evidence,
        }
    }
}
