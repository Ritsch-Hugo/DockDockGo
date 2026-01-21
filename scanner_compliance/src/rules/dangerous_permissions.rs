use crate::engine::Rule;
use crate::models::*;
use std::collections::HashMap;

pub struct DangerousPermissionsRule;

impl Rule for DangerousPermissionsRule {
    fn id(&self) -> &'static str {
        "DANGEROUS_PERMISSIONS"
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

        // On itère directement sur fs_entries pour pouvoir utiliser kind
        let mut world_writable: Vec<String> = Vec::new();
        let mut suid_sgid: Vec<String> = Vec::new();

        let mut any_mode = false;

        for e in &image.fs_entries {
            let Some(mode) = e.mode else { continue };
            any_mode = true;

            let kind = e.kind.as_deref().unwrap_or("other");

            // ✅ IMPORTANT: on ignore les symlinks (permissions non pertinentes)
            if kind == "symlink" {
                continue;
            }

            // world-writable : bit o+w (0o002)
            let is_world_writable = (mode & 0o002) != 0;

            // sticky bit : 0o1000 (ex: /tmp = 1777) -> acceptable si dir
            let has_sticky = (mode & 0o1000) != 0;
            let is_dir = kind == "dir";

            if is_world_writable {
                // Si directory + sticky => on ne flag pas (cas standard /tmp, /var/tmp)
                if !(is_dir && has_sticky) {
                    world_writable.push(format!("{} (mode={:#o}, kind={})", e.path, mode, kind));
                }
            }

            // suid (0o4000) / sgid (0o2000) -> pertinent pour files/dirs (symlink déjà exclu)
            if (mode & 0o4000) != 0 || (mode & 0o2000) != 0 {
                suid_sgid.push(format!("{} (mode={:#o}, kind={})", e.path, mode, kind));
            }
        }

        if !any_mode {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::SKIP,
                message:
                    "No file modes provided (fs_entries.mode missing), cannot evaluate permissions"
                        .to_string(),
                evidence: HashMap::new(),
            };
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
