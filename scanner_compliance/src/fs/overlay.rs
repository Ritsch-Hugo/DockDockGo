use std::collections::HashMap;

use crate::models::FsEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsNodeKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsNode {
    pub kind: FsNodeKind,
    pub mode: Option<u32>,
}

/// Index “final view” du filesystem : path -> node
pub type FsIndex = HashMap<String, FsNode>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayAction {
    /// Entrée normale : crée ou écrase le chemin
    Upsert { path: String, node: FsNode },

    /// Whiteout `.wh.<name>` : supprime `<dir>/<name>`
    Remove { target_path: String },

    /// Whiteout opaque `.wh..wh..opq`
    OpaqueDir { dir_path: String },
}

fn kind_from_entry(e: &FsEntry) -> FsNodeKind {
    match e.kind.as_deref() {
        Some("file") => FsNodeKind::File,
        Some("dir") => FsNodeKind::Dir,
        Some("symlink") => FsNodeKind::Symlink,
        Some(_) | None => FsNodeKind::Other,
    }
}

/// Convertit une FsEntry “brute” en FsNode
pub fn node_from_entry(e: &FsEntry) -> FsNode {
    FsNode {
        kind: kind_from_entry(e),
        mode: e.mode,
    }
}

fn split_dir_base(path: &str) -> (String, String) {
    match path.rsplit_once('/') {
        Some((dir, base)) => (dir.to_string(), base.to_string()),
        None => ("".to_string(), path.to_string()),
    }
}

fn join_dir_child(dir: &str, child: &str) -> String {
    if dir.is_empty() {
        child.to_string()
    } else {
        format!("{dir}/{child}")
    }
}

/// Classifie une entrée FS en action overlay (whiteout / upsert)
pub fn classify_entry(e: &FsEntry) -> OverlayAction {
    let (dir, base) = split_dir_base(&e.path);

    // `.wh..wh..opq` => opaque directory marker
    if base == ".wh..wh..opq" {
        return OverlayAction::OpaqueDir { dir_path: dir };
    }

    // `.wh.<name>` => remove <dir>/<name>
    if let Some(rest) = base.strip_prefix(".wh.") {
        let target_path = join_dir_child(&dir, rest);
        return OverlayAction::Remove { target_path };
    }

    OverlayAction::Upsert {
        path: e.path.clone(),
        node: node_from_entry(e),
    }
}

/// Supprime un chemin et tous ses descendants dans l’index
fn remove_tree(fs: &mut FsIndex, prefix: &str) {
    if prefix.is_empty() {
        return;
    }

    let child_prefix = format!("{prefix}/");

    let to_remove: Vec<String> = fs
        .keys()
        .filter(|k| *k == prefix || k.starts_with(&child_prefix))
        .cloned()
        .collect();

    for k in to_remove {
        fs.remove(&k);
    }
}

/// Supprime tous les enfants sous un dossier (dir/*) sans supprimer dir lui-même
fn remove_children(fs: &mut FsIndex, dir: &str) {
    if dir.is_empty() {
        // opaque root => tout supprimer
        fs.clear();
        return;
    }

    let child_prefix = format!("{dir}/");

    let to_remove: Vec<String> = fs
        .keys()
        .filter(|k| k.starts_with(&child_prefix))
        .cloned()
        .collect();

    for k in to_remove {
        fs.remove(&k);
    }
}

/// Applique les entrées d’un layer sur l’index final
/// - Upsert : insert / overwrite
/// - Remove : supprime la cible + ses descendants
/// - OpaqueDir : supprime les enfants existants du dossier
pub fn apply_layer(fs: &mut FsIndex, entries: &[FsEntry]) {
    for e in entries {
        match classify_entry(e) {
            OverlayAction::Upsert { path, node } => {
                fs.insert(path, node);
            }
            OverlayAction::Remove { target_path } => {
                remove_tree(fs, &target_path);
            }
            OverlayAction::OpaqueDir { dir_path } => {
                remove_children(fs, &dir_path);
            }
        }
    }
}
