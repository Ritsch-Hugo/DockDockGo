mod engine;
mod models;
mod rules;

use crate::engine::run_rules;
use crate::models::ImageData;
use crate::rules::*;
use std::process;

fn load_image_from_json(path: &str) -> Result<ImageData, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {path}: {e}"))?;

    serde_json::from_str::<ImageData>(&content)
        .map_err(|e| format!("failed to parse JSON {path}: {e}"))
}

fn usage() -> String {
    "Usage:\n  cargo run -- <input.json>\nExample:\n  cargo run -- samples/image_ok.json\n".to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("{}", usage());
        process::exit(2);
    }

    let input_path = &args[1];
    let image = match load_image_from_json(input_path) {
        Ok(img) => img,
        Err(err) => {
            eprintln!("{err}");
            process::exit(2);
        }
    };

    let rules: Vec<Box<dyn engine::Rule>> = vec![
        Box::new(NonRootUserRule),
        Box::new(RequiredLabelsRule),
        Box::new(SensitiveEnvRule),
        Box::new(FsSecretsRule),
        Box::new(ForbiddenBinariesRule),
        Box::new(DangerousPermissionsRule),
        Box::new(EntrypointCmdRule),
        Box::new(ExposedPortsRule),
        Box::new(WorkingDirRule),
        Box::new(VolumesRule),
];

    let report = run_rules(&image, &rules);

    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    println!("{json}");

    if report.summary.fail > 0 {
        process::exit(1);
    }
}
