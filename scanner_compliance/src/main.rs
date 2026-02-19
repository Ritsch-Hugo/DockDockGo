use std::process;

fn usage() -> String {
    "Usage:
  cargo run --bin scanner_compliance -- <input.json>

Example:
  cargo run --bin scanner_compliance -- samples/request_manifest_only.json
"
    .to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("{}", usage());
        process::exit(2);
    }

    let input_path = &args[1];

    // 🔥 On appelle la pipeline depuis la lib
    let image = match scanner_compliance::pipeline::load_image_from_json_file(input_path) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("{e}");
            process::exit(2);
        }
    };

    let report = scanner_compliance::pipeline::scan_image(&image);

    let json = serde_json::to_string_pretty(&report)
        .expect("serialize report");

    println!("{json}");

    if report.summary.fail > 0 {
        process::exit(1);
    }
}
