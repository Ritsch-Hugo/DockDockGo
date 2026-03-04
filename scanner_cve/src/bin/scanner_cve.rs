use anyhow::{Context, Result};
use clap::Parser;
use scanner_cve::engine;
use scanner_cve::models::ScanRequest;

#[derive(Debug, Parser)]
#[command(name = "scanner_cve", about = "DocDockGo - Static CVE scanner (V1 CLI)")]
struct Args {
    /// Path to request.json
    #[arg(long, short = 'r')]
    request: String,

    /// Pretty-print JSON output
    #[arg(long)]
    pretty: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let raw = std::fs::read_to_string(&args.request)
        .with_context(|| format!("failed to read request file: {}", args.request))?;

    let req: ScanRequest = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse JSON request: {}", args.request))?;

    let resp = engine::run(&req).context("engine pipeline failed")?;

    if args.pretty {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("{}", serde_json::to_string(&resp)?);
    }

    Ok(())
}