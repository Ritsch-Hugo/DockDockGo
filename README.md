# scanner_compliance (DockDockGo)

Stateless OCI/Docker image compliance scanner (image-level only).

## What it does
- Parses an **OCI manifest** (`manifest_raw`) and tracks artifact availability.
- Parses the **OCI config blob** (best-effort) to extract runtime metadata:
  - USER, ENV, LABELS, ENTRYPOINT/CMD, WORKDIR, EXPOSED PORTS, VOLUMES
- Reads **filesystem layers** (`tar` / `tar.gz`) in **streaming mode** (no full read in memory, no disk writes).
- Builds a **final in-memory filesystem view** (overlay) when all FS layers are present:
  - Applies layers in order
  - Supports whiteouts:
    - `.wh.<file>`
    - `.wh..wh..opq`
- Runs rules returning: `PASS / WARN / FAIL / SKIP`
- Outputs a JSON report **for every call**.

## What it does NOT do
- No Docker daemon, no `docker pull/run`, no Dockerfile, no build policy.
- No state stored between calls.
- No symlink resolution, no advanced permission model.

## Input: ScanRequest (JSON)
The binary expects a JSON payload like:

- `stage`: scan stage (e.g. `manifest_only`, `final`)
- `manifest_raw`: raw OCI manifest JSON string
- `blobs`: list of available blobs (config and layers)
  - `digest`: `sha256:...`
  - `path`: local path to the blob (present => blob is available)

The caller can invoke the scanner multiple times as blobs arrive progressively.

## Output: Report (JSON)
Report contains:
- `scan.inputs`: `has_manifest`, `has_config`, `has_fs`, layer counts
- `findings[]`: per-rule results with evidence
- `missing_artifacts[]`: artifacts still missing
- `pseudo_dockerfile` (final-only): best-effort informational output derived from config + final FS

Output is deterministic (sorted findings / missing artifacts).

## Run
Manifest-only:
```bash
cargo run --bin scanner_compliance -- samples/request_manifest_only.json
