use serde_json::Value;

use crate::models::{CveFinding, ScanSummary};

pub fn parse_trivy(json: &Value) -> (ScanSummary, Vec<CveFinding>) {

    let mut findings = Vec::new();

    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    if let Some(results) = json.get("Results").and_then(|r| r.as_array()) {

        for result in results {

            if let Some(vulns) = result.get("Vulnerabilities").and_then(|v| v.as_array()) {

                for v in vulns {

                    let cve_id = v.get("VulnerabilityID")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();

                    let package = v.get("PkgName")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();

                    let installed = v.get("InstalledVersion")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();

                    let severity = v.get("Severity")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();

                    let cvss = v.get("CVSS")
                        .and_then(|c| c.get("redhat"))
                        .and_then(|r| r.get("V3Score"))
                        .and_then(|s| s.as_f64());

                    match severity.as_str() {
                        "CRITICAL" => critical += 1,
                        "HIGH" => high += 1,
                        "MEDIUM" => medium += 1,
                        "LOW" => low += 1,
                        _ => {}
                    }

                    findings.push(CveFinding {
                        cve_id,
                        package,
                        installed_version: installed,
                        severity,
                        cvss,
                    });
                }
            }
        }
    }

    let summary = ScanSummary {
        critical,
        high,
        medium,
        low,
    };

    (summary, findings)
}