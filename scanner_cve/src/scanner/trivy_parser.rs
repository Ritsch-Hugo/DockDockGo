use serde_json::Value;

use crate::models::{CveFinding, ScanSummary, SeverityCount};

pub fn parse_trivy(json: &Value) -> (ScanSummary, Vec<CveFinding>) {
    let mut findings = Vec::new();

    let mut severity_count = SeverityCount::default();
    let mut total: u64 = 0;

    if let Some(results) = json.get("Results").and_then(|r| r.as_array()) {
        for result in results {
            if let Some(vulns) = result.get("Vulnerabilities").and_then(|v| v.as_array()) {
                for v in vulns {
                    total += 1;

                    let severity = v
                        .get("Severity")
                        .and_then(|x| x.as_str())
                        .unwrap_or("UNKNOWN")
                        .to_string();

                    match severity.as_str() {
                        "CRITICAL" => severity_count.critical += 1,
                        "HIGH" => severity_count.high += 1,
                        "MEDIUM" => severity_count.medium += 1,
                        "LOW" => severity_count.low += 1,
                        _ => severity_count.unknown += 1,
                    }

                    let cvss_score = v
                        .get("CVSS")
                        .and_then(|c| c.get("redhat"))
                        .and_then(|r| r.get("V3Score"))
                        .and_then(|s| s.as_f64());

                    let cvss_vector = v
                        .get("CVSS")
                        .and_then(|c| c.get("redhat"))
                        .and_then(|r| r.get("V3Vector"))
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string());

                    let finding = CveFinding {
                        cve_id: v
                            .get("VulnerabilityID")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),

                        package: v
                            .get("PkgName")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),

                        installed_version: v
                            .get("InstalledVersion")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),

                        fixed_version: v
                            .get("FixedVersion")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),

                        severity,

                        cvss_score,
                        cvss_vector,

                        title: v
                            .get("Title")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                    };

                    findings.push(finding);
                }
            }
        }
    }

    let summary = ScanSummary {
        vulnerabilities_total: total,
        severity_count,
    };

    (summary, findings)
}
