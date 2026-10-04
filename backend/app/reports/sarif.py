"""The report as SARIF 2.1.0.

SARIF is the interchange format for static-analysis results: it is what GitHub
code scanning, Azure DevOps and most editors read. Producing it means these
findings can be shown where a developer already looks, instead of only here.

Only **open** findings are results. A fixed finding is not a result of the
current code, and a consumer that annotates lines would annotate one that no
longer has anything on it.

Two mappings in this file are conventions rather than facts, and are named as
such:

* ``level`` — SARIF has three levels and this project has five severities.
* ``security-severity`` — the number GitHub uses to sort results into
  critical/high/medium/low. It is on CVSS's 0–10 scale for that reason only.
  **It is not a CVSS score**; each value is simply a number inside the band
  that reproduces this project's own severity on GitHub's side.
"""

from typing import Any

from app.reports.model import Report

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
FINGERPRINT_KEY = "sentinelforge/v1"

LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# Inside GitHub's bands: critical >= 9.0, high >= 7.0, medium >= 4.0, low > 0.
SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
    "INFO": "1.0",
}


def render(report: Report) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    index_of: dict[str, int] = {}
    for rule in report.rules:
        index_of[rule.rule_id] = len(rules)
        tags = ["security"]
        if rule.cwe_id:
            # The tag form GitHub recognises: external/cwe/cwe-89.
            tags.append(f"external/cwe/{rule.cwe_id.lower()}")
        descriptor: dict[str, Any] = {
            "id": rule.rule_id,
            "name": rule.rule_id,
            "shortDescription": {"text": rule.title},
            "defaultConfiguration": {"level": LEVELS.get(rule.worst_severity, "warning")},
            "properties": {
                "tags": tags,
                "security-severity": SECURITY_SEVERITY.get(rule.worst_severity, "5.5"),
            },
        }
        if rule.risk_note:
            descriptor["fullDescription"] = {"text": rule.risk_note}
        if rule.fix_note:
            descriptor["help"] = {"text": rule.fix_note}
        rules.append(descriptor)

    results: list[dict[str, Any]] = []
    for finding in report.findings:
        region: dict[str, Any] = {
            "startLine": max(1, finding.line_start),
            "endLine": max(1, finding.line_start, finding.line_end),
        }
        if finding.snippet.strip():
            # Already redacted by the analyser for credentials.
            region["snippet"] = {"text": finding.snippet}
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": index_of[finding.rule_id],
                "level": LEVELS.get(finding.severity, "warning"),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": region,
                        }
                    }
                ],
                # Stable across scans, so a consumer can tell "still there"
                # from "new" without comparing line numbers.
                "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "state": finding.status,
                    "riskScore": finding.score,
                    "fix": str(finding.fix_state),
                },
            }
        )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": report.tool_name,
                "version": report.tool_version,
                "rules": rules,
            }
        },
        "results": results,
        "columnKind": "utf16CodeUnits",
        "properties": {
            "riskScore": report.score,
            "riskGrade": report.grade,
            "riskPolicyVersion": report.policy_version,
            "truncated": report.scan.truncated,
        },
    }
    if report.commit_hash:
        run["versionControlProvenance"] = [
            {"repositoryUri": report.origin, "revisionId": report.commit_hash}
            | ({"branch": report.branch} if report.branch else {})
        ]
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


__all__ = [
    "FINGERPRINT_KEY",
    "LEVELS",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SECURITY_SEVERITY",
    "render",
]
