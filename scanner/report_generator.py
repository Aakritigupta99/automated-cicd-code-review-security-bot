
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path


def generate_json_report(all_findings, output_path="reports/scan_report.json"):
    """Generate a unified JSON report from all scanner findings."""

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    severity_counts = Counter(
        finding.get("severity", "Unclassified").capitalize()
        for finding in all_findings
    )

    tool_counts = Counter({
    "Ruff": 0,
    "Bandit": 0,
    "Gitleaks": 0,
    "pip-audit": 0,
})

    tool_counts.update(
    finding.get("tool", "Unknown")
    for finding in all_findings
)

    report = {
        "project": "Automated CI/CD Code Review & Security Scanning Bot",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total_findings": len(all_findings),
            "severity_counts": dict(severity_counts),
            "scanner_counts": dict(tool_counts),
        },
        "findings": all_findings,
    }

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    print(f"\nJSON report generated: {output_file.resolve()}")

    return report
