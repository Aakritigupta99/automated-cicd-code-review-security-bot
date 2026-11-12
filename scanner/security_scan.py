
import json
import subprocess  # nosec B404
import sys
from pathlib import Path


def scan_security(project_path="."):
    """Scan Python files for security issues using Bandit."""

    project_path = Path(project_path).resolve()

    excluded_paths = [
        str(project_path / "venv"),
        str(project_path / "tests"),
        str(project_path / ".git"),
        str(project_path / "__pycache__"),
    ]

    try:
        # Safe usage: fixed Bandit command, argument list, no shell=True.
        result = subprocess.run( # nosec B603
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                str(project_path),
                "-f",
                "json",
                "-x",
                ",".join(excluded_paths),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

        if not result.stdout.strip():
            print("Bandit did not produce a report.")
            print("Details:", result.stderr)
            return []

        report = json.loads(result.stdout)

        findings = []

        for item in report.get("results", []):
            findings.append({
                "tool": "Bandit",
                "file": item.get("filename", "Unknown"),
                "line": item.get("line_number", 0),
                "test_id": item.get("test_id", ""),
                "issue": item.get("issue_text", ""),
                "severity": item.get(
                    "issue_severity", "LOW"
                ).capitalize(),
                "confidence": item.get(
                    "issue_confidence", "LOW"
                ).capitalize()
            })

        return findings

    except subprocess.TimeoutExpired:
        print("Bandit scan timed out. Results are incomplete.")
        return []

    except FileNotFoundError:
        print("Bandit is not installed. Install it using pip.")
        return []

    except json.JSONDecodeError:
        print("Could not read Bandit's JSON report.")
        return []
