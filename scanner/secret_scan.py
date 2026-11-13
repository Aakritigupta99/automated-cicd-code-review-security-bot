
import json
import shutil
import subprocess  # nosec B404
from pathlib import Path


def scanner_error(message):
    """Return an error finding when Gitleaks cannot complete its scan."""
    return [{
        "tool": "Gitleaks",
        "file": "N/A",
        "line": 0,
        "message": message,
        "severity": "Error",
    }]


def scan_secrets(project_path="."):
    """Detect exposed secrets using Gitleaks."""

    project_path = Path(project_path).resolve()
    config_path = project_path / ".gitleaks.toml"

    # Find the Gitleaks executable.
    gitleaks_path = shutil.which("gitleaks")

    if gitleaks_path is None:
        return scanner_error(
            "Gitleaks is not installed or not in PATH."
        )

    try:
        result = subprocess.run(  # nosec B603
            [
                gitleaks_path,
                "dir",
                str(project_path),
                "--config",
                str(config_path),
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--redact",
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        if result.returncode not in (0, 1):
            return scanner_error(
                "Gitleaks execution failed: " + result.stderr
            )

        if not result.stdout.strip():
            return []

        findings = json.loads(result.stdout)

        return [
            {
                "tool": "Gitleaks",
                "file": item.get("File", "Unknown"),
                "line": item.get("StartLine", 0),
                "rule_id": item.get("RuleID", ""),
                "message": item.get("Description", ""),
                "severity": "High",
            }
            for item in findings
        ]

    except subprocess.TimeoutExpired:
        return scanner_error("Gitleaks scan timed out.")

    except FileNotFoundError:
        return scanner_error(
            "Gitleaks executable could not be found."
        )

    except json.JSONDecodeError:
        return scanner_error(
            "Could not read Gitleaks JSON report."
        )
