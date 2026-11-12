
import json
import subprocess  # nosec B404
import sys
from pathlib import Path


def scan_dependencies(requirements_file="requirements.txt"):
    """Find known vulnerabilities in project dependencies."""

    requirements_path = Path(requirements_file).resolve()

    if not requirements_path.exists():
        print(f"Requirements file not found: {requirements_path}")
        return []

    try:
        # Safe usage: fixed pip-audit command, argument list, no shell=True.
        result = subprocess.run(  # nosec B603
            [
                sys.executable,
                "-m",
                "pip_audit",
                "-r",
                str(requirements_path),
                "--format=json",
                "--progress-spinner=off",
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        if result.returncode not in (0, 1):
            print("pip-audit error:", result.stderr)
            return []

        if not result.stdout.strip():
            print("pip-audit returned an empty report.")
            return []

        report = json.loads(result.stdout)

        dependencies = (
            report.get("dependencies", [])
            if isinstance(report, dict)
            else report
        )

        findings = []

        for package in dependencies:
            for vulnerability in package.get("vulns", []):
                findings.append({
                    "tool": "pip-audit",
                    "package": package.get("name", "Unknown"),
                    "version": package.get("version", "Unknown"),
                    "vulnerability_id": vulnerability.get("id", ""),
                    "aliases": vulnerability.get("aliases", []),
                    "fix_versions": vulnerability.get(
                        "fix_versions", []
                    ),
                    "message": vulnerability.get(
                        "description",
                        "Known vulnerability detected",
                    ),
                    "severity": "Unclassified",
                })

        return findings

    except subprocess.TimeoutExpired:
        print("Dependency scan timed out.")
        return []

    except FileNotFoundError:
        print("pip-audit is not installed.")
        return []

    except json.JSONDecodeError:
        print("Could not read pip-audit JSON report.")
        return []
