
import json

# Security note: subprocess is used only to invoke the fixed Ruff CLI.
# Arguments are passed as a list; shell execution is disabled.
import subprocess  # nosec B404
import sys
from pathlib import Path


def scan_code_quality(project_path="."):
    """
    Scan Python files in a project using Ruff.
    Returns a list of code-quality findings.
    """

    project_path = Path(project_path).resolve()

    try:
        # Safe usage: fixed Ruff command, argument list, no shell=True.
        result = subprocess.run( # nosec B603
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                str(project_path),
                "--output-format",
                "json"
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False
        )

        if result.returncode not in (0, 1):
            print("Ruff error:", result.stderr)
            return []

        findings = json.loads(result.stdout)

        return [
            {
                "tool": "Ruff",
                "file": finding["filename"],
                "line": finding["location"]["row"],
                "column": finding["location"]["column"],
                "code": finding["code"],
                "message": finding["message"],
                "severity": "Low"
            }
            for finding in findings
        ]

    except subprocess.TimeoutExpired:
        print("Scan timed out.")
        return []

    except FileNotFoundError:
        print("Project folder not found.")
        return []

    except json.JSONDecodeError:
        print("Could not read Ruff output.")
        return []
