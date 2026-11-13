import sys

from scanner.code_quality import scan_code_quality
from scanner.dependency_scan import scan_dependencies
from scanner.html_report import generate_html_report
from scanner.report_generator import generate_json_report
from scanner.secret_scan import scan_secrets
from scanner.security_scan import scan_security


def display_findings(title, findings):
    print(f"\n{title}")
    print("-" * 45)

    if not findings:
        print("No issues found!")
        return

    for finding in findings:
        print(f"\nTool: {finding.get('tool', 'Unknown')}")

        if "package" in finding:
            print(f"Package: {finding['package']}")
            print(f"Version: {finding['version']}")
            print(f"Vulnerability ID: {finding['vulnerability_id']}")
            print(f"Fix Versions: {finding['fix_versions']}")
        else:
            print(f"File: {finding.get('file', 'N/A')}")
            print(f"Line: {finding.get('line', 'N/A')}")

            if "test_id" in finding:
                print(f"Test ID: {finding['test_id']}")
                print(f"Confidence: {finding['confidence']}")

            if "rule_id" in finding:
                print(f"Rule ID: {finding['rule_id']}")

        message = (
            finding.get("message")
            or finding.get("issue")
            or "No description available"
        )

        print(f"Issue: {message}")
        print(f"Severity: {finding.get('severity', 'Unclassified')}")


def main():
    print("Starting Automated Code Review Bot...")

    quality_findings = scan_code_quality(".")
    security_findings = scan_security(".")
    secret_findings = scan_secrets(".")
    dependency_findings = scan_dependencies()


    all_findings = (
    quality_findings
    + security_findings
    + secret_findings
    + dependency_findings
)

    generate_json_report(all_findings)
    generate_html_report()

    display_findings("CODE QUALITY RESULTS", quality_findings)
    display_findings("SECURITY SCAN RESULTS", security_findings)
    display_findings("SECRET DETECTION RESULTS", secret_findings)
    display_findings("DEPENDENCY VULNERABILITY RESULTS", dependency_findings)

    print("\nSCAN SUMMARY")
    print("-" * 30)

    print("Code Quality Issues:", len(quality_findings))
    print("Security Issues:", len(security_findings))
    print("Secret Detection Issues:", len(secret_findings))
    print("Dependency Vulnerabilities:", len(dependency_findings))

    total = (
        len(quality_findings)
        + len(security_findings)
        + len(secret_findings)
        + len(dependency_findings)
    )

    print("Total Findings:", total)

    if total > 0:

       print("\nScan completed with issues. Failing the workflow.")
       sys.exit(1)

    print("\nScan completed successfully. No issues found.")


if __name__ == "__main__":
    main()
