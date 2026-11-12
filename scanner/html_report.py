
import html
import json
from pathlib import Path


def generate_html_report(
    input_path="reports/scan_report.json",
    output_path="reports/scan_report.html",
):
    """Convert the unified JSON scan report into an HTML report."""

    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        print("JSON report not found. Run main.py first.")
        return

    with input_file.open("r", encoding="utf-8") as file:
        report = json.load(file)

    summary = report.get("summary", {})
    findings = report.get("findings", [])

    severity_counts = summary.get("severity_counts", {})
    scanner_counts = summary.get("scanner_counts", {})

    cards = ""

    for label, count in [
        ("Total Findings", summary.get("total_findings", 0)),
        ("High Severity", severity_counts.get("High", 0)),
        ("Medium Severity", severity_counts.get("Medium", 0)),
        ("Low Severity", severity_counts.get("Low", 0)),
    ]:
        cards += f"""
        <div class="card">
            <h3>{html.escape(label)}</h3>
            <p>{count}</p>
        </div>
        """

    rows = ""

    for finding in findings:
        tool = html.escape(str(finding.get("tool", "Unknown")))
        severity = html.escape(
            str(finding.get("severity", "Unclassified"))
        )

        file_name = finding.get("file") or finding.get("package", "N/A")
        file_name = html.escape(str(file_name))

        line = finding.get("line", "N/A")

        message = (
            finding.get("message")
            or finding.get("issue")
            or finding.get("description")
            or "No description available"
        )
        message = html.escape(str(message))

        rows += f"""
        <tr>
            <td>{tool}</td>
            <td>{severity}</td>
            <td>{file_name}</td>
            <td>{html.escape(str(line))}</td>
            <td>{message}</td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="5" class="clean">
                No findings detected. All scanners completed without
                reported issues.
            </td>
        </tr>
        """

    scanner_details = "".join(
        f"<li>{html.escape(str(tool))}: {count} finding(s)</li>"
        for tool, count in scanner_counts.items()
    )

    document = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Code Review Security Report</title>

        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f4f6f9;
                color: #263238;
                margin: 0;
                padding: 30px;
            }}

            .container {{
                max-width: 1100px;
                margin: auto;
            }}

            h1 {{ color: #1f3a5f; }}

            .cards {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 15px;
                margin: 25px 0;
            }}

            .card {{
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 8px #00000012;
            }}

            .card p {{
                font-size: 28px;
                font-weight: bold;
                margin-bottom: 0;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: white;
            }}

            th, td {{
                padding: 13px;
                text-align: left;
                border-bottom: 1px solid #ddd;
                overflow-wrap: anywhere;
            }}

            th {{
                background: #1f3a5f;
                color: white;
            }}

            .clean {{
                text-align: center;
                padding: 25px;
                color: #18794e;
                font-weight: bold;
            }}

            .section {{
                margin-top: 30px;
            }}

            .meta {{
                color: #667085;
                font-size: 14px;
            }}
        </style>
    </head>

    <body>
        <div class="container">
            <h1>Automated Code Review & Security Report</h1>

            <p class="meta">
                Generated at:
                {html.escape(str(report.get("generated_at", "Unknown")))}
            </p>

            <div class="cards">
                {cards}
            </div>

            <div class="section">
                <h2>Scanner Summary</h2>
                <ul>{scanner_details}</ul>
            </div>

            <div class="section">
                <h2>Detailed Findings</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th>Severity</th>
                            <th>File / Package</th>
                            <th>Line</th>
                            <th>Issue</th>
                        </tr>
                    </thead>

                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(document, encoding="utf-8")

    print(f"HTML report generated: {output_file.resolve()}")


if __name__ == "__main__":
    generate_html_report()
