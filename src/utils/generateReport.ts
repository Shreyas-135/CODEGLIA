import { ScanReport } from '../types/vulnerability';

export function generateHTMLReport(report: ScanReport): string {
  const severityColors = {
    CRITICAL: '#dc2626',
    HIGH: '#ea580c',
    MEDIUM: '#d97706',
    LOW: '#65a30d',
    INFO: '#0284c7'
  };

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - ${report.projectName}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2rem;
            line-height: 1.6;
            color: #1f2937;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 3rem 2rem;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }

        .header p {
            opacity: 0.9;
            font-size: 1.1rem;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            padding: 2rem;
            background: #f8fafc;
        }

        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.15);
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .stat-label {
            color: #64748b;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .severity-breakdown {
            padding: 2rem;
        }

        .severity-breakdown h2 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
            color: #1e293b;
        }

        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }

        .severity-card {
            padding: 1.5rem;
            border-radius: 12px;
            color: white;
            text-align: center;
            font-weight: 600;
        }

        .vulnerabilities {
            padding: 2rem;
        }

        .vulnerabilities h2 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
            color: #1e293b;
        }

        .vuln-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .vuln-table thead {
            background: #1e293b;
            color: white;
        }

        .vuln-table th {
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.05em;
        }

        .vuln-table td {
            padding: 1rem;
            border-bottom: 1px solid #e2e8f0;
        }

        .vuln-table tbody tr:hover {
            background: #f8fafc;
        }

        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .code-snippet {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            margin-top: 0.5rem;
            overflow-x: auto;
        }

        .vuln-detail {
            font-size: 0.9rem;
            color: #64748b;
        }

        .footer {
            background: #f8fafc;
            padding: 2rem;
            text-align: center;
            color: #64748b;
            border-top: 1px solid #e2e8f0;
        }

        .filter-section {
            padding: 1.5rem 2rem;
            background: white;
            border-bottom: 1px solid #e2e8f0;
        }

        .filter-buttons {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 0.5rem 1rem;
            border: 2px solid #e2e8f0;
            background: white;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .filter-btn:hover {
            border-color: #667eea;
            color: #667eea;
        }

        .filter-btn.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }
            .filter-section {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Vulnerability Report</h1>
            <p>${report.projectName}</p>
            <p style="font-size: 0.95rem; margin-top: 0.5rem;">Generated on ${new Date(report.scanDate).toLocaleString()}</p>
        </div>

        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">${report.totalVulnerabilities}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${report.totalFiles}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${report.languages.length}</div>
                <div class="stat-label">Languages</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${report.criticalCount + report.highCount}</div>
                <div class="stat-label">Critical & High</div>
            </div>
        </div>

        <div class="severity-breakdown">
            <h2>Severity Breakdown</h2>
            <div class="severity-grid">
                <div class="severity-card" style="background: ${severityColors.CRITICAL};">
                    <div style="font-size: 2rem;">${report.criticalCount}</div>
                    <div>CRITICAL</div>
                </div>
                <div class="severity-card" style="background: ${severityColors.HIGH};">
                    <div style="font-size: 2rem;">${report.highCount}</div>
                    <div>HIGH</div>
                </div>
                <div class="severity-card" style="background: ${severityColors.MEDIUM};">
                    <div style="font-size: 2rem;">${report.mediumCount}</div>
                    <div>MEDIUM</div>
                </div>
                <div class="severity-card" style="background: ${severityColors.LOW};">
                    <div style="font-size: 2rem;">${report.lowCount}</div>
                    <div>LOW</div>
                </div>
                <div class="severity-card" style="background: ${severityColors.INFO};">
                    <div style="font-size: 2rem;">${report.infoCount}</div>
                    <div>INFO</div>
                </div>
            </div>
        </div>

        <div class="vulnerabilities">
            <h2>Detailed Vulnerabilities</h2>
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>Type</th>
                        <th>CWE/CVE</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    ${report.vulnerabilities.map(vuln => `
                        <tr>
                            <td>
                                <span class="severity-badge" style="background: ${severityColors[vuln.severity]}; color: white;">
                                    ${vuln.severity}
                                </span>
                            </td>
                            <td><strong>${vuln.fileName}</strong></td>
                            <td>${vuln.lineOfCode}</td>
                            <td>${vuln.vulnerabilityType}</td>
                            <td>
                                ${vuln.cwe ? `<div>CWE: ${vuln.cwe}</div>` : ''}
                                ${vuln.cve ? `<div>CVE: ${vuln.cve}</div>` : ''}
                                ${!vuln.cwe && !vuln.cve ? 'N/A' : ''}
                            </td>
                            <td>
                                <div><strong>${vuln.description}</strong></div>
                                ${vuln.explanation ? `<div class="vuln-detail" style="margin-top: 0.5rem;">${vuln.explanation}</div>` : ''}
                                ${vuln.suggestedFix ? `<div class="code-snippet">Fix: ${vuln.suggestedFix}</div>` : ''}
                                <div class="vuln-detail" style="margin-top: 0.5rem;">
                                    Tool: ${vuln.tool} | Language: ${vuln.language}
                                    ${vuln.confidenceLevel ? ` | Confidence: ${vuln.confidenceLevel}` : ''}
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p><strong>Vulnerability Detection Tool</strong></p>
            <p>AI-Powered Security Analysis using Bandit & Semgrep with Gemini API</p>
            <p style="margin-top: 1rem; font-size: 0.85rem;">
                Detected ${report.languages.join(', ')} code across ${report.totalFiles} files
            </p>
        </div>
    </div>
</body>
</html>
  `.trim();

  return html;
}

export function downloadReport(html: string, filename: string = 'vulnerability-report.html') {
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
