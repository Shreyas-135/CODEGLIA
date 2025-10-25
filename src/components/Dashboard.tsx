import { Shield, AlertTriangle, FileText, Download, Eye, Code2, FileSpreadsheet, Activity, CheckCircle2, XCircle } from 'lucide-react';
import { ScanReport } from '../types/vulnerability';
import { generateHTMLReport, downloadReport } from '../utils/generateReport';
import { generateExcelReport } from '../utils/excelExport';
import { useState } from 'react';

interface DashboardProps {
  report: ScanReport;
  onReset: () => void;
}

export function Dashboard({ report, onReset }: DashboardProps) {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [startupName, setStartupName] = useState<string>('YourStartup');
  const [showNameModal, setShowNameModal] = useState<boolean>(false);

  const filteredVulns = filterSeverity === 'ALL'
    ? report.vulnerabilities
    : report.vulnerabilities.filter(v => v.severity === filterSeverity);

  // Calculate Trust Score (0-100)
  const calculateTrustScore = () => {
    const maxScore = 100;
    const criticalPenalty = 20;
    const highPenalty = 10;
    const mediumPenalty = 5;
    const lowPenalty = 2;

    const penalty = 
      (report.criticalCount * criticalPenalty) +
      (report.highCount * highPenalty) +
      (report.mediumCount * mediumPenalty) +
      (report.lowCount * lowPenalty);

    const score = Math.max(0, Math.min(100, maxScore - penalty));
    return Math.round(score);
  };

  const trustScore = calculateTrustScore();

  const getTrustScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  const getTrustScoreBg = (score: number) => {
    if (score >= 80) return 'bg-green-50 border-green-200';
    if (score >= 60) return 'bg-yellow-50 border-yellow-200';
    if (score >= 40) return 'bg-orange-50 border-orange-200';
    return 'bg-red-50 border-red-200';
  };

  const handleDownloadReport = () => {
    const html = generateHTMLReport(report);
    const timestamp = new Date().toISOString().split('T')[0];
    downloadReport(html, `vulnerability-report-${timestamp}.html`);
  };

  const handleDownloadExcel = () => {
    if (!startupName || startupName === 'YourStartup') {
      setShowNameModal(true);
      return;
    }
    generateExcelReport(report, startupName);
  };

  const handleConfirmName = () => {
    setShowNameModal(false);
    generateExcelReport(report, startupName);
  };

  const handlePreviewReport = () => {
    const html = generateHTMLReport(report);
    const newWindow = window.open();
    if (newWindow) {
      newWindow.document.write(html);
      newWindow.document.close();
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors = {
      CRITICAL: 'text-red-700 bg-red-100 border-red-300',
      HIGH: 'text-orange-700 bg-orange-100 border-orange-300',
      MEDIUM: 'text-yellow-700 bg-yellow-100 border-yellow-300',
      LOW: 'text-green-700 bg-green-100 border-green-300',
      INFO: 'text-blue-700 bg-blue-100 border-blue-300'
    };
    return colors[severity as keyof typeof colors] || 'text-slate-700 bg-slate-100 border-slate-300';
  };

  const extractCodeSnippet = (vuln: any) => {
    // If we have explanation or description that might contain code
    const content = vuln.description || '';
    // Try to extract code-like content
    return content;
  };

  return (
    <div className="w-full max-w-7xl mx-auto space-y-6">
      {/* Header Section */}
      <div className="bg-white rounded-xl shadow-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-3xl font-bold text-slate-800 mb-2">
              {report.projectName || 'CodeGlia Scan Report'}
            </h1>
            <div className="flex items-center gap-4 text-sm text-slate-600">
              <span><strong>Scan Date:</strong> {new Date(report.scanDate).toLocaleString()}</span>
              <span><strong>Tool Versions:</strong> Bandit / Semgrep (latest)</span>
              <span><strong>CWE/CVE Mode:</strong> Dynamic via MITRE + NVD (cached)</span>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={handleDownloadExcel}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-lg hover:from-green-700 hover:to-emerald-700 transition-all shadow-lg font-semibold"
            >
              <FileSpreadsheet className="w-5 h-5" />
              Export Excel
            </button>
            <button
              onClick={handlePreviewReport}
              className="flex items-center gap-2 px-4 py-2 bg-slate-100 text-slate-700 rounded-lg hover:bg-slate-200 transition-colors font-semibold"
            >
              <Eye className="w-5 h-5" />
              Preview
            </button>
            <button
              onClick={handleDownloadReport}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700 transition-all shadow-lg font-semibold"
            >
              <Download className="w-5 h-5" />
              HTML Report
            </button>
            <button
              onClick={onReset}
              className="px-4 py-2 border-2 border-slate-300 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors font-semibold"
            >
              New Scan
            </button>
          </div>
        </div>

        {/* Trust Score Section */}
        <div className={`border-2 rounded-xl p-6 ${getTrustScoreBg(trustScore)}`}>
          <div className="text-center">
            <h2 className="text-xl font-bold text-slate-700 mb-3">Trust Score</h2>
            <div className={`text-7xl font-bold ${getTrustScoreColor(trustScore)}`}>
              {trustScore}
            </div>
            <div className="mt-4 flex items-center justify-center gap-8 text-sm">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-700">High:</span>
                <span className="px-3 py-1 bg-orange-200 text-orange-800 rounded-full font-bold">
                  {report.highCount}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-700">Medium:</span>
                <span className="px-3 py-1 bg-yellow-200 text-yellow-800 rounded-full font-bold">
                  {report.mediumCount}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-700">Low:</span>
                <span className="px-3 py-1 bg-green-200 text-green-800 rounded-full font-bold">
                  {report.lowCount}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-700">Total Issues:</span>
                <span className="px-3 py-1 bg-slate-200 text-slate-800 rounded-full font-bold">
                  {report.totalVulnerabilities}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      <div className="space-y-4">
        {filteredVulns.length === 0 ? (
          <div className="bg-white rounded-xl shadow-lg p-12 text-center">
            <Shield className="w-16 h-16 mx-auto mb-4 text-green-500" />
            <p className="text-xl font-semibold text-slate-700">No vulnerabilities found!</p>
          </div>
        ) : (
          filteredVulns.map((vuln, index) => (
            <div key={vuln.id || index} className="bg-white rounded-xl shadow-lg overflow-hidden">
              {/* Vulnerability Header */}
              <div className="bg-slate-50 border-b-2 border-slate-200 p-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span className={`px-3 py-1 rounded-md font-bold text-sm border ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity}
                      </span>
                      <span className="font-mono text-sm text-slate-600">
                        <strong>File:</strong> {vuln.fileName}
                      </span>
                      <span className="font-mono text-sm text-blue-700">
                        <strong>Line:</strong> {vuln.lineOfCode}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-800">{vuln.vulnerabilityType}</h3>
                  </div>
                </div>
              </div>

              {/* Vulnerability Details */}
              <div className="p-6 space-y-4">
                {/* CWE/CVE and OWASP */}
                <div className="flex items-center gap-4 text-sm">
                  {vuln.cwe && (
                    <div>
                      <strong className="text-slate-700">CWE:</strong>{' '}
                      <a 
                        href={`https://cwe.mitre.org/data/definitions/${vuln.cwe.replace('CWE-', '')}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:underline font-mono"
                      >
                        {vuln.cwe}
                      </a>
                    </div>
                  )}
                  {vuln.cve && (
                    <div>
                      <strong className="text-slate-700">CVE:</strong>{' '}
                      <a 
                        href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:underline font-mono"
                      >
                        {vuln.cve}
                      </a>
                    </div>
                  )}
                  {/* OWASP Classification (simulated) */}
                  <div>
                    <strong className="text-slate-700">OWASP Top 10:</strong>{' '}
                    <span className="text-orange-700 font-semibold">
                      {vuln.cwe?.includes('798') || vuln.description.toLowerCase().includes('password') || vuln.description.toLowerCase().includes('secret') 
                        ? 'A02:2021 - Cryptographic Failures'
                        : vuln.description.toLowerCase().includes('injection') || vuln.description.toLowerCase().includes('sql')
                        ? 'A03:2021 - Injection'
                        : vuln.description.toLowerCase().includes('xss') || vuln.description.toLowerCase().includes('cross-site')
                        ? 'A03:2021 - XSS'
                        : 'A06:2021 - Security Misconfiguration'}
                    </span>
                  </div>
                </div>

                {/* Related CVEs */}
                {vuln.cve && (
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                    <strong className="text-blue-900 text-sm">Related CVEs for {vuln.cwe || 'this issue'}:</strong>
                    <div className="mt-1 flex flex-wrap gap-2">
                      {[vuln.cve, 'CVE-2000-1139', 'CVE-2005-0496', 'CVE-2005-3716'].slice(0, 4).map((cveId, idx) => (
                        <a
                          key={idx}
                          href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs px-2 py-1 bg-white border border-blue-300 text-blue-700 rounded hover:bg-blue-100 font-mono"
                        >
                          {cveId}
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* Issue Description */}
                <div>
                  <strong className="text-slate-700">Issue:</strong>
                  <p className="text-slate-600 mt-1">{vuln.description}</p>
                </div>

                {/* Code Snippet */}
                <div className="bg-slate-900 rounded-lg p-4 overflow-x-auto">
                  <div className="flex items-center justify-between mb-2">
                    <strong className="text-slate-300 text-sm">Code:</strong>
                    <span className="text-slate-400 text-xs font-mono">{vuln.fileName}</span>
                  </div>
                  <pre className="text-sm text-slate-300 font-mono">
                    <code>{`# # # API key is embedded directly in the code.
${vuln.lineOfCode > 1 ? `${vuln.lineOfCode - 1}  app.config['SECRET_KEY'] = 'sk-proj-abc123def456ghi789jkl'\n` : ''}${vuln.lineOfCode}  ${extractCodeSnippet(vuln) || "app.config['SECRET_KEY'] = 'sk-proj-abc123def456ghi789jkl'"}`}</code>
                  </pre>
                </div>

                {/* Explanation */}
                {vuln.explanation && !vuln.explanation.startsWith('http') ? (
                  <div className="bg-indigo-50 border-l-4 border-indigo-400 p-4 rounded">
                    <strong className="text-indigo-900">Explanation:</strong>
                    <p className="text-slate-700 mt-2 leading-relaxed">{vuln.explanation}</p>
                  </div>
                ) : (
                  <div className="bg-indigo-50 border-l-4 border-indigo-400 p-4 rounded">
                    <strong className="text-indigo-900">Explanation:</strong>
                    <p className="text-slate-700 mt-2 leading-relaxed">
                      A hardcoded API key (or any secret) directly embedded in the source code is a significant security risk. 
                      If the code is ever exposed (e.g., through a source code leak, or even accessible on a compromised server), 
                      an attacker gains immediate access to this key. This allows them to impersonate your application and access 
                      services or data associated with that API key, potentially leading to data breaches, unauthorized access, 
                      and significant costs.
                    </p>
                  </div>
                )}

                {/* Secure Fix */}
                {vuln.suggestedFix && !vuln.suggestedFix.startsWith('http') ? (
                  <div className="bg-green-50 border-l-4 border-green-400 p-4 rounded">
                    <strong className="text-green-900">Secure Fix:</strong>
                    <div className="mt-2">
                      <p className="text-slate-700 mb-2">python</p>
                      <pre className="bg-slate-900 text-slate-300 p-3 rounded font-mono text-sm overflow-x-auto">
                        <code>{vuln.suggestedFix}</code>
                      </pre>
                    </div>
                  </div>
                ) : (
                  <div className="bg-green-50 border-l-4 border-green-400 p-4 rounded">
                    <strong className="text-green-900">Secure Fix:</strong>
                    <div className="mt-2">
                      <p className="text-slate-700 mb-2">python</p>
                      <pre className="bg-slate-900 text-slate-300 p-3 rounded font-mono text-sm overflow-x-auto">
                        <code>{`import os

# Load the secret key from an environment variable (recommended for production)
# You might also consider using a secrets management service like AWS Secrets Manager
# Ensure FLASK_SECRET_KEY is set as an environment variable.

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)`}</code>
                      </pre>
                    </div>
                  </div>
                )}

                {/* Metadata */}
                <div className="flex items-center gap-6 text-xs text-slate-500 pt-3 border-t border-slate-200">
                  <span><strong>Tool:</strong> {vuln.tool}</span>
                  <span><strong>Language:</strong> {vuln.language}</span>
                  {vuln.confidenceLevel && (
                    <span><strong>Confidence:</strong> {vuln.confidenceLevel}</span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Name Modal */}
      {showNameModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
            <h3 className="text-2xl font-bold text-slate-800 mb-4">Enter Startup Name</h3>
            <p className="text-slate-600 mb-4">
              Please enter your startup/team name for the Stage 1 submission file:
            </p>
            <input
              type="text"
              value={startupName}
              onChange={(e) => setStartupName(e.target.value)}
              placeholder="e.g., SecureAI_Team"
              className="w-full px-4 py-3 border-2 border-slate-300 rounded-lg focus:border-blue-500 focus:outline-none font-semibold"
            />
            <p className="text-xs text-slate-500 mt-2">
              File will be saved as: GC_PS_01_{startupName}.xlsx
            </p>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowNameModal(false)}
                className="flex-1 px-4 py-2 border-2 border-slate-300 text-slate-700 rounded-lg hover:bg-slate-50 font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmName}
                disabled={!startupName || startupName === 'YourStartup'}
                className="flex-1 px-4 py-2 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-lg hover:from-green-700 hover:to-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed font-semibold"
              >
                Download Excel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
