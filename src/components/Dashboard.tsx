import { Shield, AlertTriangle, FileText, Download, Eye, Code2, FileSpreadsheet, Activity } from 'lucide-react';
import { ScanReport } from '../types/vulnerability';
import { generateHTMLReport, downloadReport } from '../utils/generateReport';
import { generateExcelReport, generateCSVReport, downloadCSV } from '../utils/excelExport';
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

  const handleDownloadCSV = () => {
    const csv = generateCSVReport(report);
    downloadCSV(csv, `GC_PS_01_${startupName}.csv`);
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
      CRITICAL: 'bg-red-600',
      HIGH: 'bg-orange-600',
      MEDIUM: 'bg-yellow-600',
      LOW: 'bg-green-600',
      INFO: 'bg-blue-600'
    };
    return colors[severity as keyof typeof colors] || 'bg-slate-600';
  };

  const getSeverityBorderColor = (severity: string) => {
    const colors = {
      CRITICAL: 'border-red-200',
      HIGH: 'border-orange-200',
      MEDIUM: 'border-yellow-200',
      LOW: 'border-green-200',
      INFO: 'border-blue-200'
    };
    return colors[severity as keyof typeof colors] || 'border-slate-200';
  };

  return (
    <div className="w-full max-w-7xl mx-auto space-y-6">
      <div className="bg-white rounded-xl shadow-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <div>
              <h2 className="text-3xl font-bold text-slate-800">Security Scan Report</h2>
              <p className="text-slate-600">
                Generated on {new Date(report.scanDate).toLocaleString()}
              </p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={handleDownloadExcel}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-lg hover:from-green-700 hover:to-emerald-700 transition-all shadow-lg font-semibold"
            >
              <FileSpreadsheet className="w-5 h-5" />
              Stage 1 Excel
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
              HTML
            </button>
            <button
              onClick={onReset}
              className="px-4 py-2 border-2 border-slate-300 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors font-semibold"
            >
              New Scan
            </button>
          </div>
        </div>

        {report.f1Score !== undefined && (
          <div className="bg-gradient-to-br from-blue-50 to-indigo-50 border-2 border-blue-200 p-4 rounded-xl mb-6">
            <div className="flex items-center gap-3 mb-3">
              <Activity className="w-6 h-6 text-blue-600" />
              <h3 className="text-lg font-bold text-slate-800">Detection Metrics</h3>
            </div>
            <div className="grid grid-cols-4 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold text-blue-700">{(report.f1Score * 100).toFixed(2)}%</p>
                <p className="text-sm text-slate-600 font-semibold">F1 Score</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-blue-700">{report.precision ? (report.precision * 100).toFixed(2) : 'N/A'}%</p>
                <p className="text-sm text-slate-600 font-semibold">Precision</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-blue-700">{report.recall ? (report.recall * 100).toFixed(2) : 'N/A'}%</p>
                <p className="text-sm text-slate-600 font-semibold">Recall</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-blue-700">{report.detectionAccuracy ? (report.detectionAccuracy * 100).toFixed(2) : 'N/A'}%</p>
                <p className="text-sm text-slate-600 font-semibold">Accuracy</p>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-gradient-to-br from-slate-50 to-slate-100 p-6 rounded-xl border border-slate-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-600 text-sm font-semibold uppercase tracking-wide">
                  Total Vulnerabilities
                </p>
                <p className="text-4xl font-bold text-slate-800 mt-2">
                  {report.totalVulnerabilities}
                </p>
              </div>
              <AlertTriangle className="w-12 h-12 text-slate-400" />
            </div>
          </div>

          <div className="bg-gradient-to-br from-slate-50 to-slate-100 p-6 rounded-xl border border-slate-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-600 text-sm font-semibold uppercase tracking-wide">
                  Files Scanned
                </p>
                <p className="text-4xl font-bold text-slate-800 mt-2">
                  {report.totalFiles}
                </p>
              </div>
              <FileText className="w-12 h-12 text-slate-400" />
            </div>
          </div>

          <div className="bg-gradient-to-br from-slate-50 to-slate-100 p-6 rounded-xl border border-slate-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-600 text-sm font-semibold uppercase tracking-wide">
                  Languages
                </p>
                <p className="text-4xl font-bold text-slate-800 mt-2">
                  {report.languages.length}
                </p>
              </div>
              <Code2 className="w-12 h-12 text-slate-400" />
            </div>
          </div>

          <div className="bg-gradient-to-br from-red-50 to-orange-50 p-6 rounded-xl border border-red-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-red-600 text-sm font-semibold uppercase tracking-wide">
                  Critical & High
                </p>
                <p className="text-4xl font-bold text-red-700 mt-2">
                  {report.criticalCount + report.highCount}
                </p>
              </div>
              <AlertTriangle className="w-12 h-12 text-red-400" />
            </div>
          </div>
        </div>

        <div className="grid grid-cols-5 gap-3">
          <div className="bg-red-50 border border-red-200 p-4 rounded-xl text-center">
            <p className="text-3xl font-bold text-red-700">{report.criticalCount}</p>
            <p className="text-red-600 font-semibold text-sm uppercase mt-1">Critical</p>
          </div>
          <div className="bg-orange-50 border border-orange-200 p-4 rounded-xl text-center">
            <p className="text-3xl font-bold text-orange-700">{report.highCount}</p>
            <p className="text-orange-600 font-semibold text-sm uppercase mt-1">High</p>
          </div>
          <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-xl text-center">
            <p className="text-3xl font-bold text-yellow-700">{report.mediumCount}</p>
            <p className="text-yellow-600 font-semibold text-sm uppercase mt-1">Medium</p>
          </div>
          <div className="bg-green-50 border border-green-200 p-4 rounded-xl text-center">
            <p className="text-3xl font-bold text-green-700">{report.lowCount}</p>
            <p className="text-green-600 font-semibold text-sm uppercase mt-1">Low</p>
          </div>
          <div className="bg-blue-50 border border-blue-200 p-4 rounded-xl text-center">
            <p className="text-3xl font-bold text-blue-700">{report.infoCount}</p>
            <p className="text-blue-600 font-semibold text-sm uppercase mt-1">Info</p>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-2xl font-bold text-slate-800">Vulnerabilities</h3>
          <div className="flex gap-2">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(severity => (
              <button
                key={severity}
                onClick={() => setFilterSeverity(severity)}
                className={`px-4 py-2 rounded-lg font-semibold text-sm transition-all ${
                  filterSeverity === severity
                    ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg'
                    : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                }`}
              >
                {severity}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-4 max-h-[600px] overflow-y-auto">
          {filteredVulns.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <Shield className="w-16 h-16 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-semibold">No vulnerabilities found for this filter</p>
            </div>
          ) : (
            filteredVulns.map((vuln, index) => (
              <div
                key={vuln.id || index}
                className={`border-l-4 ${getSeverityBorderColor(vuln.severity)} bg-slate-50 p-4 rounded-lg`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={`${getSeverityColor(vuln.severity)} text-white px-3 py-1 rounded-full text-xs font-bold uppercase`}
                    >
                      {vuln.severity}
                    </span>
                    <span className="text-slate-700 font-semibold">
                      {vuln.fileName}:{vuln.lineOfCode}
                    </span>
                  </div>
                  <div className="flex gap-2 text-xs">
                    {vuln.cwe && (
                      <span className="bg-slate-200 text-slate-700 px-2 py-1 rounded font-semibold">
                        CWE: {vuln.cwe}
                      </span>
                    )}
                    {vuln.cve && (
                      <span className="bg-slate-200 text-slate-700 px-2 py-1 rounded font-semibold">
                        CVE: {vuln.cve}
                      </span>
                    )}
                  </div>
                </div>

                <h4 className="font-bold text-slate-800 mb-2">{vuln.vulnerabilityType}</h4>
                <p className="text-slate-600 mb-3">{vuln.description}</p>

                {vuln.explanation && (
                  <div className="bg-blue-50 border border-blue-200 p-3 rounded-lg mb-3">
                    <p className="text-sm text-slate-700">
                      <strong className="text-blue-800">Explanation:</strong> {vuln.explanation}
                    </p>
                  </div>
                )}

                {vuln.suggestedFix && (
                  <div className="bg-green-50 border border-green-200 p-3 rounded-lg mb-3">
                    <p className="text-sm text-slate-700">
                      <strong className="text-green-800">Suggested Fix:</strong> {vuln.suggestedFix}
                    </p>
                  </div>
                )}

                <div className="flex gap-4 text-xs text-slate-500 mt-3">
                  <span>Language: <strong>{vuln.language}</strong></span>
                  <span>Tool: <strong>{vuln.tool}</strong></span>
                  {vuln.confidenceLevel && (
                    <span>Confidence: <strong>{vuln.confidenceLevel}</strong></span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

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
