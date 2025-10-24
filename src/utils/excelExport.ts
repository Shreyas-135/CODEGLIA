import * as XLSX from 'xlsx';
import { ScanReport, ExcelRow } from '../types/vulnerability';

export function generateExcelReport(report: ScanReport, startupName: string): void {
  const excelData: ExcelRow[] = report.vulnerabilities.map((vuln, index) => ({
    Ser: index + 1,
    'Name of Application Tested': vuln.applicationName,
    Language: vuln.language,
    'Vulnerability Found': vuln.vulnerabilityType,
    CVE: vuln.cve || vuln.cwe || 'N/A',
    'File Name': vuln.fileName,
    'Line of Code': vuln.lineOfCode,
    'Detection Accuracy': report.f1Score != null
      ? `${(report.f1Score * 100).toFixed(2)}%`
      : (report.detectionAccuracy != null ? `${(report.detectionAccuracy * 100).toFixed(2)}%` : 'N/A')
  }));

  const worksheet = XLSX.utils.json_to_sheet(excelData);

  const columnWidths = [
    { wch: 5 },
    { wch: 30 },
    { wch: 15 },
    { wch: 40 },
    { wch: 20 },
    { wch: 40 },
    { wch: 12 },
    { wch: 18 }
  ];
  worksheet['!cols'] = columnWidths;

  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, 'Vulnerabilities');

  const summaryData = [
    ['Summary Statistics', ''],
    ['Total Vulnerabilities', report.totalVulnerabilities],
    ['Total Files Scanned', report.totalFiles],
    ['Languages Detected', report.languages.join(', ')],
    ['Critical Severity', report.criticalCount],
    ['High Severity', report.highCount],
    ['Medium Severity', report.mediumCount],
    ['Low Severity', report.lowCount],
    ['Info Severity', report.infoCount],
    ['', ''],
    ['Detection Metrics', ''],
    ['F1 Score', report.f1Score ? report.f1Score.toFixed(4) : 'N/A'],
    ['Precision', report.precision ? report.precision.toFixed(4) : 'N/A'],
    ['Recall', report.recall ? report.recall.toFixed(4) : 'N/A'],
    ['Detection Accuracy', report.detectionAccuracy ? `${(report.detectionAccuracy * 100).toFixed(2)}%` : 'N/A']
  ];

  const summaryWorksheet = XLSX.utils.aoa_to_sheet(summaryData);
  summaryWorksheet['!cols'] = [{ wch: 25 }, { wch: 30 }];
  XLSX.utils.book_append_sheet(workbook, summaryWorksheet, 'Summary');

  const filename = `GC_PS_01_${startupName}.xlsx`;

  XLSX.writeFile(workbook, filename);
}

export function generateCSVReport(report: ScanReport): string {
  const headers = ['Ser', 'Name of Application Tested', 'Language', 'Vulnerability Found', 'CVE', 'File Name', 'Line of Code', 'Detection Accuracy'];

  const rows = report.vulnerabilities.map((vuln, index) => [
    index + 1,
    vuln.applicationName,
    vuln.language,
    vuln.vulnerabilityType,
    vuln.cve || vuln.cwe || 'N/A',
    vuln.fileName,
    vuln.lineOfCode,
    report.f1Score != null
      ? `${(report.f1Score * 100).toFixed(2)}%`
      : (report.detectionAccuracy != null ? `${(report.detectionAccuracy * 100).toFixed(2)}%` : 'N/A')
  ]);

  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
  ].join('\n');

  return csvContent;
}

export function downloadCSV(csvContent: string, filename: string = 'vulnerability-report.csv') {
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
