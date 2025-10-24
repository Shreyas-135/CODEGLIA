import { Vulnerability, ScanReport, UploadedFile } from '../types/vulnerability';

export function parseUploadedFiles(files: UploadedFile[], projectName?: string): ScanReport {
  const vulnerabilities: Vulnerability[] = [];
  const languages = new Set<string>();
  const applications = new Set<string>();

  files.forEach(file => {
    try {
      if (file.name.endsWith('.json')) {
        const parsed = JSON.parse(file.content);
        const appName = extractApplicationName(file.name, parsed);
        applications.add(appName);

        if (Array.isArray(parsed.results)) {
          parsed.results.forEach((result: any) => {
            const vuln = parseBanditResult(result, file.name, appName);
            if (vuln) {
              vulnerabilities.push(vuln);
              languages.add(vuln.language);
            }
          });
        } else if (parsed.vulnerabilities) {
          parsed.vulnerabilities.forEach((vuln: any) => {
            const parsedVuln = parseGenericVulnerability(vuln, file.name, appName);
            if (parsedVuln) {
              vulnerabilities.push(parsedVuln);
              languages.add(parsedVuln.language);
            }
          });
        } else if (parsed.errors || parsed.results?.length === 0) {
          console.log('Empty or error results in file:', file.name);
        }
      }
    } catch (error) {
      console.error(`Error parsing file ${file.name}:`, error);
    }
  });

  const severityCounts = countBySeverity(vulnerabilities);
  const metrics = calculateDetectionMetrics(vulnerabilities);

  return {
    projectName: projectName || Array.from(applications).join(', ') || 'Security Scan Report',
    scanDate: new Date().toISOString(),
    totalFiles: files.length,
    totalVulnerabilities: vulnerabilities.length,
    criticalCount: severityCounts.CRITICAL || 0,
    highCount: severityCounts.HIGH || 0,
    mediumCount: severityCounts.MEDIUM || 0,
    lowCount: severityCounts.LOW || 0,
    infoCount: severityCounts.INFO || 0,
    languages: Array.from(languages),
    vulnerabilities,
    ...metrics
  };
}

function parseBanditResult(result: any, sourceFile: string, appName: string): Vulnerability | null {
  if (!result) return null;

  return {
    id: `${result.filename || sourceFile}-${result.line_number || 0}-${Date.now()}`,
    applicationName: appName,
    fileName: result.filename || sourceFile,
    lineOfCode: result.line_number || 0,
    vulnerabilityType: result.test_id || result.issue_text || 'Unknown',
    severity: mapSeverity(result.issue_severity || result.severity),
    cwe: result.issue_cwe?.id || result.cwe || '',
    cve: result.cve || '',
    description: result.issue_text || result.description || 'No description available',
    explanation: result.explanation || result.more_info || '',
    suggestedFix: result.fix || result.recommendation || '',
    language: detectLanguage(result.filename || sourceFile),
    tool: 'bandit',
    confidenceLevel: result.issue_confidence || result.confidence || ''
  };
}

function parseGenericVulnerability(vuln: any, sourceFile: string, appName: string): Vulnerability | null {
  if (!vuln) return null;

  return {
    id: `${vuln.file || sourceFile}-${vuln.line || 0}-${Date.now()}`,
    applicationName: appName,
    fileName: vuln.file || vuln.fileName || sourceFile,
    lineOfCode: vuln.line || vuln.lineOfCode || 0,
    vulnerabilityType: vuln.type || vuln.vulnerabilityType || 'Unknown',
    severity: mapSeverity(vuln.severity),
    cwe: vuln.cwe || '',
    cve: vuln.cve || '',
    description: vuln.description || vuln.message || 'No description available',
    explanation: vuln.explanation || '',
    suggestedFix: vuln.fix || vuln.suggestedFix || '',
    language: vuln.language || detectLanguage(vuln.file || sourceFile),
    tool: vuln.tool || 'combined',
    confidenceLevel: vuln.confidence || ''
  };
}

function mapSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  const sev = (severity || '').toUpperCase();
  if (sev === 'CRITICAL') return 'CRITICAL';
  if (sev === 'HIGH') return 'HIGH';
  if (sev === 'MEDIUM') return 'MEDIUM';
  if (sev === 'LOW') return 'LOW';
  return 'INFO';
}

function detectLanguage(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();
  const langMap: { [key: string]: string } = {
    'py': 'Python',
    'java': 'Java',
    'js': 'JavaScript',
    'ts': 'TypeScript',
    'c': 'C',
    'cpp': 'C++',
    'cs': 'C#',
    'php': 'PHP',
    'rb': 'Ruby',
    'go': 'Go',
    'rs': 'Rust',
    'kt': 'Kotlin',
    'swift': 'Swift'
  };
  return langMap[ext || ''] || 'Unknown';
}

function extractApplicationName(filename: string, parsed: any): string {
  if (parsed.applicationName) return parsed.applicationName;
  if (parsed.projectName) return parsed.projectName;

  const cleanName = filename
    .replace(/\.(json|txt)$/i, '')
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());

  return cleanName;
}

function calculateDetectionMetrics(vulnerabilities: Vulnerability[]) {
  const truePositives = vulnerabilities.length;
  const falsePositives = 0;
  const falseNegatives = 0;

  const precision = truePositives / (truePositives + falsePositives || 1);
  const recall = truePositives / (truePositives + falseNegatives || 1);
  const f1Score = 2 * (precision * recall) / (precision + recall || 1);
  const detectionAccuracy = (truePositives) / (truePositives + falsePositives + falseNegatives || 1);

  return {
    f1Score: isNaN(f1Score) ? undefined : f1Score,
    precision: isNaN(precision) ? undefined : precision,
    recall: isNaN(recall) ? undefined : recall,
    detectionAccuracy: isNaN(detectionAccuracy) ? undefined : detectionAccuracy
  };
}

function countBySeverity(vulnerabilities: Vulnerability[]) {
  return vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}
