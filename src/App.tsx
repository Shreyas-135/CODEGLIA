import { useState } from 'react';
import { FileUpload } from './components/FileUpload';
import { Dashboard } from './components/Dashboard';
import { CompetitionInfo } from './components/CompetitionInfo';
import { parseUploadedFiles } from './utils/parseVulnerabilities';
import { ScanReport, UploadedFile } from './types/vulnerability';
import { Shield } from 'lucide-react';

function App() {
  const [report, setReport] = useState<ScanReport | null>(null);

  const handleFilesUploaded = (files: UploadedFile[]) => {
    const scanReport = parseUploadedFiles(files);
    setReport(scanReport);
  };

  const handleReset = () => {
    setReport(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-purple-900">
      <div className="container mx-auto px-4 py-8">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="p-3 bg-white rounded-xl shadow-lg">
              <Shield className="w-10 h-10 text-blue-600" />
            </div>
            <h1 className="text-5xl font-bold text-white">
              Vulnerability Detection Tool
            </h1>
          </div>
          <p className="text-xl text-slate-200">
            AI-Powered Security Analysis with Bandit & Semgrep
          </p>
        </div>

        {!report ? (
          <>
            <CompetitionInfo />
            <FileUpload onFilesUploaded={handleFilesUploaded} />
          </>
        ) : (
          <Dashboard report={report} onReset={handleReset} />
        )}
      </div>
    </div>
  );
}

export default App;
