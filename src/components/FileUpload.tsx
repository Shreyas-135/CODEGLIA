import { Upload, FileJson, AlertCircle } from 'lucide-react';
import { useState, useRef } from 'react';
import { UploadedFile, ScanReport } from '../types/vulnerability';

interface FileUploadProps {
  onFilesUploaded: (files: UploadedFile[]) => void;
  onReportGenerated?: (report: ScanReport) => void;
}

export function FileUpload({ onFilesUploaded, onReportGenerated }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    setError(null);

    const items = Array.from(e.dataTransfer.items);
    const files: UploadedFile[] = [];
    const archives: File[] = [];

    for (const item of items) {
      if (item.kind === 'file') {
        const file = item.getAsFile();
        if (file) {
          if (isArchive(file.name)) {
            archives.push(file);
          } else {
            await processFile(file, files);
          }
        }
      }
    }

    if (archives.length > 0 && onReportGenerated) {
      try {
        const report = await uploadArchiveToBackend(archives[0]);
        onReportGenerated(report);
        return;
      } catch (err: any) {
        setError(err?.message || 'Failed to process archive with backend.');
        return;
      }
    }

    if (files.length > 0) {
      onFilesUploaded(files);
    } else {
      setError('No valid JSON files found. Please upload vulnerability scan results.');
    }
  };

  const handleFileInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    const fileList = e.target.files;
    if (!fileList) return;

    const files: UploadedFile[] = [];
    const archives: File[] = [];
    for (let i = 0; i < fileList.length; i++) {
      const f = fileList[i];
      if (isArchive(f.name)) {
        archives.push(f);
      } else {
        await processFile(f, files);
      }
    }

    if (archives.length > 0 && onReportGenerated) {
      try {
        const report = await uploadArchiveToBackend(archives[0]);
        onReportGenerated(report);
        return;
      } catch (err: any) {
        setError(err?.message || 'Failed to process archive with backend.');
        return;
      }
    }

    if (files.length > 0) {
      onFilesUploaded(files);
    } else {
      setError('No valid JSON files found. Please upload vulnerability scan results.');
    }
  };

  const processFile = async (file: File, files: UploadedFile[]) => {
    if (file.name.endsWith('.json')) {
      try {
        const content = await file.text();
        files.push({
          name: file.name,
          content,
          type: file.type
        });
      } catch (err) {
        console.error('Error reading file:', file.name, err);
      }
    }
  };

  const isArchive = (name: string) => {
    const lower = name.toLowerCase();
    return (
      lower.endsWith('.zip') ||
      lower.endsWith('.tar') ||
      lower.endsWith('.tgz') ||
      lower.endsWith('.tar.gz')
    );
  };

  const uploadArchiveToBackend = async (file: File): Promise<ScanReport> => {
    const form = new FormData();
    form.append('file', file);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        body: form
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || 'Backend error');
      }
      const data = await res.json();
      return data as ScanReport;
    } catch (err) {
      throw err as Error;
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      <div
        className={`border-4 border-dashed rounded-xl p-12 text-center transition-all ${
          isDragging
            ? 'border-blue-500 bg-blue-50'
            : 'border-slate-300 bg-white hover:border-slate-400'
        }`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".json,.zip,.tar,.tgz,.tar.gz"
          onChange={handleFileInput}
          className="hidden"
        />

        <div className="flex flex-col items-center gap-4">
          <div className="p-4 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full">
            <Upload className="w-12 h-12 text-white" />
          </div>

          <div>
            <h3 className="text-2xl font-bold text-slate-800 mb-2">
              Upload Vulnerability Scan Results or Source Archive
            </h3>
            <p className="text-slate-600 mb-4">
              Drag and drop JSON outputs (Bandit/Semgrep) or a .zip/.tar.gz of the source code
            </p>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg font-semibold hover:from-blue-700 hover:to-purple-700 transition-all shadow-lg hover:shadow-xl"
            >
              Select Files
            </button>
          </div>

          <div className="flex items-center gap-3 text-sm text-slate-500">
            <FileJson className="w-5 h-5" />
            <span>Supports JSON (Bandit/Semgrep) and archives for Flask backend scanning</span>
          </div>
        </div>
      </div>

      {error && (
        <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-red-800 font-semibold">Upload Error</p>
            <p className="text-red-600 text-sm">{error}</p>
          </div>
        </div>
      )}
    </div>
  );
}
