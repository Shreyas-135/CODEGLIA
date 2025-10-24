import { Upload, FileJson, AlertCircle } from 'lucide-react';
import JSZip from 'jszip';
import { useState, useRef } from 'react';
import { UploadedFile, ScanReport } from '../types/vulnerability';

interface FileUploadProps {
  onFilesUploaded: (files: UploadedFile[]) => void;
  onReportGenerated?: (report: ScanReport) => void;
}

// Get backend URL from environment or use relative path
const getBackendUrl = () => {
  // Check for Vite environment variable
  const viteUrl = import.meta.env.VITE_BACKEND_URL || import.meta.env.VITE_BASEAPP_URL;
  if (viteUrl) {
    return viteUrl.replace(/\/$/, ''); // Remove trailing slash
  }
  
  // Use relative path if no environment variable
  return '';
};

export function FileUpload({ onFilesUploaded, onReportGenerated }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [groundTruthFile, setGroundTruthFile] = useState<File | null>(null);
  const [enableAI, setEnableAI] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dirInputRef = useRef<HTMLInputElement>(null);

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
        // Detect optional ground truth by filename
        if (isGroundTruth(f.name)) {
          setGroundTruthFile(f);
        } else {
          await processFile(f, files);
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

  const isGroundTruth = (name: string) => {
    const lower = name.toLowerCase();
    return lower.includes('ground') || lower.includes('truth') || lower.includes('labels');
  };

  const uploadArchiveToBackend = async (file: File): Promise<ScanReport> => {
    setIsUploading(true);
    const form = new FormData();
    form.append('file', file);
    if (groundTruthFile) {
      form.append('ground_truth', groundTruthFile);
    }
    if (enableAI) {
      form.append('ai', '1');
    }
    
    const backendUrl = getBackendUrl();
    const apiUrl = `${backendUrl}/api/scan`;
    
    console.log('Uploading to:', apiUrl);
    
    try {
      const res = await fetch(apiUrl, {
        method: 'POST',
        body: form,
        // Add headers for CORS if needed
        headers: {
          'Accept': 'application/json',
        },
      });
      
      if (!res.ok) {
        let errorMsg = `Server error: ${res.status} ${res.statusText}`;
        try {
          const errorData = await res.json();
          errorMsg = errorData.error || errorMsg;
        } catch {
          const text = await res.text();
          errorMsg = text || errorMsg;
        }
        throw new Error(errorMsg);
      }
      
      const data = await res.json();
      return data as ScanReport;
    } catch (err: any) {
      console.error('Upload error:', err);
      if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
        throw new Error(`Cannot connect to backend server at ${apiUrl}. Please ensure the backend is running.`);
      }
      throw err;
    } finally {
      setIsUploading(false);
    }
  };

  const zipDirectory = async (fileList: FileList): Promise<File> => {
    const zip = new JSZip();
    const root = zip.folder('src')!;
    for (let i = 0; i < fileList.length; i++) {
      const f = fileList[i] as any as File & { webkitRelativePath?: string };
      const p = (f.webkitRelativePath || f.name).replace(/^[\/]+/, '');
      const arr = new Uint8Array(await f.arrayBuffer());
      root.file(p, arr);
    }
    const content = await zip.generateAsync({ type: 'uint8array' });
    return new File([content], 'source.zip', { type: 'application/zip' });
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      <div
        className={`border-4 border-dashed rounded-xl p-12 text-center transition-all ${
          isDragging
            ? 'border-blue-500 bg-blue-50'
            : 'border-slate-300 bg-white hover:border-slate-400'
        } ${isUploading ? 'opacity-60 pointer-events-none' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".json,.csv,.zip,.tar,.tgz,.tar.gz"
          onChange={handleFileInput}
          className="hidden"
          disabled={isUploading}
        />
        <input
          ref={dirInputRef}
          type="file"
          // @ts-expect-error - webkitdirectory is non-standard but widely supported
          webkitdirectory="true"
          directory="true"
          onChange={async (e) => {
            const items = e.target.files;
            if (!items) return;
            try {
              const archive = await zipDirectory(items);
              const report = await uploadArchiveToBackend(archive);
              onReportGenerated && onReportGenerated(report);
            } catch (err: any) {
              setError(err?.message || 'Failed to compress and upload folder.');
            }
          }}
          className="hidden"
          disabled={isUploading}
        />

        <div className="flex flex-col items-center gap-4">
          <div className="p-4 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full">
            {isUploading ? (
              <div className="w-12 h-12 border-4 border-white border-t-transparent rounded-full animate-spin"></div>
            ) : (
              <Upload className="w-12 h-12 text-white" />
            )}
          </div>

          <div>
            <h3 className="text-2xl font-bold text-slate-800 mb-2">
              {isUploading ? 'Processing...' : 'Upload Vulnerability Scan Results or Source Archive'}
            </h3>
            <p className="text-slate-600 mb-4">
              Drag and drop JSON outputs (Bandit/Semgrep), optional Ground Truth (.json/.csv), or a .zip/.tar.gz of the source code. You can also upload a folder.
            </p>
            {!isUploading && (
              <>
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg font-semibold hover:from-blue-700 hover:to-purple-700 transition-all shadow-lg hover:shadow-xl"
                >
                  Select Files
                </button>
                <button
                  onClick={() => dirInputRef.current?.click()}
                  className="ml-3 px-6 py-3 border-2 border-slate-300 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors font-semibold"
                >
                  Upload Folder
                </button>
              </>
            )}
          </div>

          <div className="flex items-center gap-3 text-sm text-slate-500">
            <FileJson className="w-5 h-5" />
            <span>Supports JSON (Bandit/Semgrep), Ground Truth (.json/.csv), archives or folders for backend scanning</span>
          </div>

          <div className="mt-4 flex items-center justify-center gap-6 text-sm">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input 
                type="checkbox" 
                checked={enableAI} 
                onChange={(e) => setEnableAI(e.target.checked)}
                disabled={isUploading}
              />
              <span className="text-slate-700 font-semibold">Enrich with Gemini (if configured)</span>
            </label>
            {groundTruthFile && (
              <span className="text-green-700 bg-green-50 border border-green-200 px-2 py-1 rounded">
                Ground Truth: {groundTruthFile.name}
              </span>
            )}
          </div>
        </div>
      </div>

      {error && (
        <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-red-800 font-semibold">Upload Error</p>
            <p className="text-red-600 text-sm">{error}</p>
            <p className="text-red-500 text-xs mt-2">
              Backend URL: {getBackendUrl() || '(relative path)'}/api/scan
            </p>
          </div>
        </div>
      )}
      
      {isUploading && (
        <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <p className="text-blue-800 font-semibold text-center">
            Processing your upload... This may take a few minutes for large codebases.
          </p>
        </div>
      )}
    </div>
  );
}
