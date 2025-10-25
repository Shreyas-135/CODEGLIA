import { Upload, FileJson, AlertCircle, Loader2, Sparkles, Info } from 'lucide-react';
import JSZip from 'jszip';
import { useState, useRef } from 'react';
import { UploadedFile, ScanReport } from '../types/vulnerability';

interface FileUploadProps {
  onFilesUploaded: (files: UploadedFile[]) => void;
  onReportGenerated?: (report: ScanReport) => void;
}

const getBackendUrl = () => {
  const viteUrl = import.meta.env.VITE_BACKEND_URL || import.meta.env.VITE_BASEAPP_URL;
  if (viteUrl) {
    return viteUrl.replace(/\/$/, '');
  }
  return 'https://codeglia.onrender.com';
};

interface ProgressState {
  status: string;
  message: string;
  progress: number;
}

export function FileUpload({ onFilesUploaded, onReportGenerated }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [progressState, setProgressState] = useState<ProgressState | null>(null);
  const [groundTruthFile, setGroundTruthFile] = useState<File | null>(null);
  const [enableAI, setEnableAI] = useState<boolean>(true); // Default to enabled
  const [showAIInfo, setShowAIInfo] = useState<boolean>(false);
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
        await uploadArchiveToBackendStreaming(archives[0]);
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
        if (isGroundTruth(f.name)) {
          setGroundTruthFile(f);
        } else {
          await processFile(f, files);
        }
      }
    }

    if (archives.length > 0 && onReportGenerated) {
      try {
        await uploadArchiveToBackendStreaming(archives[0]);
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

  const uploadArchiveToBackendStreaming = async (file: File): Promise<void> => {
    setIsUploading(true);
    setProgressState({ status: 'uploading', message: 'Uploading file...', progress: 0 });
    
    const form = new FormData();
    form.append('file', file);
    if (groundTruthFile) {
      form.append('ground_truth', groundTruthFile);
    }
    if (enableAI) {
      form.append('ai', '1');
    }
    form.append('streaming', '1');
    
    const backendUrl = getBackendUrl();
    const apiUrl = `${backendUrl}/api/scan`;
    
    console.log('Streaming upload to:', apiUrl);
    console.log('File size:', file.size, 'bytes');
    console.log('AI Enrichment:', enableAI ? 'Enabled' : 'Disabled');
    
    try {
      const res = await fetch(apiUrl, {
        method: 'POST',
        body: form,
        mode: 'cors',
        credentials: 'omit',
        headers: {
          'Accept': 'text/event-stream',
        },
      });
      
      if (!res.ok) {
        const text = await res.text();
        let errorMsg = `Server error: ${res.status} ${res.statusText}`;
        try {
          const errorData = JSON.parse(text);
          errorMsg = errorData.error || errorMsg;
        } catch {}
        throw new Error(errorMsg);
      }

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      
      if (!reader) {
        throw new Error('No response stream available');
      }

      let buffer = '';
      
      while (true) {
        const { done, value } = await reader.read();
        
        if (done) {
          console.log('Stream complete');
          break;
        }
        
        buffer += decoder.decode(value, { stream: true });
        
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            try {
              const parsed = JSON.parse(data);
              
              if (parsed.error) {
                throw new Error(parsed.error);
              }
              
              if (parsed.status === 'complete' && parsed.result) {
                console.log('Scan completed successfully');
                setProgressState({ status: 'complete', message: 'Scan complete!', progress: 100 });
                setTimeout(() => {
                  if (onReportGenerated) {
                    onReportGenerated(parsed.result as ScanReport);
                  }
                  setIsUploading(false);
                  setProgressState(null);
                }, 500);
              } else if (parsed.status) {
                setProgressState({
                  status: parsed.status,
                  message: parsed.message || 'Processing...',
                  progress: parsed.progress || 0
                });
              }
            } catch (parseErr) {
              console.error('Failed to parse SSE message:', data, parseErr);
            }
          }
        }
      }
      
    } catch (err: any) {
      console.error('Upload error:', err);
      setIsUploading(false);
      setProgressState(null);
      
      if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
        throw new Error(
          `Cannot connect to backend server at ${apiUrl}.\n\n` +
          `Possible issues:\n` +
          `1. Backend server is not running or not accessible\n` +
          `2. CORS is blocking the request\n` +
          `3. Network/firewall issues\n\n` +
          `Please check:\n` +
          `- Backend is deployed and running at ${backendUrl}\n` +
          `- Backend health endpoint: ${backendUrl}/health`
        );
      }
      
      throw err;
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

  const testBackendConnection = async () => {
    const backendUrl = getBackendUrl();
    setError(null);
    setIsUploading(true);
    
    try {
      const healthUrl = `${backendUrl}/health`;
      console.log('Testing connection to:', healthUrl);
      
      const res = await fetch(healthUrl, {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
      });
      
      if (res.ok) {
        const data = await res.json();
        alert(`✅ Backend is reachable!\n\nStatus: ${data.status}\nTime: ${data.time}`);
      } else {
        alert(`⚠️ Backend responded with error: ${res.status} ${res.statusText}`);
      }
    } catch (err: any) {
      console.error('Connection test failed:', err);
      alert(
        `❌ Cannot connect to backend\n\n` +
        `URL: ${backendUrl}/health\n` +
        `Error: ${err.message}\n\n` +
        `Please ensure the backend is running.`
      );
    } finally {
      setIsUploading(false);
    }
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
              setProgressState({ status: 'zipping', message: 'Compressing folder...', progress: 5 });
              const archive = await zipDirectory(items);
              await uploadArchiveToBackendStreaming(archive);
            } catch (err: any) {
              setError(err?.message || 'Failed to compress and upload folder.');
              setProgressState(null);
            }
          }}
          className="hidden"
          disabled={isUploading}
        />

        <div className="flex flex-col items-center gap-4">
          <div className="p-4 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full">
            {isUploading ? (
              <Loader2 className="w-12 h-12 text-white animate-spin" />
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
                <button
                  onClick={testBackendConnection}
                  className="ml-3 px-6 py-3 border-2 border-green-300 text-green-700 rounded-lg hover:bg-green-50 transition-colors font-semibold"
                >
                  Test Connection
                </button>
              </>
            )}
          </div>

          <div className="flex items-center gap-3 text-sm text-slate-500">
            <FileJson className="w-5 h-5" />
            <span>Supports JSON (Bandit/Semgrep), Ground Truth (.json/.csv), archives or folders for backend scanning</span>
          </div>

          <div className="mt-4 w-full max-w-md space-y-3">
            {/* AI Enrichment Toggle */}
            <div className="bg-gradient-to-r from-purple-50 to-pink-50 border-2 border-purple-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-3 cursor-pointer select-none flex-1">
                  <div className="relative">
                    <input 
                      type="checkbox" 
                      checked={enableAI} 
                      onChange={(e) => setEnableAI(e.target.checked)}
                      disabled={isUploading}
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-slate-300 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-gradient-to-r peer-checked:from-purple-600 peer-checked:to-pink-600"></div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Sparkles className={`w-5 h-5 ${enableAI ? 'text-purple-600' : 'text-slate-400'}`} />
                    <span className={`font-bold ${enableAI ? 'text-purple-900' : 'text-slate-600'}`}>
                      AI-Powered Enrichment (Gemini)
                    </span>
                  </div>
                </label>
                <button
                  onClick={() => setShowAIInfo(!showAIInfo)}
                  className="p-1 hover:bg-purple-100 rounded transition-colors"
                >
                  <Info className="w-5 h-5 text-purple-600" />
                </button>
              </div>
              
              {showAIInfo && (
                <div className="mt-3 pt-3 border-t border-purple-200 text-sm text-slate-700 space-y-2">
                  <p className="flex items-start gap-2">
                    <span className="text-purple-600 font-bold">•</span>
                    <span><strong>Personalized Explanations:</strong> Get detailed explanations of why each vulnerability is dangerous</span>
                  </p>
                  <p className="flex items-start gap-2">
                    <span className="text-purple-600 font-bold">•</span>
                    <span><strong>Code-Specific Fixes:</strong> Receive exact line numbers and code changes to fix issues</span>
                  </p>
                  <p className="flex items-start gap-2">
                    <span className="text-purple-600 font-bold">•</span>
                    <span><strong>Context-Aware:</strong> AI analyzes your actual code for targeted recommendations</span>
                  </p>
                  <p className="text-xs text-slate-500 mt-2 italic">
                    Note: Enriches up to 50 vulnerabilities per scan. Requires GEMINI_API_KEY on backend.
                  </p>
                </div>
              )}
            </div>

            {/* Ground Truth File Display */}
            {groundTruthFile && (
              <div className="bg-green-50 border-2 border-green-200 rounded-lg p-3 flex items-center gap-2">
                <FileJson className="w-5 h-5 text-green-700" />
                <span className="text-green-800 font-semibold text-sm flex-1">
                  Ground Truth: {groundTruthFile.name}
                </span>
                <button
                  onClick={() => setGroundTruthFile(null)}
                  className="text-green-700 hover:text-green-900 text-sm font-bold"
                >
                  ✕
                </button>
              </div>
            )}
          </div>
          
          <div className="mt-2 text-xs text-slate-500">
            Backend: {getBackendUrl()}
          </div>
        </div>
      </div>

      {/* Real-time Progress Bar */}
      {isUploading && progressState && (
        <div className="mt-4 p-6 bg-gradient-to-br from-blue-50 to-indigo-50 border-2 border-blue-200 rounded-xl">
          <div className="mb-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-blue-900">
                {progressState.message}
              </span>
              <span className="text-sm font-bold text-blue-900">
                {progressState.progress}%
              </span>
            </div>
            <div className="w-full bg-blue-100 rounded-full h-3 overflow-hidden">
              <div 
                className="bg-gradient-to-r from-blue-600 to-purple-600 h-full rounded-full transition-all duration-500 ease-out"
                style={{ width: `${progressState.progress}%` }}
              />
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-blue-700">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Status: <strong>{progressState.status}</strong></span>
            {enableAI && progressState.status === 'ai' && (
              <span className="ml-2 flex items-center gap-1 text-purple-700">
                <Sparkles className="w-3 h-3" />
                <strong>AI enriching vulnerabilities...</strong>
              </span>
            )}
          </div>
        </div>
      )}

      {error && (
        <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="text-red-800 font-semibold">Upload Error</p>
            <pre className="text-red-600 text-sm whitespace-pre-wrap mt-2 font-mono">{error}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
