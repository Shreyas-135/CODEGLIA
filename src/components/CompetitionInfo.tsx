import { CheckCircle, Target, Award, FileText } from 'lucide-react';

export function CompetitionInfo() {
  return (
    <div className="bg-white rounded-xl shadow-lg p-6 mb-6">
      <div className="flex items-center gap-3 mb-6">
        <Award className="w-8 h-8 text-yellow-600" />
        <h2 className="text-2xl font-bold text-slate-800">
          AI Grand Challenge - Stage 1 Submission
        </h2>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0 mt-1" />
            <div>
              <h3 className="font-bold text-slate-800 mb-1">Languages Supported</h3>
              <p className="text-sm text-slate-600">
                Java, Python, C/C++, C#, PHP (Stage 1 Requirements)
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0 mt-1" />
            <div>
              <h3 className="font-bold text-slate-800 mb-1">Vulnerability Detection</h3>
              <p className="text-sm text-slate-600">
                OWASP Top 10, CWE-Top 25, Memory Safety, Injection, Misconfiguration
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0 mt-1" />
            <div>
              <h3 className="font-bold text-slate-800 mb-1">CVE/CWE Mapping</h3>
              <p className="text-sm text-slate-600">
                Automatic mapping to known vulnerability databases
              </p>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-start gap-3">
            <Target className="w-5 h-5 text-blue-600 flex-shrink-0 mt-1" />
            <div>
              <h3 className="font-bold text-slate-800 mb-1">Detection Accuracy</h3>
              <p className="text-sm text-slate-600">
                F1 Score calculation for evaluation metrics
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <FileText className="w-5 h-5 text-purple-600 flex-shrink-0 mt-1" />
            <div>
              <h3 className="font-bold text-slate-800 mb-1">Submission Format</h3>
              <p className="text-sm text-slate-600">
                Excel format: GC_PS_01_Startup_name.xlsx with all required fields
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0 mt-1" />
            <div>
              <h3 className="font-bold text-slate-800 mb-1">AI-Powered Analysis</h3>
              <p className="text-sm text-slate-600">
                Gemini API integration for explanations and fix suggestions
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <p className="text-sm text-slate-700">
          <strong className="text-blue-800">Stage 1 Evaluation Criteria:</strong>
          <br />
          Languages Supported (30%) | Vulnerabilities Detected with CVE/CWE (40%) | Detection Accuracy/F1 Score (30%)
        </p>
      </div>
    </div>
  );
}
