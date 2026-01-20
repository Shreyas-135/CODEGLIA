#!/usr/bin/env python3
"""
llm_scanner.py - LLM-based vulnerability scanner module.
Supports multiple backends: Google Gemini, OpenAI GPT-4, and Ollama (local models).
"""

import os
import json
import hashlib
import time
import re
from typing import List, Dict, Optional, Tuple


class LLMScanner:
    """
    LLM-based vulnerability scanner that can use multiple backends.
    """
    
    SUPPORTED_EXTENSIONS = ['.py', '.js', '.java', '.php', '.c', '.cpp', '.h', '.hpp', 
                           '.cs', '.rb', '.pl', '.go', '.rs', '.ts', '.jsx', '.tsx']
    
    SECURITY_PROMPT_TEMPLATE = """Analyze the following code for security vulnerabilities.

File: {filename}
Code:
```{language}
{code}
```

Identify security issues including:
- SQL injection (CWE-89)
- Command injection (CWE-78)
- Cross-site scripting (XSS, CWE-79)
- Path traversal (CWE-22)
- Insecure deserialization (CWE-502)
- Hardcoded secrets (CWE-798)
- Weak cryptography (CWE-327)
- Authentication issues (CWE-287)
- Authorization issues (CWE-284)
- Information disclosure (CWE-200)

For each vulnerability found, return JSON array with objects containing:
- line: line number (integer, estimate if exact line unknown)
- severity: "high", "medium", or "low"
- issue_text: brief description of the vulnerability
- cwe: CWE identifier (e.g., "CWE-89")
- explanation: detailed explanation of the vulnerability
- fix: code snippet showing how to fix the vulnerability

Return ONLY valid JSON array. If no vulnerabilities found, return empty array [].
Example: [{{"line": 10, "severity": "high", "issue_text": "SQL Injection", "cwe": "CWE-89", "explanation": "...", "fix": "..."}}]
"""
    
    def __init__(self, backend: str = "gemini", model: Optional[str] = None, cache_enabled: bool = True):
        """
        Initialize LLM Scanner.
        
        Args:
            backend: Backend to use ('gemini', 'openai', or 'ollama')
            model: Model name (optional, uses defaults if not specified)
            cache_enabled: Enable caching of scan results
        """
        self.backend = backend.lower()
        self.model = model
        self.cache_enabled = cache_enabled
        self.cache_file = ".llm_scan_cache.json"
        self.cache = self._load_cache() if cache_enabled else {}
        
        # Set default models
        if not self.model:
            if self.backend == "gemini":
                self.model = "gemini-2.0-flash-exp"
            elif self.backend == "openai":
                self.model = "gpt-4"
            elif self.backend == "ollama":
                self.model = "codellama"
        
        # Initialize backend
        self._init_backend()
    
    def _init_backend(self):
        """Initialize the selected backend."""
        # Don't actually initialize until we need to scan
        # This allows the module to be imported without dependencies
        self.client = None
        self._backend_initialized = False
    
    def _ensure_backend_initialized(self):
        """Lazy initialization of backend when needed."""
        if self._backend_initialized:
            return
        
        if self.backend == "gemini":
            import google.generativeai as genai
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                raise ValueError("GEMINI_API_KEY environment variable not set")
            genai.configure(api_key=api_key)
            self.client = genai.GenerativeModel(self.model)
        
        elif self.backend == "openai":
            try:
                import openai
                api_key = os.getenv("OPENAI_API_KEY")
                if not api_key:
                    raise ValueError("OPENAI_API_KEY environment variable not set")
                openai.api_key = api_key
                self.client = openai
            except ImportError:
                raise ImportError("openai package not installed. Install with: pip install openai>=1.12.0")
        
        elif self.backend == "ollama":
            try:
                import ollama
                self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
                self.client = ollama
            except ImportError:
                raise ImportError("ollama package not installed. Install with: pip install ollama>=0.1.0")
        
        else:
            raise ValueError(f"Unsupported backend: {self.backend}. Choose 'gemini', 'openai', or 'ollama'")
        
        self._backend_initialized = True
    
    def _load_cache(self) -> dict:
        """Load cache from file."""
        if not os.path.exists(self.cache_file):
            return {}
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _save_cache(self):
        """Save cache to file."""
        if not self.cache_enabled:
            return
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"⚠️ Warning: Could not save LLM cache: {e}")
    
    def _get_cache_key(self, code: str, filename: str) -> str:
        """Generate cache key from code content."""
        content = f"{filename}:{code}"
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def _get_language_from_file(self, filename: str) -> str:
        """Determine programming language from filename."""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.php': 'php',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.cs': 'csharp',
            '.rb': 'ruby',
            '.pl': 'perl',
            '.go': 'go',
            '.rs': 'rust',
        }
        ext = os.path.splitext(filename)[1].lower()
        return ext_map.get(ext, 'text')
    
    def _analyze_with_llm(self, code: str, filename: str) -> List[Dict]:
        """
        Analyze code with LLM backend.
        
        Args:
            code: Source code to analyze
            filename: Filename for context
            
        Returns:
            List of vulnerability dictionaries
        """
        # Check cache
        cache_key = self._get_cache_key(code, filename)
        if self.cache_enabled and cache_key in self.cache:
            print(f"[LLM] Cache hit for {filename}")
            return self.cache[cache_key]
        
        # Ensure backend is initialized
        self._ensure_backend_initialized()
        
        language = self._get_language_from_file(filename)
        prompt = self.SECURITY_PROMPT_TEMPLATE.format(
            filename=filename,
            language=language,
            code=code
        )
        
        try:
            if self.backend == "gemini":
                response = self.client.generate_content(prompt)
                result_text = response.text.strip()
            
            elif self.backend == "openai":
                response = self.client.ChatCompletion.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a senior security engineer analyzing code for vulnerabilities."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1
                )
                result_text = response.choices[0].message.content.strip()
            
            elif self.backend == "ollama":
                response = self.client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a senior security engineer analyzing code for vulnerabilities."},
                        {"role": "user", "content": prompt}
                    ]
                )
                result_text = response['message']['content'].strip()
            
            # Parse JSON response
            vulnerabilities = self._parse_llm_response(result_text, filename)
            
            # Cache result
            if self.cache_enabled:
                self.cache[cache_key] = vulnerabilities
                self._save_cache()
            
            return vulnerabilities
        
        except Exception as e:
            print(f"⚠️ LLM analysis failed for {filename}: {e}")
            return []
    
    def _parse_llm_response(self, response_text: str, filename: str) -> List[Dict]:
        """Parse LLM response into vulnerability list."""
        # Remove markdown code fences if present
        text = response_text.strip()
        if text.startswith("```json"):
            text = text[7:].strip()
        elif text.startswith("```"):
            text = text[3:].strip()
        if text.endswith("```"):
            text = text[:-3].strip()
        
        try:
            parsed = json.loads(text)
            if not isinstance(parsed, list):
                print(f"⚠️ Warning: LLM response is not a list for {filename}")
                return []
            
            # Validate and normalize each vulnerability
            vulnerabilities = []
            for vuln in parsed:
                if not isinstance(vuln, dict):
                    continue
                
                # Required fields with defaults
                normalized = {
                    "scanner": "LLM",
                    "file": filename,
                    "line": vuln.get("line", 1),
                    "severity": (vuln.get("severity", "medium") or "medium").lower(),
                    "issue_text": vuln.get("issue_text", "Security issue detected"),
                    "cwe": vuln.get("cwe", "N/A"),
                    "cwe_title": "",  # Will be filled later
                    "cve": "No known CVE mapping available",
                    "code": "",  # Will be extracted if needed
                    "ai_explanation": {
                        "explanation": vuln.get("explanation", ""),
                        "fix": vuln.get("fix", "")
                    }
                }
                
                # Normalize severity
                if normalized["severity"] in ["error", "critical"]:
                    normalized["severity"] = "high"
                elif normalized["severity"] in ["warning", "info"]:
                    normalized["severity"] = "low"
                elif normalized["severity"] not in ["high", "medium", "low"]:
                    normalized["severity"] = "medium"
                
                vulnerabilities.append(normalized)
            
            return vulnerabilities
        
        except json.JSONDecodeError as e:
            print(f"⚠️ Warning: Could not parse LLM response as JSON for {filename}: {e}")
            print(f"Response text: {text[:200]}...")
            return []
    
    def _should_scan_file(self, filepath: str) -> bool:
        """Check if file should be scanned."""
        ext = os.path.splitext(filepath)[1].lower()
        return ext in self.SUPPORTED_EXTENSIONS
    
    def _read_file(self, filepath: str) -> Optional[str]:
        """Read file content safely."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"⚠️ Could not read {filepath}: {e}")
            return None
    
    def scan_file(self, filepath: str) -> List[Dict]:
        """
        Scan a single file for vulnerabilities.
        
        Args:
            filepath: Path to file to scan
            
        Returns:
            List of vulnerability dictionaries
        """
        if not self._should_scan_file(filepath):
            return []
        
        code = self._read_file(filepath)
        if not code:
            return []
        
        # Handle large files by chunking (max ~4000 lines per chunk)
        lines = code.split('\n')
        if len(lines) > 4000:
            print(f"⚠️ File {filepath} is large ({len(lines)} lines), chunking...")
            # For now, just analyze first 4000 lines
            # TODO: Implement smarter chunking that focuses on critical functions
            code = '\n'.join(lines[:4000])
        
        return self._analyze_with_llm(code, filepath)
    
    def scan_directory(self, directory: str, progress_callback=None) -> Tuple[List[Dict], Dict]:
        """
        Scan entire directory for vulnerabilities.
        
        Args:
            directory: Root directory to scan
            progress_callback: Optional callback function(current, total, filename)
            
        Returns:
            Tuple of (vulnerabilities list, statistics dict)
        """
        all_vulnerabilities = []
        files_scanned = 0
        files_with_issues = 0
        total_issues = 0
        start_time = time.time()
        
        # Collect all files to scan
        files_to_scan = []
        for root, dirs, files in os.walk(directory):
            # Skip common directories to ignore
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__', '.venv']]
            
            for file in files:
                filepath = os.path.join(root, file)
                if self._should_scan_file(filepath):
                    files_to_scan.append(filepath)
        
        total_files = len(files_to_scan)
        print(f"🔍 Found {total_files} files to scan with LLM")
        
        # Scan each file
        for i, filepath in enumerate(files_to_scan, 1):
            if progress_callback:
                progress_callback(i, total_files, filepath)
            
            print(f"[{i}/{total_files}] Scanning {filepath}...")
            
            file_vulnerabilities = self.scan_file(filepath)
            if file_vulnerabilities:
                all_vulnerabilities.extend(file_vulnerabilities)
                files_with_issues += 1
                total_issues += len(file_vulnerabilities)
            
            files_scanned += 1
        
        elapsed_time = time.time() - start_time
        
        statistics = {
            "files_scanned": files_scanned,
            "files_with_issues": files_with_issues,
            "total_issues": total_issues,
            "elapsed_time": elapsed_time,
            "model": self.model,
            "backend": self.backend
        }
        
        return all_vulnerabilities, statistics


def main():
    """Test the LLM scanner."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python llm_scanner.py <directory_or_file>")
        sys.exit(1)
    
    target = sys.argv[1]
    backend = os.getenv("LLM_BACKEND", "gemini")
    model = os.getenv("LLM_MODEL")
    
    print(f"🚀 Starting LLM Scanner (backend={backend}, model={model or 'default'})")
    
    scanner = LLMScanner(backend=backend, model=model)
    
    if os.path.isfile(target):
        vulnerabilities = scanner.scan_file(target)
        print(f"\n✅ Found {len(vulnerabilities)} vulnerabilities")
        print(json.dumps(vulnerabilities, indent=2))
    else:
        vulnerabilities, stats = scanner.scan_directory(target)
        print(f"\n✅ Scan complete!")
        print(f"   Files scanned: {stats['files_scanned']}")
        print(f"   Files with issues: {stats['files_with_issues']}")
        print(f"   Total issues: {stats['total_issues']}")
        print(f"   Time: {stats['elapsed_time']:.2f}s")
        print(f"\nVulnerabilities:")
        print(json.dumps(vulnerabilities, indent=2))


if __name__ == "__main__":
    main()
