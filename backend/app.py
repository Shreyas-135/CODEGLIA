import io
import json
import os
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
import xml.etree.ElementTree as ET
import re
import csv
import requests
import traceback
from flask import Flask, jsonify, request, Response, stream_with_context
import time

from flask_cors import CORS
app = Flask(__name__)
CORS(app, origins="*")

import subprocess

# Enhanced CORS configuration
CORS(app, 
     resources={r"/*": {
         "origins": "*",
         "methods": ["GET", "POST", "OPTIONS"],
         "allow_headers": ["Content-Type", "Accept", "Authorization"],
         "expose_headers": ["Content-Type"],
         "supports_credentials": False,
         "max_age": 3600
     }})


@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Accept,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

LANGUAGE_EXTENSIONS: Dict[str, str] = {
    "py": "Python",
    "java": "Java",
    "js": "JavaScript",
    "ts": "TypeScript",
    "c": "C",
    "cpp": "C++",
    "cc": "C++",
    "cs": "C#",
    "php": "PHP",
    "rb": "Ruby",
    "go": "Go",
    "rs": "Rust",
    "kt": "Kotlin",
    "swift": "Swift",
    "m": "Objective-C",
    "mm": "Objective-C++",
}

# Files/directories to skip during scanning
SKIP_DIRS = {
    'node_modules', '.git', '.svn', '.hg', '__pycache__', 
    'venv', 'env', '.venv', 'build', 'dist', '.next',
    'coverage', '.pytest_cache', '.tox', 'vendor'
}

SKIP_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico', '.svg',
    '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.flac', '.aac', '.ogg',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.exe', '.dll', '.so', '.dylib', '.bin',
    '.log', '.tmp', '.cache', '.lock', '.md', '.txt',
    '.woff', '.woff2', '.ttf', '.eot', '.otf'
}


def _map_severity(value: Optional[str]) -> str:
    if not value:
        return "INFO"
    v = value.upper()
    if v in SEVERITY_ORDER:
        return v
    if v in {"VERY-HIGH", "ERROR"}:
        return "CRITICAL"
    if v in {"HIGH", "WARNING"}:
        return "HIGH"
    if v in {"MEDIUM"}:
        return "MEDIUM"
    if v in {"LOW", "INFO"}:
        return v if v in SEVERITY_ORDER else "LOW"
    return "INFO"


def _detect_language(filename: str) -> str:
    ext = filename.split(".")[-1].lower() if "." in filename else ""
    return LANGUAGE_EXTENSIONS.get(ext, "Unknown")


@dataclass
class Vulnerability:
    id: str
    applicationName: str
    fileName: str
    lineOfCode: int
    vulnerabilityType: str
    severity: str
    cwe: Optional[str]
    cve: Optional[str]
    description: str
    explanation: Optional[str]
    suggestedFix: Optional[str]
    language: str
    tool: str
    confidenceLevel: Optional[str]


@dataclass
class ScanReport:
    projectName: str
    scanDate: str
    totalFiles: int
    totalVulnerabilities: int
    criticalCount: int
    highCount: int
    mediumCount: int
    lowCount: int
    infoCount: int
    languages: List[str]
    vulnerabilities: List[Dict]
    detectionAccuracy: Optional[float] = None
    f1Score: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "time": datetime.utcnow().isoformat() + "Z" 
    })

@app.get("/")
def root():
    return jsonify({
        "status": "ok",
        "message": "Vulnerability Scanner API",
        "endpoints": {
            "health": "/health",
            "scan": "/api/scan (POST)"
        }
    })


@app.post("/api/scan")
def scan_archive():
    """Accepts a code archive (.zip, .tar, .tar.gz) and runs security scanners with progress updates."""
    upload = request.files.get("file")
    if upload:
        upload.seek(0, os.SEEK_END)
        file_size = upload.tell()
        upload.seek(0)
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            return jsonify({"error": "File too large. Maximum size is 100MB."}), 413

    streaming = request.form.get("streaming") == "1" or file_size > 10 * 1024 * 1024

    if streaming:
        return Response(
            stream_with_context(_scan_with_progress()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'
            }
        )
    else:
        return _scan_synchronous()


def _scan_synchronous():
    """Synchronous scanning for backward compatibility"""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded."}), 400

        upload = request.files["file"]
        if not upload or not upload.filename:
            return jsonify({"error": "Invalid file upload."}), 400

        upload.seek(0, os.SEEK_END)
        file_size = upload.tell()
        upload.seek(0)
        if file_size > 100 * 1024 * 1024:
            return jsonify({"error": "File too large. Maximum size is 100MB."}), 413

        ground_truth_upload = request.files.get("ground_truth")
        ai_enrich = (request.form.get("ai") or "").lower() in {"1", "true", "yes"}
        application_name = request.form.get("application_name") or Path(upload.filename).stem

        with tempfile.TemporaryDirectory(prefix="vulnscan_") as tmpdir:
            archive_path = os.path.join(tmpdir, upload.filename)
            upload.save(archive_path)

            code_dir = os.path.join(tmpdir, "code")
            os.makedirs(code_dir, exist_ok=True)

            try:
                _extract_archive(archive_path, code_dir)
            except Exception as exc:
                return jsonify({"error": f"Failed to extract archive: {exc}"}), 400

            # Clean up extracted directory
            _cleanup_code_directory(code_dir)

            file_count, languages = _collect_files_and_languages(code_dir)

            bandit_results = _run_bandit(code_dir)
            semgrep_results = _run_semgrep(code_dir)

            vulns: List[Vulnerability] = []
            vulns.extend(_parse_bandit_json(bandit_results, application_name))
            vulns.extend(_parse_semgrep_json(semgrep_results, application_name))

            _scan_dependencies(code_dir, application_name, vulns, max_packages=50)

            if ai_enrich and vulns:
                _enrich_with_gemini(vulns, code_dir)

            languages_from_vulns = {v.language for v in vulns if v.language and v.language != "Unknown"}
            languages = list(set(languages) | languages_from_vulns)

            severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }
            for v in vulns:
                severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1

            metrics: Dict[str, float] = {}
            if ground_truth_upload:
                try:
                    gt_items = _parse_ground_truth(ground_truth_upload)
                    if gt_items:
                        metrics = _calculate_metrics_from_ground_truth(vulns, gt_items, code_dir)
                except Exception as e:
                    print(f"Ground truth processing failed: {e}")

            report = ScanReport(
                projectName=application_name or "Security Scan Report",
                scanDate=datetime.utcnow().isoformat() + "Z",
                totalFiles=file_count,
                totalVulnerabilities=len(vulns),
                criticalCount=severity_counts.get("CRITICAL", 0),
                highCount=severity_counts.get("HIGH", 0),
                mediumCount=severity_counts.get("MEDIUM", 0),
                lowCount=severity_counts.get("LOW", 0),
                infoCount=severity_counts.get("INFO", 0),
                languages=sorted(languages),
                vulnerabilities=[v.__dict__ for v in vulns],
                **metrics,
            )

            return jsonify(report.__dict__)

    except Exception as e:
        print(f"ERROR in /api/scan: {str(e)}")
        traceback.print_exc()
        return jsonify({
            "error": f"Internal server error: {str(e)}",
            "type": type(e).__name__
        }), 500


def _scan_with_progress():
    """Generator function that yields progress updates"""
    try:
        upload = request.files.get("file")
        if not upload or not upload.filename:
            yield f"data: {json.dumps({'error': 'No file uploaded'})}\n\n"
            return

        ground_truth_upload = request.files.get("ground_truth")
        ai_enrich = (request.form.get("ai") or "").lower() in {"1", "true", "yes"}
        application_name = request.form.get("application_name") or Path(upload.filename).stem

        yield f"data: {json.dumps({'status': 'starting', 'message': 'Initializing scan...', 'progress': 5})}\n\n"
        time.sleep(0.1)

        with tempfile.TemporaryDirectory(prefix="vulnscan_") as tmpdir:
            archive_path = os.path.join(tmpdir, upload.filename)
            upload.save(archive_path)

            yield f"data: {json.dumps({'status': 'extracting', 'message': 'Extracting archive...', 'progress': 10})}\n\n"
            
            code_dir = os.path.join(tmpdir, "code")
            os.makedirs(code_dir, exist_ok=True)

            try:
                _extract_archive(archive_path, code_dir)
            except Exception as exc:
                yield f"data: {json.dumps({'error': f'Failed to extract: {exc}'})}\n\n"
                return

            yield f"data: {json.dumps({'status': 'cleanup', 'message': 'Cleaning up unnecessary files...', 'progress': 15})}\n\n"
            _cleanup_code_directory(code_dir)

            yield f"data: {json.dumps({'status': 'analyzing', 'message': 'Analyzing codebase...', 'progress': 20})}\n\n"
            
            file_count, languages = _collect_files_and_languages(code_dir)
            yield f"data: {json.dumps({'status': 'analyzing', 'message': f'Found {file_count} files in {len(languages)} languages', 'progress': 25})}\n\n"

            yield f"data: {json.dumps({'status': 'scanning', 'message': 'Running Bandit scanner...', 'progress': 30})}\n\n"
            bandit_results = _run_bandit(code_dir)
            
            yield f"data: {json.dumps({'status': 'scanning', 'message': 'Running Semgrep scanner (this may take a while)...', 'progress': 40})}\n\n"
            semgrep_results = _run_semgrep(code_dir)

            yield f"data: {json.dumps({'status': 'parsing', 'message': 'Parsing scan results...', 'progress': 70})}\n\n"
            
            vulns: List[Vulnerability] = []
            vulns.extend(_parse_bandit_json(bandit_results, application_name))
            vulns.extend(_parse_semgrep_json(semgrep_results, application_name))

            yield f"data: {json.dumps({'status': 'dependencies', 'message': 'Scanning dependencies...', 'progress': 80})}\n\n"
            _scan_dependencies(code_dir, application_name, vulns, max_packages=50)

            if ai_enrich and vulns:
                yield f"data: {json.dumps({'status': 'ai', 'message': 'Enriching with AI...', 'progress': 85})}\n\n"
                _enrich_with_gemini(vulns, code_dir)

            yield f"data: {json.dumps({'status': 'finalizing', 'message': 'Generating report...', 'progress': 95})}\n\n"

            languages_from_vulns = {v.language for v in vulns if v.language and v.language != "Unknown"}
            languages = list(set(languages) | languages_from_vulns)

            severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }
            for v in vulns:
                severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1

            metrics: Dict[str, float] = {}
            if ground_truth_upload:
                try:
                    gt_items = _parse_ground_truth(ground_truth_upload)
                    if gt_items:
                        metrics = _calculate_metrics_from_ground_truth(vulns, gt_items, code_dir)
                except Exception as e:
                    print(f"Ground truth processing failed: {e}")

            report = ScanReport(
                projectName=application_name or "Security Scan Report",
                scanDate=datetime.utcnow().isoformat() + "Z",
                totalFiles=file_count,
                totalVulnerabilities=len(vulns),
                criticalCount=severity_counts.get("CRITICAL", 0),
                highCount=severity_counts.get("HIGH", 0),
                mediumCount=severity_counts.get("MEDIUM", 0),
                lowCount=severity_counts.get("LOW", 0),
                infoCount=severity_counts.get("INFO", 0),
                languages=sorted(languages),
                vulnerabilities=[v.__dict__ for v in vulns],
                **metrics,
            )

            yield f"data: {json.dumps({'status': 'complete', 'progress': 100, 'result': report.__dict__})}\n\n"

    except Exception as e:
        print(f"ERROR in streaming scan: {str(e)}")
        traceback.print_exc()
        yield f"data: {json.dumps({'error': f'Internal error: {str(e)}', 'type': type(e).__name__})}\n\n"


def _cleanup_code_directory(code_dir: str):
    """Remove unnecessary directories and files that slow down scanning"""
    for root, dirs, files in os.walk(code_dir, topdown=True):
        # Remove skip directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]
        
        # Remove non-code files
        for f in files:
            if any(f.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                try:
                    os.remove(os.path.join(root, f))
                except:
                    pass


def _extract_archive(archive_path: str, target_dir: str) -> None:
    lower = archive_path.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            _safe_extract_zip_optimized(zf, target_dir)
    elif lower.endswith(".tar") or lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        with tarfile.open(archive_path, "r:*") as tf:
            _safe_extract_tar_optimized(tf, target_dir)
    else:
        raise ValueError("Unsupported archive format. Use .zip or .tar(.gz)")


def _safe_extract_zip_optimized(zf: zipfile.ZipFile, path: str) -> None:
    for member in zf.infolist():
        _validate_member_path(member.filename, path)
        # Skip based on path components
        if any(skip in member.filename.split('/') for skip in SKIP_DIRS):
            continue
        if any(member.filename.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
            continue
        if member.filename.startswith('.') or '/.' in member.filename:
            continue
        if member.file_size > 10 * 1024 * 1024:  # Skip files >10MB
            continue
    zf.extractall(path)


def _safe_extract_tar_optimized(tf: tarfile.TarFile, path: str) -> None:
    for member in tf.getmembers():
        _validate_member_path(member.name, path)
        if any(skip in member.name.split('/') for skip in SKIP_DIRS):
            continue
        if any(member.name.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
            continue
        if member.name.startswith('.') or '/.' in member.name:
            continue
        if member.size > 10 * 1024 * 1024:  # Skip files >10MB
            continue
    tf.extractall(path)


def _validate_member_path(member_path: str, base_path: str) -> None:
    dest_path = os.path.abspath(os.path.join(base_path, member_path))
    if not dest_path.startswith(os.path.abspath(base_path)):
        raise ValueError("Archive contains invalid paths")


def _collect_files_and_languages(code_dir: str) -> Tuple[int, List[str]]:
    count = 0
    languages: set = set()
    for root, dirs, files in os.walk(code_dir):
        # Skip directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]
        
        for f in files:
            if not any(f.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                count += 1
                lang = _detect_language(f)
                if lang != "Unknown":
                    languages.add(lang)
    return count, sorted(list(languages))


def _run_bandit(code_dir: str) -> Optional[dict]:
    """Run Bandit with optimizations"""
    try:
        # Only scan Python files
        process = subprocess.run(
            [
                "bandit", 
                "-r", code_dir, 
                "-f", "json", 
                "-q",
                "--skip", "B404,B603",  # Skip some noisy checks
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=300,  # 5 minutes max
        )
        if process.returncode not in (0, 1):
            return None
        return json.loads(process.stdout or "{}")
    except (FileNotFoundError, Exception) as e:
        print(f"Bandit error: {e}")
        return None


def _run_semgrep(code_dir: str) -> Optional[dict]:
    """OPTIMIZED: Run Semgrep with aggressive performance settings"""
    try:
        process = subprocess.run(
            [
                "semgrep",
                "scan",
                "--json",
                "--quiet",
                "--timeout", "30",  # Per-file timeout
                "--timeout-threshold", "3",  # Skip file after 3 timeouts
                "--max-memory", "2000",  # 2GB memory limit
                "--max-target-bytes", "5000000",  # Skip files >5MB
                "--optimizations", "all",  # Enable all optimizations
                "--config", "p/security-audit",  # Lighter ruleset
                "--exclude", "*.min.js",  # Skip minified files
                "--exclude", "*.bundle.js",
                "--exclude", "test",
                "--exclude", "tests",
                code_dir,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=600,  # 10 minutes total max
        )
        if process.returncode not in (0, 1):
            print(f"Semgrep failed with code {process.returncode}")
            return None
        return json.loads(process.stdout or "{}")
    except subprocess.TimeoutExpired:
        print("Semgrep timeout - codebase too large")
        return None
    except (FileNotFoundError, Exception) as e:
        print(f"Semgrep error: {e}")
        return None


def _scan_dependencies(code_dir: str, app_name: str, vulns: List[Vulnerability], max_packages: int = 50):
    """Dependency scanning with limits"""
    # Python dependencies
    py_req_files = _find_files(code_dir, {
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-prod.txt",
    })
    
    for req_path in py_req_files[:2]:
        rel = _canonicalize_path(req_path, code_dir)
        data = _run_pip_audit(code_dir, req_path)
        dep_vulns = _parse_pip_audit_json(data, app_name, rel) if data else []
        
        if dep_vulns:
            vulns.extend(dep_vulns[:max_packages])
        else:
            pairs = _parse_requirements_txt(req_path)
            if pairs:
                pairs = pairs[:max_packages]
                osv_map = _osv_query_batch("PyPI", pairs)
                count = 0
                for (pkg, ver), vul_list in osv_map.items():
                    for vobj in vul_list:
                        if count >= max_packages:
                            break
                        vulns.append(
                            _create_dep_vuln(app_name, rel, pkg, ver, vobj, "Python", "osv")
                        )
                        count += 1

    # Node.js dependencies (limited)
    node_lock_files = _find_files(code_dir, {"package-lock.json", "npm-shrinkwrap.json"})
    for lock_path in node_lock_files[:1]:
        rel = _canonicalize_path(lock_path, code_dir)
        pairs = _collect_npm_packages_from_lock(lock_path)
        if pairs:
            pairs = pairs[:max_packages]
            osv_map = _osv_query_batch("npm", pairs)
            count = 0
            for (pkg, ver), vul_list in osv_map.items():
                for vobj in vul_list:
                    if count >= max_packages:
                        break
                    vulns.append(
                        _create_dep_vuln(app_name, rel, pkg, ver, vobj, "JavaScript", "osv")
                    )
                    count += 1


# Helper functions (unchanged from original)
def _parse_pip_audit_json(data: Optional[dict], app_name: str, req_file_rel: str) -> List[Vulnerability]:
    if not data:
        return []
    results: List[Vulnerability] = []
    
    def make_vuln(pkg_name: str, pkg_version: str, vuln_obj: dict) -> Vulnerability:
        cve: Optional[str] = None
        vid = vuln_obj.get("id") or ""
        aliases = vuln_obj.get("aliases") or []
        if isinstance(aliases, list):
            for al in aliases:
                if isinstance(al, str) and al.upper().startswith("CVE-"):
                    cve = al
                    break
        if not cve and isinstance(vid, str) and vid.upper().startswith("CVE-"):
            cve = vid

        sev = (vuln_obj.get("severity") or "").upper()
        severity = _map_severity(sev or "LOW")
        description = vuln_obj.get("description") or vuln_obj.get("summary") or f"Vulnerability in {pkg_name}"
        vtype = vuln_obj.get("id") or (aliases[0] if aliases else f"Vulnerable dependency: {pkg_name}")
        return Vulnerability(
            id=f"{req_file_rel}:{pkg_name}:{pkg_version}:pip-audit",
            applicationName=app_name,
            fileName=req_file_rel,
            lineOfCode=0,
            vulnerabilityType=str(vtype),
            severity=severity,
            cwe=None,
            cve=cve,
            description=description,
            explanation=None,
            suggestedFix=None,
            language="Python",
            tool="pip-audit",
            confidenceLevel=None,
        )

    for dep in data.get("dependencies", []):
        name = dep.get("name")
        version = dep.get("version")
        for vobj in dep.get("vulns", []) or []:
            results.append(make_vuln(name, version, vobj))
    return results

def _parse_requirements_txt(path: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "==" in s:
                    name, ver = s.split("==", 1)
                    pairs.append((name.strip(), ver.strip()))
    except Exception:
        return []
    return pairs


def _collect_npm_packages_from_lock(lock_path: str) -> List[Tuple[str, str]]:
    pkgs: List[Tuple[str, str]] = []
    try:
        with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        packages = data.get("packages")
        if isinstance(packages, dict):
            for k, v in packages.items():
                name = v.get("name") or (k.split("node_modules/")[-1] if "node_modules/" in k else None)
                ver = v.get("version")
                if name and ver and name != "":
                    pkgs.append((name, ver))
    except Exception:
        return []
    seen = set()
    uniq: List[Tuple[str, str]] = []
    for n, v in pkgs:
        key = (n.lower(), v)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((n, v))
    return uniq


def _osv_query_batch(ecosystem: str, pairs: List[Tuple[str, str]]) -> Dict[Tuple[str, str], List[dict]]:
    results: Dict[Tuple[str, str], List[dict]] = {}
    if not pairs:
        return results
    url = "https://api.osv.dev/v1/querybatch"
    headers = {"Content-Type": "application/json"}
    chunk_size = 50
    for i in range(0, len(pairs), chunk_size):
        chunk = pairs[i:i + chunk_size]
        body = {
            "queries": [
                {
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": version,
                }
                for name, version in chunk
            ]
        }
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=15)
            if resp.status_code != 200:
                continue
            data = resp.json() or {}
            for j, res in enumerate(data.get("results", [])):
                vulns = res.get("vulns") or []
                key = chunk[j]
                if vulns:
                    results[key] = vulns
        except Exception:
            continue
    return results


def _create_dep_vuln(app_name: str, manifest_rel: str, pkg_name: str, pkg_version: str, vobj: dict, language: str, tool: str) -> Vulnerability:
    aliases = vobj.get("aliases") or []
    cve = None
    for al in aliases:
        if isinstance(al, str) and al.upper().startswith("CVE-"):
            cve = al
            break
    if not cve and isinstance(vobj.get("id"), str) and vobj.get("id").upper().startswith("CVE-"):
        cve = vobj.get("id")
    
    sev_entries = vobj.get("severity") or []
    sev_string = None
    if isinstance(sev_entries, list) and sev_entries:
        sev_string = sev_entries[0].get("score") or sev_entries[0].get("type")
    severity = _map_severity(_cvss_to_severity(sev_string))
    title = vobj.get("summary") or vobj.get("id") or f"Dependency vulnerability in {pkg_name}"
    description = vobj.get("details") or title
    return Vulnerability(
        id=f"{manifest_rel}:{pkg_name}:{pkg_version}:{vobj.get('id') or 'osv'}",
        applicationName=app_name,
        fileName=manifest_rel,
        lineOfCode=0,
        vulnerabilityType=str(title),
        severity=severity,
        cwe=None,
        cve=cve,
        description=description[:5000],
        explanation=None,
        suggestedFix=None,
        language=language,
        tool=tool,
        confidenceLevel=None,
    )


def _cvss_to_severity(score_str: Optional[str]) -> str:
    try:
        if not score_str:
            return "LOW"
        if score_str.replace(".", "", 1).isdigit():
            score = float(score_str)
        else:
            m = re.search(r"\b([0-9]+\.[0-9]+)\b", score_str)
            score = float(m.group(1)) if m else 0.0
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    except Exception:
        return "LOW"


def _canonicalize_path(path_str: str, base_dir: str) -> str:
    if not path_str:
        return ""
    p = os.path.abspath(os.path.join(base_dir, path_str)) if not os.path.isabs(path_str) else os.path.abspath(path_str)
    try:
        rel = os.path.relpath(p, base_dir)
        return rel.replace("\\", "/").lower()
    except Exception:
        return p.replace("\\", "/").lower()


def _parse_ground_truth(upload) -> List[Dict]:
    filename = (upload.filename or "").lower()
    data: List[Dict] = []
    content = upload.read()
    try:
        upload.stream.seek(0)
    except Exception:
        pass
    if filename.endswith(".json"):
        try:
            parsed = json.loads(content.decode("utf-8"))
            if isinstance(parsed, dict) and "vulnerabilities" in parsed:
                items = parsed.get("vulnerabilities") or []
            elif isinstance(parsed, list):
                items = parsed
            else:
                items = []
            for it in items:
                if isinstance(it, dict):
                    data.append(it)
        except Exception:
            return []
    elif filename.endswith(".csv"):
        try:
            text = content.decode("utf-8")
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                data.append(row)
        except Exception:
            return []
    return data


def _calculate_metrics_from_ground_truth(
    predictions: List[Vulnerability], ground_truth: List[Dict], code_dir: str
) -> Dict[str, float]:
    gt_entries: List[Dict] = []
    for gt in ground_truth:
        file_val = gt.get("fileName") or gt.get("file") or gt.get("path") or ""
        line_val = gt.get("lineOfCode") or gt.get("line") or gt.get("start_line") or 0
        cwe_val = gt.get("cwe") or gt.get("cwe_id") or gt.get("rule_id") or gt.get("type")
        gt_entries.append(
            {
                "file": _canonicalize_path(str(file_val), code_dir),
                "line": int(str(line_val) or 0) if str(line_val).strip() else 0,
                "cwe": _normalize_cwe(cwe_val),
                "type": (str(cwe_val) if _normalize_cwe(cwe_val) is None else None),
            }
        )
    
    pred_entries: List[Dict] = []
    for v in predictions:
        pred_entries.append(
            {
                "file": _canonicalize_path(v.fileName, code_dir),
                "line": int(v.lineOfCode or 0),
                "cwe": _normalize_cwe(v.cwe),
                "type": v.vulnerabilityType,
            }
        )

    matched_gt = set()
    tp = 0
    for pred in pred_entries:
        for i, gt in enumerate(gt_entries):
            if i in matched_gt:
                continue
            if _match_pred_to_gt(pred, gt):
                matched_gt.add(i)
                tp += 1
                break
    
    fp = max(0, len(pred_entries) - tp)
    fn = max(0, len(gt_entries) - tp)
    precision = tp / (tp + fp or 1)
    recall = tp / (tp + fn or 1)
    f1 = 2 * (precision * recall) / (precision + recall or 1)
    acc = tp / (tp + fp + fn or 1)
    return {
        "f1Score": f1,
        "precision": precision,
        "recall": recall,
        "detectionAccuracy": acc,
    }


def _normalize_cwe(cwe: Optional[str]) -> Optional[str]:
    if not cwe:
        return None
    m = re.search(r"([0-9]{1,5})", str(cwe))
    return f"CWE-{m.group(1)}" if m else None


def _match_pred_to_gt(pred: Dict, gt: Dict) -> bool:
    if pred.get("file") != gt.get("file"):
        return False
    pl = int(pred.get("line") or 0)
    gl = int(gt.get("line") or 0)
    if pl and gl and abs(pl - gl) > 3:
        return False
    pcwe = pred.get("cwe")
    gcwe = gt.get("cwe")
    if gcwe:
        return pcwe == gcwe
    ptype = (pred.get("type") or "").lower()
    gtype = (gt.get("type") or "").lower()
    if ptype and gtype:
        return ptype == gtype
    return True


def _enrich_with_gemini(vulns: List[Vulnerability], code_dir: str, max_items: int = 50) -> None:
    """ENHANCED: Enrich vulnerabilities with AI-generated explanations and fixes using Gemini API"""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("GEMINI_API_KEY not set, skipping AI enrichment")
        return
    try:
        import google.generativeai as genai
    except ImportError:
        print("google-generativeai not installed, skipping AI enrichment")
        return
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")

    count = 0
    for v in vulns:
        if count >= max_items:
            break
        
        # Only enrich if explanation/fix is missing or is an HTTP link
        needs_expl = not v.explanation or (isinstance(v.explanation, str) and v.explanation.startswith("http"))
        needs_fix = not v.suggestedFix or (isinstance(v.suggestedFix, str) and v.suggestedFix.startswith("http"))
        
        if not (needs_expl or needs_fix):
            continue

        # Read more context around the vulnerability
        snippet = _read_code_snippet(os.path.join(code_dir, v.fileName), v.lineOfCode, window=10)
        
        # Enhanced prompt with specific instructions
        prompt = (
            "You are an expert security analyst. Analyze this code vulnerability and provide:\n"
            "1. A clear explanation of WHY this is a security issue (2-3 sentences)\n"
            "2. A concrete code fix with the EXACT line number to change\n\n"
            "Return ONLY a JSON object with this exact structure:\n"
            "{\n"
            '  "explanation": "Clear explanation here",\n'
            '  "suggestedFix": "On line X, replace ... with ... because ..."\n'
            "}\n\n"
            f"Vulnerability Details:\n"
            f"- Type: {v.vulnerabilityType}\n"
            f"- Severity: {v.severity}\n"
            f"- CWE: {v.cwe or 'N/A'}\n"
            f"- File: {v.fileName}\n"
            f"- Line: {v.lineOfCode}\n"
            f"- Issue: {v.description}\n\n"
            f"Code Context (line {v.lineOfCode}):\n"
            f"```\n{snippet}\n```\n\n"
            "Remember: Be specific about line numbers and actual code changes."
        )
        
        try:
            resp = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,  # Lower temperature for more focused responses
                    max_output_tokens=500,
                )
            )
            text = getattr(resp, "text", None)
            if not text:
                continue
            
            # Try to extract JSON first
            match = re.search(r'\{[^{}]*"explanation"[^{}]*"suggestedFix"[^{}]*\}', text, re.DOTALL)
            if match:
                try:
                    obj = json.loads(match.group(0))
                    if needs_expl and obj.get("explanation"):
                        expl = obj["explanation"].strip()
                        # Clean up any remaining URLs
                        if not expl.startswith("http"):
                            v.explanation = expl[:800]
                    if needs_fix and obj.get("suggestedFix"):
                        fix = obj["suggestedFix"].strip()
                        # Clean up any remaining URLs
                        if not fix.startswith("http"):
                            v.suggestedFix = fix[:800]
                    count += 1
                    print(f"✓ Enriched {v.fileName}:{v.lineOfCode}")
                    continue
                except json.JSONDecodeError as e:
                    print(f"JSON parse error: {e}")
            
            # Fallback: Parse structured text response
            text_clean = text.strip()
            if "explanation" in text_clean.lower() and "fix" in text_clean.lower():
                # Try to extract sections
                expl_match = re.search(r'explanation["\s:]+([^{}"]+?)(?:suggested|fix|$)', text_clean, re.IGNORECASE | re.DOTALL)
                fix_match = re.search(r'(?:suggested)?fix["\s:]+([^{}"]+?)(?:$|\})', text_clean, re.IGNORECASE | re.DOTALL)
                
                if needs_expl and expl_match:
                    expl = expl_match.group(1).strip().strip(',').strip('"').strip()
                    if expl and not expl.startswith("http") and len(expl) > 20:
                        v.explanation = expl[:800]
                
                if needs_fix and fix_match:
                    fix = fix_match.group(1).strip().strip(',').strip('"').strip()
                    if fix and not fix.startswith("http") and len(fix) > 20:
                        v.suggestedFix = fix[:800]
                
                count += 1
                print(f"✓ Enriched (fallback) {v.fileName}:{v.lineOfCode}")
            
        except Exception as e:
            print(f"Error enriching {v.fileName}:{v.lineOfCode}: {e}")
            continue
    
    print(f"AI enrichment complete: {count}/{min(max_items, len(vulns))} vulnerabilities enriched")


def _read_code_snippet(path: str, line: int, window: int = 6) -> str:
    """Read code snippet with line numbers for better context"""
    try:
        p = path if os.path.isabs(path) else path
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        start_idx = max(0, (line - 1) - window)
        end_idx = min(len(lines), (line - 1) + window + 1)
        
        # Add line numbers to snippet
        snippet_lines = []
        for i in range(start_idx, end_idx):
            line_num = i + 1
            prefix = ">>> " if line_num == line else "    "
            snippet_lines.append(f"{prefix}{line_num:4d} | {lines[i].rstrip()}")
        
        return "\n".join(snippet_lines)
    except Exception as e:
        print(f"Error reading code snippet from {path}: {e}")
        return "(source code unavailable)"


def _parse_semgrep_json(data: Optional[dict], app_name: str) -> List[Vulnerability]:
    if not data or "results" not in data:
        return []
    vulns: List[Vulnerability] = []
    for r in data.get("results", []):
        path = r.get("path") or r.get("extra", {}).get("path") or ""
        start = (r.get("start") or {}).get("line") or (
            (r.get("extra") or {}).get("start") or {}
        ).get("line")
        line_no = int(start or 0)
        extra = r.get("extra") or {}
        message = extra.get("message") or "Semgrep finding"
        severity = _map_severity(extra.get("severity"))
        metadata = extra.get("metadata") or {}
        cwe = None
        cve = None
        if isinstance(metadata, dict):
            cwe = metadata.get("cwe") or metadata.get("cwe_id")
            if isinstance(cwe, list):
                cwe = ", ".join(cwe)
        
        vulns.append(
            Vulnerability(
                id=f"{path}:{line_no}:semgrep:{r.get('check_id')}",
                applicationName=app_name,
                fileName=path,
                lineOfCode=line_no,
                vulnerabilityType=r.get("check_id") or "Unknown",
                severity=severity,
                cwe=cwe,
                cve=cve,
                description=message,
                explanation=metadata.get("description") if isinstance(metadata, dict) else None,
                suggestedFix=metadata.get("fix") if isinstance(metadata, dict) else None,
                language=_detect_language(path),
                tool="semgrep",
                confidenceLevel=None,
            )
        )
    return vulns


def _find_files(root_dir: str, names: Set[str]) -> List[str]:
    paths: List[str] = []
    for r, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f in names:
                paths.append(os.path.join(r, f))
    return paths


def _run_pip_audit(code_dir: str, requirements_path: str) -> Optional[dict]:
    try:
        process = subprocess.run(
            ["pip-audit", "-r", requirements_path, "-f", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            cwd=code_dir,
            timeout=90,
        )
        if process.returncode not in (0, 1):
            return None
        text = process.stdout or "{}"
        if not text.strip() or text.strip() == "null":
            return None
        return json.loads(text)
    except (FileNotFoundError, Exception):
        return None


def _parse_pip_audit_json(data: Optional[dict], app_name: str, req_file_rel: str) -> List[Vulnerability]:
    if not data:
        return []
    results: List[Vulnerability] = []
    
    def make_vuln(pkg_name: str, pkg_version: str, vuln_obj: dict) -> Vulnerability:
        cve: Optional[str] = None
        vid = vuln_obj.get("id") or ""
        aliases = vuln_obj.get("aliases") or []
        if isinstance(aliases, list):
            for al in aliases:
                if isinstance(al, str) and al.upper().startswith("CVE-"):
                    cve = al
                    break
        if not cve and isinstance(vid, str) and vid.upper().startswith("CVE-"):
            cve = vid

        sev = (vuln_obj.get("severity") or "").upper()
        severity = _map_severity(sev or "LOW")
        description = vuln_obj.get("description") or vuln_obj.get("summary") or f"Vulnerability in {pkg_name}"
        vtype = vuln_obj.get("id") or (aliases[0] if aliases else f"Vulnerable dependency: {pkg_name}")
        return Vulnerability(
            id=f"{req_file_rel}:{pkg_name}:{pkg_version}:pip-audit",
            applicationName=app_name,
            fileName=req_file_rel,
            lineOfCode=0,
            vulnerabilityType=str(vtype),
            severity=severity,
            cwe=None,
            cve=cve,
            description=description,
            description = vuln_obj.get("description") or vuln_obj.get("summary") or f"Vulnerability in {pkg_name}"
        vtype = vuln_obj.get("id") or (aliases[0] if aliases else f"Vulnerable dependency: {pkg_name}")
        return Vulnerability(
            id=f"{req_file_rel}:{pkg_name}:{pkg_version}:pip-audit",
            applicationName=app_name,
            fileName=req_file_rel,
            lineOfCode=0,
            vulnerabilityType=str(vtype),
            severity=severity,
            cwe=None,
            cve=cve,
            description=description,
            explanation=None,
            suggestedFix=None,
            language="Python",
            tool="pip-audit",
            confidenceLevel=None,
        )

    for dep in data.get("dependencies", []):
        name = dep.get("name")
        version = dep.get("version")
        for vobj in dep.get("vulns", []) or []:
            results.append(make_vuln(name, version, vobj))
    return results
def process_scan_results(results, filename):
    vulns = []
    for r in results:
        vulns.append(
            Vulnerability(
                file=filename,
                line=r.get("line_number"),
                message=r.get("issue_text"),
                severity=r.get("issue_severity"),
                moreInfo=r.get("more_info"),
                suggestedFix=r.get("fix") or r.get("recommendation"),
                language=_detect_language(filename),
                tool="bandit",
                confidenceLevel=r.get("issue_confidence") or r.get("confidence"),
            )
        )
    return vulns


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"Starting backend server on port {port}...")
    print(f"Health check: http://localhost:{port}/health")
    print(f"API endpoint: http://localhost:{port}/api/scan")
    app.run(host="0.0.0.0", port=port, debug=False)
