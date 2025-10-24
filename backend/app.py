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
from flask import Flask, jsonify, request

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


# Comprehensive after_request handler
@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Accept,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

# Handle OPTIONS requests explicitly
@app.route("/api/scan", methods=["POST", "OPTIONS"])
def scan():
    if request.method == "OPTIONS":
        return '', 204

    # Ensure a file was uploaded
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    ground_truth = request.files.get('ground_truth')
    ai_enabled = request.form.get('ai') == '1'

    # TODO: Insert your scanning logic here
    # For demo, we just return file names and flags
    response = {
        "filename": file.filename,
        "ground_truth": ground_truth.filename if ground_truth else None,
        "ai_enabled": ai_enabled,
        "message": "Scan received successfully"
    }

    return jsonify(response), 200



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
    """Accepts a code archive (.zip, .tar, .tar.gz) and runs security scanners."""
    try:
        print(f"Received scan request. Files: {list(request.files.keys())}")
        print(f"Form data: {dict(request.form)}")
        
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded."}), 400

        upload = request.files["file"]
        if not upload or not upload.filename:
            return jsonify({"error": "Invalid file upload."}), 400

        print(f"Processing file: {upload.filename}")

        ground_truth_upload = request.files.get("ground_truth")
        ai_enrich = (request.form.get("ai") or "").lower() in {"1", "true", "yes"}
        application_name = request.form.get("application_name") or Path(upload.filename).stem

        with tempfile.TemporaryDirectory(prefix="vulnscan_") as tmpdir:
            archive_path = os.path.join(tmpdir, upload.filename)
            upload.save(archive_path)
            print(f"Saved archive to: {archive_path}")

            code_dir = os.path.join(tmpdir, "code")
            os.makedirs(code_dir, exist_ok=True)

            try:
                _extract_archive(archive_path, code_dir)
                print(f"Extracted archive to: {code_dir}")
            except Exception as exc:
                print(f"Extraction error: {exc}")
                return jsonify({"error": f"Failed to extract archive: {exc}"}), 400

            file_count, languages = _collect_files_and_languages(code_dir)
            print(f"Found {file_count} files in {len(languages)} languages")

            bandit_results = _run_bandit(code_dir)
            semgrep_results = _run_semgrep(code_dir)

            vulns: List[Vulnerability] = []
            vulns.extend(_parse_bandit_json(bandit_results, application_name))
            vulns.extend(_parse_semgrep_json(semgrep_results, application_name))

            # Dependency scanning
            py_req_files = _find_files(code_dir, {
                "requirements.txt",
                "requirements-dev.txt",
                "requirements-prod.txt",
            })
            for req_path in py_req_files:
                rel = _canonicalize_path(req_path, code_dir)
                data = _run_pip_audit(code_dir, req_path)
                dep_vulns = _parse_pip_audit_json(data, application_name, rel) if data else []
                if dep_vulns:
                    vulns.extend(dep_vulns)
                else:
                    pairs = _parse_requirements_txt(req_path)
                    if pairs:
                        osv_map = _osv_query_batch("PyPI", pairs)
                        for (pkg, ver), vul_list in osv_map.items():
                            for vobj in vul_list:
                                vulns.append(
                                    _create_dep_vuln(application_name, rel, pkg, ver, vobj, "Python", "osv")
                                )

            node_lock_files = _find_files(code_dir, {"package-lock.json", "npm-shrinkwrap.json"})
            for lock_path in node_lock_files:
                rel = _canonicalize_path(lock_path, code_dir)
                pairs = _collect_npm_packages_from_lock(lock_path)
                if pairs:
                    osv_map = _osv_query_batch("npm", pairs)
                    for (pkg, ver), vul_list in osv_map.items():
                        for vobj in vul_list:
                            vulns.append(
                                _create_dep_vuln(application_name, rel, pkg, ver, vobj, "JavaScript", "osv")
                            )

            if ai_enrich:
                try:
                    _enrich_with_gemini(vulns, code_dir)
                except Exception as e:
                    print(f"AI enrichment failed: {e}")

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

            print(f"Scan complete. Found {len(vulns)} vulnerabilities")
            return jsonify(report.__dict__)

    except Exception as e:
        print(f"ERROR in /api/scan: {str(e)}")
        traceback.print_exc()
        return jsonify({
            "error": f"Internal server error: {str(e)}",
            "type": type(e).__name__
        }), 500


def _extract_archive(archive_path: str, target_dir: str) -> None:
    lower = archive_path.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            _safe_extract_zip(zf, target_dir)
    elif lower.endswith(".tar") or lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        with tarfile.open(archive_path, "r:*") as tf:
            _safe_extract_tar(tf, target_dir)
    else:
        raise ValueError("Unsupported archive format. Use .zip or .tar(.gz)")


def _safe_extract_zip(zf: zipfile.ZipFile, path: str) -> None:
    for member in zf.infolist():
        _validate_member_path(member.filename, path)
    zf.extractall(path)


def _safe_extract_tar(tf: tarfile.TarFile, path: str) -> None:
    for member in tf.getmembers():
        _validate_member_path(member.name, path)
    tf.extractall(path)


def _validate_member_path(member_path: str, base_path: str) -> None:
    dest_path = os.path.abspath(os.path.join(base_path, member_path))
    if not dest_path.startswith(os.path.abspath(base_path)):
        raise ValueError("Archive contains invalid paths")


def _collect_files_and_languages(code_dir: str) -> Tuple[int, List[str]]:
    count = 0
    languages: set = set()
    for root, _, files in os.walk(code_dir):
        for f in files:
            count += 1
            languages.add(_detect_language(f))
    languages.discard("Unknown")
    return count, sorted(list(languages))


def _run_bandit(code_dir: str) -> Optional[dict]:
    try:
        process = subprocess.run(
            ["bandit", "-r", code_dir, "-f", "json", "-q"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=300,
        )
        if process.returncode not in (0, 1):
            return None
        return json.loads(process.stdout or "{}")
    except (FileNotFoundError, Exception) as e:
        print(f"Bandit error: {e}")
        return None


def _run_semgrep(code_dir: str) -> Optional[dict]:
    try:
        process = subprocess.run(
            [
                "semgrep",
                "scan",
                "--json",
                "--quiet",
                "--timeout","120",
                "--config","p/owasp-top-ten",
                "--config","p/cwe-top-25",
                code_dir,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=420,
        )
        if process.returncode not in (0, 1):
            return None
        return json.loads(process.stdout or "{}")
    except (FileNotFoundError, Exception) as e:
        print(f"Semgrep error: {e}")
        return None


def _parse_bandit_json(data: Optional[dict], app_name: str) -> List[Vulnerability]:
    if not data or "results" not in data:
        return []
    vulns: List[Vulnerability] = []
    for r in data.get("results", []):
        filename = r.get("filename") or ""
        line_no = r.get("line_number") or 0
        issue_text = r.get("issue_text") or r.get("issue") or "Bandit finding"
        severity = _map_severity(r.get("issue_severity") or r.get("severity"))
        cwe = None
        issue_cwe = r.get("issue_cwe")
        if isinstance(issue_cwe, dict):
            cwe = issue_cwe.get("id")
        elif isinstance(issue_cwe, str):
            cwe = issue_cwe
        
        vulns.append(
            Vulnerability(
                id=f"{filename}:{line_no}:bandit",
                applicationName=app_name,
                fileName=filename,
                lineOfCode=int(line_no or 0),
                vulnerabilityType=r.get("test_id") or r.get("issue_text") or "Unknown",
                severity=severity,
                cwe=cwe,
                cve=r.get("cve") or None,
                description=issue_text,
                explanation=r.get("more_info"),
                suggestedFix=r.get("fix") or r.get("recommendation"),
                language=_detect_language(filename),
                tool="bandit",
                confidenceLevel=r.get("issue_confidence") or r.get("confidence"),
            )
        )
    return vulns


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
    for r, _, files in os.walk(root_dir):
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
            timeout=300,
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
            explanation=None,
            suggestedFix=(", ".join(vuln_obj.get("fix_versions") or []) or None),
            language="Python",
            tool="pip-audit",
            confidenceLevel=None,
        )

    if isinstance(data, dict) and isinstance(data.get("dependencies"), list):
        for dep in data.get("dependencies", []):
            name = dep.get("name") or ""
            version = dep.get("version") or ""
            for vobj in dep.get("vulns", []) or []:
                try:
                    results.append(make_vuln(name, version, vobj))
                except Exception:
                    continue
    
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
    chunk_size = 100
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
            resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=20)
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


def _enrich_with_gemini(vulns: List[Vulnerability], code_dir: str, max_items: int = 10) -> None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return
    try:
        import google.generativeai as genai
    except Exception:
        return
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")

    count = 0
    for v in vulns:
        if count >= max_items:
            break
        needs_expl = not v.explanation
        needs_fix = not v.suggestedFix
        if not (needs_expl or needs_fix):
            continue

        snippet = _read_code_snippet(os.path.join(code_dir, v.fileName), v.lineOfCode)
        prompt = (
            "You are a secure code expert. Given the finding below and code snippet, "
            "return a concise JSON with keys 'explanation' and 'suggestedFix'. "
            "Keep each under 120 words.\n\n"
            f"Finding: type={v.vulnerabilityType}, severity={v.severity}, cwe={v.cwe or ''}\n"
            f"File: {v.fileName}:{v.lineOfCode}\n\n"
            f"Code snippet:\n{snippet}\n"
        )
        try:
            resp = model.generate_content(prompt)
            text = getattr(resp, "text", None)
            if not text:
                continue
            match = re.search(r"\{[\s\S]*\}", text)
            if match:
                try:
                    obj = json.loads(match.group(0))
                    if needs_expl and isinstance(obj.get("explanation"), str):
                        v.explanation = obj.get("explanation")
                    if needs_fix and isinstance(obj.get("suggestedFix"), str):
                        v.suggestedFix = obj.get("suggestedFix")
                    count += 1
                    continue
                except Exception:
                    pass
            parts = text.split("Suggested fix:")
            if needs_expl and parts:
                v.explanation = parts[0].strip()[:600]
            if needs_fix and len(parts) > 1:
                v.suggestedFix = parts[1].strip()[:600]
            count += 1
        except Exception:
            continue


def _read_code_snippet(path: str, line: int, window: int = 6) -> str:
    try:
        p = path if os.path.isabs(path) else path
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        idx = max(0, (line - 1) - window)
        end = min(len(lines), (line - 1) + window)
        snippet = "".join(lines[idx:end])
        return snippet
    except Exception:
        return "(source code unavailable)"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting backend server on port {port}...")
    print(f"Health check: http://localhost:{port}/health")
    print(f"API endpoint: http://localhost:{port}/api/scan")
    app.run(host="0.0.0.0", port=port, debug=False)
