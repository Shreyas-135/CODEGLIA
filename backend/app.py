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
import re
import csv
import requests

from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


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
    # Map common tool severities
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


@app.get("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat() + "Z"})


@app.post("/api/scan")
def scan_archive():
    """Accepts a code archive (.zip, .tar, .tar.gz) and runs security scanners.
    Returns a unified JSON matching the frontend ScanReport type.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    upload = request.files["file"]
    ground_truth_upload = request.files.get("ground_truth")
    ai_enrich = (request.form.get("ai") or "").lower() in {"1", "true", "yes"}
    application_name = request.form.get("application_name") or Path(upload.filename).stem

    # Create a temporary workspace
    with tempfile.TemporaryDirectory(prefix="vulnscan_") as tmpdir:
        archive_path = os.path.join(tmpdir, upload.filename)
        upload.save(archive_path)

        code_dir = os.path.join(tmpdir, "code")
        os.makedirs(code_dir, exist_ok=True)

        try:
            _extract_archive(archive_path, code_dir)
        except Exception as exc:
            return jsonify({"error": f"Failed to extract archive: {exc}"}), 400

        # Gather list of files
        file_count, languages = _collect_files_and_languages(code_dir)

        bandit_results = _run_bandit(code_dir)
        semgrep_results = _run_semgrep(code_dir)

        vulns: List[Vulnerability] = []
        vulns.extend(_parse_bandit_json(bandit_results, application_name))
        vulns.extend(_parse_semgrep_json(semgrep_results, application_name))

        # Dependency scanning: Python (pip-audit) and Node (OSV on package-lock)
        # 1) Python requirements via pip-audit; fallback to OSV if pip-audit unavailable
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
                # Fallback to OSV using pinned versions from requirements
                pairs = _parse_requirements_txt(req_path)
                if pairs:
                    osv_map = _osv_query_batch("PyPI", pairs)
                    for (pkg, ver), vul_list in osv_map.items():
                        for vobj in vul_list:
                            vulns.append(
                                _create_dep_vuln(application_name, rel, pkg, ver, vobj, "Python", "osv")
                            )

        # 2) Node: use OSV on package-lock.json if present
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

        # Optionally enrich with AI explanations/fixes
        if ai_enrich:
            try:
                _enrich_with_gemini(vulns, code_dir)
            except Exception:
                # Best-effort enrichment; ignore failures
                pass

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

        # Compute metrics - prefer ground truth if provided
        metrics = _calculate_metrics(len(vulns))
        if ground_truth_upload:
            try:
                gt_items = _parse_ground_truth(ground_truth_upload)
                if gt_items:
                    metrics = _calculate_metrics_from_ground_truth(vulns, gt_items, code_dir)
            except Exception:
                # Fallback to default metrics if parsing fails
                pass

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
    # Prevent path traversal
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
            # 1 can indicate issues found
            return None
        return json.loads(process.stdout or "{}")
    except FileNotFoundError:
        return None
    except Exception:
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
        # semgrep exits 1 when findings present
        if process.returncode not in (0, 1):
            return None


# ----------------------
# Dependency Scanning (Python/Node)
# ----------------------

def _find_files(root_dir: str, names: Set[str]) -> List[str]:
    paths: List[str] = []
    for r, _, files in os.walk(root_dir):
        for f in files:
            if f in names:
                paths.append(os.path.join(r, f))
    return paths


def _run_pip_audit(code_dir: str, requirements_path: str) -> Optional[dict]:
    """Run pip-audit on a requirements file and return JSON output."""
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
        # Some pip-audit versions can emit "null" on no vulns
        if not text.strip() or text.strip() == "null":
            return None
        return json.loads(text)
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _parse_pip_audit_json(data: Optional[dict], app_name: str, req_file_rel: str) -> List[Vulnerability]:
    """Produce Vulnerability objects from pip-audit JSON, handling schema variants."""
    if not data:
        return []

    results: List[Vulnerability] = []

    def make_vuln(pkg_name: str, pkg_version: str, vuln_obj: dict) -> Vulnerability:
        # Try to extract CVE from id or aliases
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

    # Newer schema: {"dependencies": [{"name":..., "version":..., "vulns": [..]}]}
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

    # Older schema alternative: list of entries with keys {"dependency": {name, version}, "vulns": [...]}
    if isinstance(data, list):
        for entry in data:
            dep = entry.get("dependency") or {}
            name = dep.get("name") or entry.get("name") or ""
            version = dep.get("version") or entry.get("version") or ""
            vulns = entry.get("vulns") or entry.get("advisories") or []
            for vobj in vulns:
                try:
                    results.append(make_vuln(name, version, vobj))
                except Exception:
                    continue
        return results

    return results


def _parse_requirements_txt(path: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                # Support formats: pkg==1.2.3 or pkg~=1.2 or pkg>=1.0 (skip if not pinned)
                if "==" in s:
                    name, ver = s.split("==", 1)
                    pairs.append((name.strip(), ver.strip()))
                elif "@" in s and ";" not in s:
                    # URL reference, skip
                    continue
    except Exception:
        return []
    return pairs


def _collect_npm_packages_from_lock(lock_path: str) -> List[Tuple[str, str]]:
    pkgs: List[Tuple[str, str]] = []
    try:
        with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        # package-lock v2+: has "packages" with keys "node_modules/<name>"
        packages = data.get("packages")
        if isinstance(packages, dict):
            for k, v in packages.items():
                name = v.get("name") or (k.split("node_modules/")[-1] if "node_modules/" in k else None)
                ver = v.get("version")
                if name and ver and name != "":
                    pkgs.append((name, ver))
        # v1: nested dependencies
        deps = data.get("dependencies")
        def walk_deps(obj: dict):
            for name, meta in (obj or {}).items():
                ver = meta.get("version")
                if name and ver:
                    pkgs.append((name, ver))
                if isinstance(meta.get("dependencies"), dict):
                    walk_deps(meta.get("dependencies"))
        if isinstance(deps, dict):
            walk_deps(deps)
    except Exception:
        return []
    # Deduplicate
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
    # chunk to avoid huge payloads
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


def _cvss_to_severity(score_str: Optional[str]) -> str:
    try:
        if not score_str:
            return "LOW"
        # score can be like "CVSS:3.1/AV/N/AC/L/..." or a numeric string; handle numeric only
        if score_str.replace(".", "", 1).isdigit():
            score = float(score_str)
        else:
            # If vector, extract the numeric score if present (OSV may not include numeric)
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


def _create_dep_vuln(app_name: str, manifest_rel: str, pkg_name: str, pkg_version: str, vobj: dict, language: str, tool: str) -> Vulnerability:
    aliases = vobj.get("aliases") or []
    cve = None
    for al in aliases:
        if isinstance(al, str) and al.upper().startswith("CVE-"):
            cve = al
            break
    if not cve and isinstance(vobj.get("id"), str) and vobj.get("id").upper().startswith("CVE-"):
        cve = vobj.get("id")
    # Severity from OSV
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
        return json.loads(process.stdout or "{}")
    except FileNotFoundError:
        return None
    except Exception:
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
        # Try to infer CWE/CVE from text fields when missing
        if not cwe:
            more_info = r.get("more_info") or ""
            inferred_cwes = _extract_cwes_from_text(" ".join([issue_text or "", more_info]))
            cwe = inferred_cwes[0] if inferred_cwes else None
        inferred_cves = _extract_cves_from_text(issue_text or "")

        vulns.append(
            Vulnerability(
                id=f"{filename}:{line_no}:bandit",
                applicationName=app_name,
                fileName=filename,
                lineOfCode=int(line_no or 0),
                vulnerabilityType=r.get("test_id") or r.get("issue_text") or "Unknown",
                severity=severity,
                cwe=cwe,
                cve=r.get("cve") or (inferred_cves[0] if inferred_cves else None),
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
            # semgrep uses multiple shapes for CWE
            cwe = metadata.get("cwe") or metadata.get("cwe_id")
            if isinstance(cwe, list):
                cwe = ", ".join(cwe)
            # Try references for CWE/CVE
            refs = metadata.get("references")
            if refs:
                refs_text = "\n".join(refs if isinstance(refs, list) else [str(refs)])
                cwe_from_refs = _extract_cwes_from_text(refs_text)
                cve_from_refs = _extract_cves_from_text(refs_text)
                if not cwe and cwe_from_refs:
                    cwe = ", ".join(cwe_from_refs)
                if cve_from_refs:
                    cve = cve_from_refs[0]
        rules = data.get("config_info", {})
        
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


def _calculate_metrics(tp_count: int) -> Dict[str, float]:
    # Placeholder metrics; in Stage 1, F1 is often reported from benchmark datasets.
    true_pos = tp_count
    false_pos = 0
    false_neg = 0
    precision = true_pos / (true_pos + false_pos or 1)
    recall = true_pos / (true_pos + false_neg or 1)
    f1 = 2 * (precision * recall) / (precision + recall or 1)
    accuracy = true_pos / (true_pos + false_pos + false_neg or 1)
    return {
        "f1Score": f1,
        "precision": precision,
        "recall": recall,
        "detectionAccuracy": accuracy,
    }


def _extract_cwes_from_text(text: str) -> List[str]:
    if not text:
        return []
    cwes = re.findall(r"\bCWE-?([0-9]{1,5})\b", text, flags=re.IGNORECASE)
    # Normalize to CWE-###
    return [f"CWE-{cwe}" for cwe in cwes]


def _extract_cves_from_text(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r"\bCVE-[0-9]{4}-[0-9]{3,7}\b", text, flags=re.IGNORECASE)


def _parse_ground_truth(upload) -> List[Dict]:
    """Parse ground truth file (JSON list or object with 'vulnerabilities', or CSV)."""
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


def _canonicalize_path(path_str: str, base_dir: str) -> str:
    if not path_str:
        return ""
    p = os.path.abspath(os.path.join(base_dir, path_str)) if not os.path.isabs(path_str) else os.path.abspath(path_str)
    # Try to strip base_dir for normalized comparison
    try:
        rel = os.path.relpath(p, base_dir)
        return rel.replace("\\", "/").lower()
    except Exception:
        return p.replace("\\", "/").lower()


def _normalize_cwe(cwe: Optional[str]) -> Optional[str]:
    if not cwe:
        return None
    m = re.search(r"([0-9]{1,5})", str(cwe))
    return f"CWE-{m.group(1)}" if m else None


def _calculate_metrics_from_ground_truth(
    predictions: List[Vulnerability], ground_truth: List[Dict], code_dir: str
) -> Dict[str, float]:
    # Build normalized GT entries
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
    # Build normalized predictions
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
        found = False
        for i, gt in enumerate(gt_entries):
            if i in matched_gt:
                continue
            if _match_pred_to_gt(pred, gt):
                matched_gt.add(i)
                tp += 1
                found = True
                break
        # We count FP later implicitly
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


def _match_pred_to_gt(pred: Dict, gt: Dict) -> bool:
    # Require file equality
    if pred.get("file") != gt.get("file"):
        return False
    # If both have line numbers, allow small window
    pl = int(pred.get("line") or 0)
    gl = int(gt.get("line") or 0)
    if pl and gl and abs(pl - gl) > 3:
        return False
    # Prefer CWE match if present
    pcwe = pred.get("cwe")
    gcwe = gt.get("cwe")
    if gcwe:
        return pcwe == gcwe
    # Fallback to type string match (case-insensitive)
    ptype = (pred.get("type") or "").lower()
    gtype = (gt.get("type") or "").lower()
    if ptype and gtype:
        return ptype == gtype
    return True


def _enrich_with_gemini(vulns: List[Vulnerability], code_dir: str, max_items: int = 10) -> None:
    """Best-effort enrichment using Gemini if GEMINI_API_KEY is set.
    Populates explanation/suggestedFix when empty.
    """
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
            text = getattr(resp, "text", None) or getattr(resp, "candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text")
            if not text:
                continue
            # Try to parse JSON object
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
            # Fallback: split text heuristically
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
        # If given path is absolute already extracted, use as-is else try joining
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
    app.run(host="0.0.0.0", port=port)
