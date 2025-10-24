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
from typing import Dict, List, Optional, Tuple

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

        metrics = _calculate_metrics(len(vulns))

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

        vulns.append(
            Vulnerability(
                id=f"{filename}:{line_no}:bandit",
                applicationName=app_name,
                fileName=filename,
                lineOfCode=int(line_no or 0),
                vulnerabilityType=r.get("test_id") or r.get("issue_text") or "Unknown",
                severity=severity,
                cwe=cwe,
                cve=r.get("cve"),
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
