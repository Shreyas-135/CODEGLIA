import requests
import time

# --- CWE Title Fetching and Caching ---
_CWE_CACHE_FILE = ".cwe_cache.json"
_cwe_cache = None

def _load_cwe_cache():
    global _cwe_cache
    if _cwe_cache is not None:
        return _cwe_cache
    try:
        with open(_CWE_CACHE_FILE, "r", encoding="utf-8") as f:
            _cwe_cache = json.load(f)
    except Exception:
        _cwe_cache = {}
    return _cwe_cache

def _save_cwe_cache():
    global _cwe_cache
    if _cwe_cache is None:
        return
    try:
        with open(_CWE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_cwe_cache, f, indent=2)
    except Exception:
        pass

def get_cwe_details(cwe_id):
    """
    Fetch CWE title and description from MITRE data dynamically, with local caching.
    Ensures title is always present if possible, using HTML <h2> fallback if JSON "Name" is missing.
    Returns dict: {"title": ..., "description": ...}
    """
    if not isinstance(cwe_id, str) or not cwe_id.startswith("CWE-"):
        return {"title": "", "description": ""}
    cache = _load_cwe_cache()
    if cwe_id in cache:
        cached = cache[cwe_id]
        # Ensure title is present (HTML <h2> fallback if missing)
        if not cached.get("title"):
            cwe_num = cwe_id.replace("CWE-", "")
            try:
                html_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                html = requests.get(html_url, timeout=8).text
                import re as _re
                m = _re.search(r"<h2>(CWE-\d+): ([^<]+)</h2>", html)
                title = m.group(2) if m else ""
                if title:
                    cached["title"] = title
                    _save_cwe_cache()
            except Exception:
                pass
        return cached
    # Try fetching from MITRE
    cwe_num = cwe_id.replace("CWE-", "")
    url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.json"
    try:
        res = requests.get(url, timeout=8)
        if res.status_code == 200:
            data = res.json()
            title = data.get("Name", "")
            desc = data.get("Description", "")
            # Fallback: If title is missing, parse from HTML <h2>
            if not title:
                try:
                    html_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                    html = requests.get(html_url, timeout=8).text
                    import re as _re
                    m = _re.search(r"<h2>(CWE-\d+): ([^<]+)</h2>", html)
                    title = m.group(2) if m else ""
                except Exception:
                    pass
            cache[cwe_id] = {"title": title, "description": desc}
            _save_cwe_cache()
            return cache[cwe_id]
        else:
            # fallback: try parsing HTML
            html_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            html = requests.get(html_url, timeout=8).text
            import re as _re
            m = _re.search(r"<h2>(CWE-\d+): ([^<]+)</h2>", html)
            title = m.group(2) if m else ""
            desc = ""
            cache[cwe_id] = {"title": title, "description": desc}
            _save_cwe_cache()
            return cache[cwe_id]
    except Exception as e:
        # fallback: just return empty
        cache[cwe_id] = {"title": "", "description": ""}
        return cache[cwe_id]

# --- NVD API CVE Fetching with Rate Limiting ---
def get_cve_for_cwe(cwe_id):
    """Fetch CVE list dynamically from NVD API given a CWE ID. Rate-limited and robust."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={cwe_id}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            if "vulnerabilities" in data:
                cves = [v["cve"]["id"] for v in data["vulnerabilities"]]
                # Rate limit: sleep 1s after NVD call
                time.sleep(1)
                return cves[:5] if cves else []
        else:
            print(f"⚠️ NVD API status {res.status_code} for {cwe_id}")
    except Exception as e:
        print(f"⚠️ NVD fetch failed for {cwe_id}: {e}")
    return []
#
CWE_MAP = {
    "hardcoded password": "CWE-798",
    "sql injection": "CWE-89",
    "sql string": "CWE-89",
    "manual sql": "CWE-89",
    "formatted sql query": "CWE-89",
    "unparameterized query": "CWE-89",
    "unsafe sql": "CWE-89",
    "query concatenation": "CWE-89",
    "raw sql": "CWE-89",
    "execute query": "CWE-89",
    "command injection": "CWE-78",
    "shell": "CWE-78",
    "os.system": "CWE-78",
    "insecure deserialization": "CWE-502",
    "path traversal": "CWE-22",
    #"path": "CWE-22",
    "use of eval": "CWE-95",
    "unsafe yaml load": "CWE-20",
    "no timeout": "CWE-400",
    "request timeout": "CWE-400",
    "missing raise_for_status": "CWE-703",
    "insecure random": "CWE-330",
    "injection": "CWE-78",  # fallback for injection
    "password": "CWE-798",
    "secret": "CWE-798",
    "timeout": "CWE-400",
    # Expanded categories:
    "xss": "CWE-79",
    "cross site scripting": "CWE-79",
    "csrf": "CWE-352",
    "cross site request forgery": "CWE-352",
    "ssrf": "CWE-918",
    "server side request forgery": "CWE-918",
    "xxe": "CWE-611",
    "xml external entity": "CWE-611",
    "directory traversal": "CWE-22",
    "file inclusion": "CWE-98",
    "insecure configuration": "CWE-16",
    "insecure config": "CWE-16",
    "denial of service": "CWE-400",
    #"dos": "CWE-400",
    "resource exhaustion": "CWE-400",
    "race condition": "CWE-362",
    "unvalidated redirect": "CWE-601",
    "open redirect": "CWE-601",
    "unsafe reflection": "CWE-470",
    "weak crypto": "CWE-327",
    "cryptographically weak": "CWE-327",
    "unrestricted file upload": "CWE-434",
    "file upload": "CWE-434",
    "broken authentication": "CWE-287",
    "information disclosure": "CWE-200",
    "leak": "CWE-200",
    "out of bounds": "CWE-787",
    "buffer overflow": "CWE-120",
    "format string": "CWE-134",
    # --- Added mappings ---
    "md5": "CWE-327",
    "weak hash": "CWE-327",
    "weak hashing": "CWE-327",
    "verify=false": "CWE-295",
    "disable ssl verification": "CWE-295",
    "ssl verification": "CWE-295",
    "certificate verification": "CWE-295",
    "improper ssl": "CWE-295",
    #"crypto": "CWE-327",
    "weak encryption": "CWE-327",
    "broken crypto": "CWE-327",
    "input validation": "CWE-20",
    "unsafe input": "CWE-20",
    "api key": "CWE-798",
    "access control": "CWE-284",
    "authorization": "CWE-284",
    "temp file": "CWE-377",
    "temporary file": "CWE-377",
    "error message": "CWE-209",
    "verbose error": "CWE-209",
    "crypto misuse": "CWE-327",
    "weak key": "CWE-327",
    "gets(": "CWE-242",
    "strcpy(": "CWE-242",
    "template injection": "CWE-94",
    "jinja": "CWE-94",
    "improper permission": "CWE-276",
}


# --- CVE mapping for specific known vulnerabilities ---
CVE_MAP = {
    "CVE-2021-44228": "Apache Log4j Remote Code Execution (CWE-502)",
    "CVE-2017-5638": "Apache Struts RCE via Content-Type (CWE-20)",
    "CVE-2014-0160": "Heartbleed (CWE-125)",
    "CVE-2019-0708": "BlueKeep (CWE-287)",
    "CVE-2022-22965": "Spring4Shell Remote Code Execution (CWE-502)",
    "CVE-2021-41773": "Apache Path Traversal (CWE-22)",
    "CVE-2020-0601": "Windows CryptoAPI Spoofing (CWE-295)",
    "CVE-2018-7600": "Drupalgeddon2 (CWE-20)",
    "CVE-2021-3156": "Sudo Privilege Escalation via Command Injection (CWE-78)",
    "CVE-2014-6271": "Bash Shellshock Command Injection (CWE-78)",
    "CVE-2019-11043": "PHP-FPM RCE (CWE-89)",
    "CVE-2012-1823": "PHP-CGI Query String Injection (CWE-89)",
    "CVE-2021-3449": "OpenSSL Denial of Service (CWE-400)",
    "CVE-2022-21661": "WordPress Core SQL Injection (CWE-89)",
    "CVE-2020-11023": "jQuery XSS Vulnerability (CWE-79)",
    "CVE-2021-26855": "Microsoft Exchange SSRF (CWE-918)",
    "CVE-2023-34362": "MOVEit Transfer SQL Injection (CWE-89)",
    "CVE-2022-22963": "Spring Cloud Function SpEL Injection (CWE-94)",
    "CVE-2021-34527": "PrintNightmare Privilege Escalation (CWE-269)",
    "CVE-2020-0796": "SMBGhost Remote Code Execution (CWE-787)",
}

# --- Unified CVE mapping by CWE code ---
CVE_MAP_BY_CWE = {
    "CWE-89": ["CVE-2022-21661", "CVE-2012-1823", "CVE-2019-11043", "CVE-2023-34362", "CVE-2018-10933", "CVE-2017-5941"],
    "CWE-78": ["CVE-2014-6271", "CVE-2021-3156", "CVE-2019-5736", "CVE-2016-4437"],
    "CWE-502": ["CVE-2021-44228", "CVE-2022-22965", "CVE-2015-4852"],
    "CWE-22": ["CVE-2021-41773", "CVE-2018-9206"],
    "CWE-79": ["CVE-2020-11023", "CVE-2019-11358", "CVE-2018-3721"],
    "CWE-918": ["CVE-2021-26855", "CVE-2019-5418"],
    "CWE-611": ["CVE-2017-12629", "CVE-2019-9670"],
    "CWE-400": ["CVE-2021-3449", "CVE-2016-10195"],
    "CWE-287": ["CVE-2019-0708", "CVE-2018-10933"],
    "CWE-787": ["CVE-2020-0796", "CVE-2017-1000253"],
    "CWE-125": ["CVE-2014-0160", "CVE-2016-2107"],
    "CWE-434": ["CVE-2015-7501", "CVE-2019-6340"],
    "CWE-601": ["CVE-2015-2080", "CVE-2018-1000525"],
    "CWE-16": ["CVE-2017-9805", "CVE-2019-5420"],
    "CWE-352": ["CVE-2018-1000525", "CVE-2019-6339"],
    "CWE-95": ["CVE-2019-5418", "CVE-2017-5941"],
    "CWE-703": ["CVE-2017-3735"],
    "CWE-330": ["CVE-2019-1552"],
    "CWE-295": ["CVE-2020-0601", "CVE-2016-2107"],
    "CWE-269": ["CVE-2021-34527", "CVE-2018-8897"],
    "CWE-200": ["CVE-2018-1002105"],
    "CWE-327": ["CVE-2015-4000", "CVE-2016-2183"],
    "CWE-362": ["CVE-2017-1000112"],
    "CWE-470": ["CVE-2017-7525"],
    "CWE-98": ["CVE-2017-9841"],
    "CWE-120": ["CVE-2017-1000253"],
    "CWE-134": ["CVE-2017-16943"],
    "CWE-20": ["CVE-2018-7600", "CVE-2017-5638", "CVE-2017-9805", "CVE-2019-5418", "CVE-2018-1000656"],
    "CWE-284": ["CVE-2021-40539", "CVE-2019-11043"],
    "CWE-377": ["CVE-2022-34918"],
    "CWE-209": ["CVE-2021-21300"],
    "CWE-276": ["CVE-2017-12635"],
    "CWE-242": ["CVE-2016-0638"],
    "CWE-94": ["CVE-2022-22963", "CVE-2017-5941", "CVE-2023-29491"],
}

# --- OWASP Top 10 Mapping for Common CWE IDs ---

#
OWASP_TOP10_MAP = {
    # A01: Broken Access Control
    "CWE-200": "A01:2021 - Broken Access Control",
    "CWE-284": "A01:2021 - Broken Access Control",
    "CWE-285": "A01:2021 - Broken Access Control",

    # A02: Cryptographic Failures
    "CWE-310": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-329": "A02:2021 - Cryptographic Failures",
    "CWE-330": "A02:2021 - Cryptographic Failures",
    "CWE-295": "A02:2021 - Cryptographic Failures",
    "CWE-798": "A02:2021 - Cryptographic Failures",

    # A03: Injection
    "CWE-78": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-89": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-95": "A03:2021 - Injection",
    "CWE-20": "A03:2021 - Injection",
    "CWE-134": "A03:2021 - Injection",
    "CWE-242": "A03:2021 - Injection",

    # A04: Insecure Design
    "CWE-362": "A04:2021 - Insecure Design",
    "CWE-269": "A04:2021 - Insecure Design",

    # A05: Security Misconfiguration
    "CWE-16": "A05:2021 - Security Misconfiguration",
    "CWE-22": "A05:2021 - Security Misconfiguration",
    "CWE-276": "A05:2021 - Security Misconfiguration",
    "CWE-611": "A05:2021 - Security Misconfiguration",
    "CWE-377": "A05:2021 - Security Misconfiguration",
    "CWE-352": "A05:2021 - Security Misconfiguration",
    "CWE-120": "A05:2021 - Security Misconfiguration",

    # A06: Vulnerable and Outdated Components
    "CWE-400": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-125": "A06:2021 - Vulnerable and Outdated Components",

    # A07: Identification and Authentication Failures
    "CWE-287": "A07:2021 - Identification and Authentication Failures",

    # A08: Software and Data Integrity Failures
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-434": "A08:2021 - Software and Data Integrity Failures",

    # A09: Security Logging and Monitoring Failures
    "CWE-209": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-703": "A09:2021 - Security Logging and Monitoring Failures",

    # A10: Server-Side Request Forgery (SSRF)
    "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
}
# Expanded CWE mapping dictionary for common vulnerability types



# --- CVE mapping for specific known vulnerabilities ---

import os

import re
import json

import typing

from datetime import datetime


# Google Gemini (genai) is already used in the file

import google.generativeai as genai


# Read API key from environment

GEMINI_KEY = os.getenv("GEMINI_API_KEY")




# --- AI Batch Mode, Caching, and Analysis ---

# --- OPTIMIZED AI Analysis with Caching, Batching, Async (optional), Timing ---
import hashlib
import threading
import asyncio
import concurrent.futures
import time as _time

_CACHE_FILE = ".cache.json"
_ai_cache = None

def _load_cache():
    global _ai_cache
    if _ai_cache is not None:
        return _ai_cache
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as f:
            _ai_cache = json.load(f)
    except Exception:
        _ai_cache = {}
    return _ai_cache

def _save_cache():
    global _ai_cache
    if _ai_cache is None:
        return
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_ai_cache, f, indent=2)
    except Exception:
        pass

def _get_cache_key(text: str) -> str:
    # Use a hash of the text as the key to avoid huge cache keys
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def _find_in_cache_or_equiv(summary, cache):
    """
    Checks cache for exact or semantically identical vulnerability summaries.
    Returns cached result or None.
    """
    key = _get_cache_key(summary)
    if key in cache:
        return cache[key]
    # Optionally: try to match by normalized summary for redundancy
    norm = summary.strip().lower()
    for k, v in cache.items():
        # Try to compare normalized summaries, skip if not string
        if hasattr(v, 'get') and isinstance(v, dict):
            continue
        # Not used for now, just hash key
    return None

def get_ai_analysis(vulnerability_details: str) -> dict:
    """
    Caching wrapper for single vulnerability analysis.
    Optimized: checks expanded cache before API call.
    """
    cache = _load_cache()
    key = _get_cache_key(vulnerability_details)
    if key in cache:
        print(f"[AI] Cache hit for summary (key={key[:8]})")
        return cache[key]
    # Try to skip redundant re-analysis
    cached = _find_in_cache_or_equiv(vulnerability_details, cache)
    if cached is not None:
        print(f"[AI] Redundant analysis skipped (found equivalent in cache)")
        return cached
    start = _time.time()
    result = get_ai_analysis_batch([vulnerability_details])[0]
    cache[key] = result
    _save_cache()
    print(f"[AI] Single AI analysis took {(_time.time() - start):.2f}s")
    return result

def get_ai_analysis_batch(vulnerability_summaries: list, use_async=False) -> list:
    """
    Optimized batch AI analysis: up to 10 vulnerabilities per Gemini API request.
    Caches results, skips redundant re-analysis, supports optional async concurrency.
    Prints progress and timing logs.
    """
    import math
    cache = _load_cache()
    start_total = _time.time()
    results = [None] * len(vulnerability_summaries)
    uncached = []
    uncached_indices = []
    # Expanded cache check: skip redundant analysis
    for i, summary in enumerate(vulnerability_summaries):
        key = _get_cache_key(summary)
        if key in cache:
            results[i] = cache[key]
        else:
            cached_equiv = _find_in_cache_or_equiv(summary, cache)
            if cached_equiv is not None:
                results[i] = cached_equiv
            else:
                results[i] = None
                uncached.append(summary)
                uncached_indices.append(i)
    print(f"[AI] Batch cache hits: {len(vulnerability_summaries) - len(uncached)} / {len(vulnerability_summaries)}")
    _cache_hit_time = _time.time()
    # If all are cached, return immediately
    if not uncached:
        print(f"[AI] All batch results loaded from cache in {(_cache_hit_time - start_total):.2f}s")
        return results
    if not GEMINI_KEY:
        for idx in uncached_indices:
            results[idx] = {"explanation": "AI key not configured (set GEMINI_API_KEY environment variable)", "fix": ""}
        return results
    # Batching: up to 10 per Gemini API request
    batch_size = 10
    batches = [uncached[i:i+batch_size] for i in range(0, len(uncached), batch_size)]
    batch_indices = [uncached_indices[i:i+batch_size] for i in range(0, len(uncached), batch_size)]
    def _analyze_batch(batch, batch_idx, total_batches):
        batch_start = _time.time()
        print(f"[AI] Analyzing batch {batch_idx+1}/{total_batches}... ({len(batch)} vulnerabilities)")
        try:
            genai.configure(api_key=GEMINI_KEY)
            model = genai.GenerativeModel('gemini-2.5-flash')
            numbered = []
            for idx, summary in enumerate(batch, 1):
                numbered.append(f"Vulnerability #{idx}:\n{summary.strip()}\n")
            prompt = f"""
You are a senior cybersecurity expert reviewing multiple findings from a SAST tool.

For each finding below, do BOTH of the following:
1. In simple terms, explain what this vulnerability is and why it is a risk.
2. Provide a concise, secure code snippet to fix the vulnerability.

Respond ONLY with a JSON array. For each vulnerability, return an object with two fields: "explanation" and "fix".
Example:
[
  {{"explanation": "...", "fix": "..."}},
  ...
]

Findings:
{chr(10).join(numbered)}
"""
            response = model.generate_content(prompt)
            text = response.text.strip()
            # Remove ```json fences if present
            if text.startswith("```json"):
                text = text[len("```json"):].strip()
            if text.endswith("```"):
                text = text[:-3].strip()
            # Parse as JSON array
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list) and len(parsed) == len(batch):
                    batch_results = []
                    for obj in parsed:
                        explanation = obj.get("explanation", "")
                        fix = obj.get("fix", "")
                        batch_results.append({"explanation": explanation, "fix": fix})
                else:
                    batch_results = [{"explanation": text, "fix": ""}] * len(batch)
            except Exception:
                batch_results = [{"explanation": text, "fix": ""}] * len(batch)
            print(f"[AI] Batch {batch_idx+1} AI call took {(_time.time() - batch_start):.2f}s")
            return batch_results
        except Exception as e:
            print(f"[AI] Batch {batch_idx+1} error: {e}")
            return [{"explanation": f"Error connecting to Google AI service: {e}", "fix": ""}] * len(batch)

    batch_results_list = []
    total_batches = len(batches)
    ai_call_start = _time.time()
    if use_async and total_batches > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, total_batches)) as executor:
            futures = []
            for i, batch in enumerate(batches):
                futures.append(executor.submit(_analyze_batch, batch, i, total_batches))
            for i, fut in enumerate(futures):
                res = fut.result()
                batch_results_list.append(res)
    else:
        for i, batch in enumerate(batches):
            batch_results_list.append(_analyze_batch(batch, i, total_batches))
    ai_call_end = _time.time()
    flat_results = [item for sublist in batch_results_list for item in sublist]
    for idx, res in zip(uncached_indices, flat_results):
        results[idx] = res
        cache[_get_cache_key(vulnerability_summaries[idx])] = res
    _save_cache()
    print(f"[AI] AI call(s) took {(ai_call_end - ai_call_start):.2f}s, total batch time: {(_time.time() - start_total):.2f}s")
    return results



def extract_code_from_file(path: str, start_line: typing.Optional[int] = None, end_line: typing.Optional[int] = None, ctx: int = 2) -> str:

    """Read file and return a code snippet using start/end lines or small context.


    Semgrep sometimes omits code snippets (e.g., returns 'requires login').

    This function reads the local file referred by `path` and extracts lines safely.

    """

    if not path:

        return ""

    # If path is relative, try to normalize

    try:

        # If path is absolute use it; otherwise try as given

        file_path = path

        if not os.path.exists(file_path):

            # try relative to current directory

            file_path = os.path.join(os.getcwd(), path)

        with open(file_path, 'r', encoding='utf-8') as f:

            lines = f.readlines()

    except Exception:

        return ""


    n = len(lines)

    # If no positions provided, return a small slice from the top of file (or full file if small)

    if start_line is None:

        s = 0

        e = min(n, 20)

    else:

        # semgrep lines are 1-indexed

        s = max(0, (start_line - 1) - ctx)

        # end_line may be None; default to start_line

        if end_line is None:

            e = min(n, (start_line - 1) + ctx + 1)

        else:

            e = min(n, end_line + ctx)

    snippet = "".join(lines[s:e]).rstrip()

    return snippet



def parse_bandit_results(file_path: str):

    """Parses Bandit JSON report, returns list of structured vulnerabilities with AI explanations."""

    print("\n B A N D I T  R E S U L T S \n" + "=" * 40)

    vulns = []

    try:

        with open(file_path, 'r') as f:

            data = json.load(f)

    except FileNotFoundError:

        print(f"⚠️ Bandit results file not found at: {file_path}")

        return []

    except json.JSONDecodeError:

        print(f"⚠️ Could not decode JSON from the Bandit file: {file_path}")

        return []


    vulnerabilities = data.get('results', [])

    if not vulnerabilities:

        print("✅ No vulnerabilities found by Bandit.")

        return []


    # --- Batch AI mode with caching ---
    summaries = []
    vuln_objs = []
    for i, vuln in enumerate(vulnerabilities, 1):
        filename = vuln.get('filename')
        line_number = vuln.get('line_number')
        issue_text = vuln.get('issue_text')
        severity = vuln.get('issue_severity')
        code = vuln.get('code', '').strip()
        print(f"--- Bandit Vulnerability #{i} ---")
        print(f"  File: {filename}")
        print(f"  Line: {line_number}")
        print(f"  Severity: {severity}")
        print(f"  Issue: {issue_text}")
        if code:
            print("  Code:\n" + code)
        vuln_summary = (
            f"Source: Bandit\n"
            f"File: {filename}\n"
            f"Line: {line_number}\n"
            f"Severity: {severity}\n"
            f"Issue: {issue_text}\n"
            f"Code:\n{code}\n"
        )
        summaries.append(vuln_summary)
        vuln_objs.append({
            "scanner": "Bandit",
            "file": filename,
            "line": line_number,
            "severity": severity,
            "issue_text": issue_text,
            "code": code,
            # ai_explanation to be filled after batch
        })
    # Batch in groups of 10
    ai_results = []
    for i in range(0, len(summaries), 10):
        batch = summaries[i:i+10]
        ai_results.extend(get_ai_analysis_batch(batch))
    # Attach AI explanations and extract CWE/CVE
    import random
    for idx, vuln in enumerate(vuln_objs):
        ai_explanation = ai_results[idx]
        print("\n🤖 CodeGlia AI Analysis:\n", ai_explanation.get("explanation", ""))
        print("-" * 40)
        issue_text = vuln["issue_text"]
        meta = vulnerabilities[idx].get('extra', {}).get('metadata', {})
        # --- Extract CWE ID (dynamic lookup) ---
        cwe_id = "N/A"
        cwe_match = re.search(r"CWE-\d+", issue_text or "")
        if not cwe_match:
            more_info = vulnerabilities[idx].get('more_info', '')
            if isinstance(more_info, str):
                cwe_match = re.search(r"CWE-\d+", more_info)
        # Try references in metadata for CWE
        if not cwe_match and isinstance(meta, dict):
            refs = meta.get('references', [])
            if isinstance(refs, list):
                for ref in refs:
                    m = re.search(r"CWE-\d+", str(ref))
                    if m:
                        cwe_match = m
                        break
        if cwe_match:
            cwe_id = cwe_match.group(0)
        else:
            lowered = (issue_text or "").lower()
            found = False
            for k, v in CWE_MAP.items():
                if k in lowered:
                    cwe_id = v
                    found = True
                    break
            if not found:
                cwe_id = "N/A"
        cwe_title = ""
        if cwe_id and cwe_id != "N/A" and re.match(r"CWE-\d+", cwe_id):
            cwe_info = get_cwe_details(cwe_id)
            cwe_title = cwe_info.get("title", "")
        # --- Extract CVE ID and crosslink ---
        cve_id = "N/A"
        cve_match = re.search(r"CVE-\d{4}-\d+", issue_text or "")
        if not cve_match:
            more_info = vulnerabilities[idx].get('more_info', '')
            if isinstance(more_info, str):
                cve_match = re.search(r"CVE-\d{4}-\d+", more_info)
        # Try references in metadata for CVE
        if not cve_match and isinstance(meta, dict):
            refs = meta.get('references', [])
            if isinstance(refs, list):
                for ref in refs:
                    m = re.search(r"CVE-\d{4}-\d+", str(ref))
                    if m:
                        cve_match = m
                        break
        if cve_match:
            cve_id = cve_match.group(0)
        else:
            mapped_cve = None
            # Only use CVE_MAP_BY_CWE now
            if cwe_id and cwe_id != "N/A":
                cve_list = CVE_MAP_BY_CWE.get(cwe_id, [])
                if cve_list:
                    def choose_cve_by_most_recent(cves):
                        try:
                            return sorted(cves, key=lambda c: int(c.split('-')[1]), reverse=True)[0]
                        except Exception:
                            return cves[0]
                    mapped_cve = choose_cve_by_most_recent(cve_list)
            if mapped_cve:
                cve_id = mapped_cve
            else:
                if cwe_id and cwe_id != "N/A":
                    live_cves = get_cve_for_cwe(cwe_id)
                    if live_cves:
                        cve_id = random.choice(live_cves)
                if cve_id == "N/A":
                    lowered_issue = (issue_text or "").lower()
                    for k in CVE_MAP.keys():
                        if k.lower() in lowered_issue:
                            cve_id = k
                            break
        if cve_id == "N/A" and cwe_id and cwe_id != "N/A":
            cve_id = "No known CVE mapping available"
        elif cve_id == "N/A":
            cve_id = "No known CVE mapping available"
        if cwe_id == "N/A":
            pass
        elif not re.match(r"CWE-\d+", cwe_id):
            cwe_id = "None detected (review rule metadata)"
        vuln["cwe"] = cwe_id
        vuln["cwe_title"] = cwe_title
        vuln["cve"] = cve_id
        vuln["ai_explanation"] = ai_explanation
        vulns.append(vuln)
    # Deduplicate by (file, line, issue_text), collapse to highest severity if duplicates
    unique = {}
    for v in vulns:
        def normalize_text(s):
            if not s:
                return ""
            s = s.lower()
            s = re.sub(r'\s+', ' ', s)
            s = re.sub(r'[^a-z0-9 ]', '', s)
            return s.strip()

        key = (v.get("file"), v.get("line"), normalize_text(v.get("issue_text")), v.get("cwe"))
        if key not in unique:
            unique[key] = v
        else:
            old = unique[key]
            sev_rank = {"low": 1, "medium": 2, "high": 3}
            if sev_rank.get((v.get("severity") or "medium").lower(), 2) > sev_rank.get((old.get("severity") or "medium").lower(), 2):
                unique[key] = v
    vulns = list(unique.values())
    return vulns


def parse_semgrep_results(file_path: str):
    """Parses Semgrep JSON report, returns list of structured vulnerabilities with AI explanations.

    ✅ Updated for Stage 1 readiness:
      - Handles missing snippets (auto file extract)
      - Prioritizes Semgrep metadata CWE first
      - Longest-key-first CWE keyword mapping
      - Deterministic CVE selection (most recent)
      - Safe get_cwe_details() handling
      - Robust deduplication (file + line + normalized issue + CWE)
      - Transparent debug tracing
    """
    import re, random, typing

    print("\n S E M G R E P  R E S U L T S \n" + "=" * 40)
    vulns = []

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"⚠️ Semgrep results file not found at: {file_path}")
        return []
    except json.JSONDecodeError:
        print(f"⚠️ Could not decode JSON from the Semgrep file: {file_path}")
        return []

    vulnerabilities = data.get('results', [])
    if not vulnerabilities:
        print("✅ No vulnerabilities found by Semgrep.")
        return []

    # --- Helper functions ---
    def normalize_text(s):
        if not s:
            return ""
        s = s.lower()
        s = re.sub(r'\s+', ' ', s)
        s = re.sub(r'[^a-z0-9 ]', '', s)
        return s.strip()

    def choose_cve_by_most_recent(cves):
        try:
            def year(c):
                parts = c.split('-')
                return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            sorted_list = sorted(cves, key=lambda c: (year(c), c), reverse=True)
            return sorted_list[0]
        except Exception:
            return cves[0] if cves else "No known CVE mapping available"

    sorted_cwe_keys = sorted(CWE_MAP.keys(), key=lambda x: -len(x))  # longest-key-first

    # --- Batch AI preparation ---
    summaries, vuln_objs = [], []

    for i, vuln in enumerate(vulnerabilities, 1):
        path = vuln.get('path') or vuln.get('extra', {}).get('metadata', {}).get('path')
        start = vuln.get('start', {}) or vuln.get('extra', {}).get('start', {})
        line = start.get('line') if isinstance(start, dict) else None
        extra = vuln.get('extra', {})
        message = extra.get('message') or vuln.get('check_id')

        # --- Extract code safely ---
        code = ''
        try:
            candidate = extra.get('lines')
            if isinstance(candidate, str) and candidate.strip():
                code = candidate.strip()
        except Exception:
            code = ''

        if not code:
            snippet = extra.get('snippet')
            if isinstance(snippet, str) and snippet.strip():
                code = snippet.strip()
            elif isinstance(snippet, dict) and 'lines' in snippet:
                try:
                    code = "\n".join([l.get('code', '') for l in snippet['lines'] if isinstance(l, dict)])
                except Exception:
                    code = ''

        # --- Handle missing snippet via source extraction ---
        if not code or (isinstance(code, str) and code.strip().lower() == 'requires login'):
            file_path_local = path
            start_line = start.get('line') if isinstance(start, dict) else None
            end_line = start.get('end') or vuln.get('end', {}).get('line') if isinstance(start, dict) else None
            extracted = extract_code_from_file(file_path_local, start_line, end_line, ctx=2)
            if extracted:
                code = extracted

        print(f"--- Semgrep Vulnerability #{i} ---")
        print(f"  File: {path}")
        print(f"  Line: {line}")
        print(f"  Issue: {message}")
        if code:
            print("  Code:\n" + code)

        summaries.append(
            f"Source: Semgrep\nFile: {path}\nLine: {line}\nIssue: {message}\nCode:\n{code}\n"
        )
        vuln_objs.append({
            "scanner": "Semgrep",
            "file": path,
            "line": line,
            "severity": extra.get('severity', ''),
            "issue_text": message,
            "code": code,
            "raw_extra": extra,
            "raw_vuln": vuln,
        })

    # --- Batch AI analysis ---
    ai_results = []
    for i in range(0, len(summaries), 10):
        batch = summaries[i:i+10]
        ai_results.extend(get_ai_analysis_batch(batch))

    # --- Attach CWE/CVE mappings ---
    for idx, vuln in enumerate(vuln_objs):
        ai_explanation = ai_results[idx] if idx < len(ai_results) else {"explanation": "", "fix": ""}
        message = vuln["issue_text"]
        extra = vuln.get("raw_extra", {}) or {}
        raw_vuln = vuln.get("raw_vuln", {}) or {}
        meta = raw_vuln.get('extra', {}).get('metadata', {}) if isinstance(raw_vuln, dict) else {}

        # --- Step 1: Prefer Semgrep metadata CWE ---
        cwe_id = "N/A"
        semgrep_meta_cwe = extra.get("metadata", {}).get("cwe")
        if semgrep_meta_cwe:
            if isinstance(semgrep_meta_cwe, list):
                for entry in semgrep_meta_cwe:
                    m = re.search(r"CWE[-_:]?(\d+)", str(entry), re.IGNORECASE)
                    if m:
                        cwe_id = f"CWE-{m.group(1)}"
                        break
            elif isinstance(semgrep_meta_cwe, str):
                m = re.search(r"CWE[-_:]?(\d+)", semgrep_meta_cwe, re.IGNORECASE)
                if m:
                    cwe_id = f"CWE-{m.group(1)}"

        # --- Step 2: If not found, look in message or metadata refs ---
        if cwe_id == "N/A":
            cwe_match = re.search(r"CWE[-_:]?(\d+)", message or "", re.IGNORECASE)
            if cwe_match:
                cwe_id = f"CWE-{cwe_match.group(1)}"
            else:
                refs = meta.get('references', []) if isinstance(meta, dict) else []
                if isinstance(refs, list):
                    for ref in refs:
                        m = re.search(r"CWE[-_:]?(\d+)", str(ref), re.IGNORECASE)
                        if m:
                            cwe_id = f"CWE-{m.group(1)}"
                            break

        # --- Step 3: Longest-key-first fallback keyword match ---
        if cwe_id == "N/A":
            lowered = (message or "").lower()
            for key in sorted_cwe_keys:
                if key in lowered:
                    cwe_id = CWE_MAP[key]
                    break

        # --- Step 4: Normalize CWE format ---
        if isinstance(cwe_id, str):
            cwe_id = cwe_id.strip().upper().replace("_", "-").replace("CWE:", "CWE-")
            mnorm = re.match(r"CWE-(\d+)", cwe_id)
            if mnorm:
                cwe_id = f"CWE-{mnorm.group(1)}"
            else:
                cwe_id = "N/A"

        # --- Step 5: Get CWE title safely ---
        cwe_title = ""
        if cwe_id != "N/A":
            try:
                cwe_info = get_cwe_details(cwe_id) or {}
                cwe_title = cwe_info.get("title", "")
            except Exception:
                cwe_title = ""

        # --- Step 6: Deterministic CVE mapping ---
        cve_id = "No known CVE mapping available"
        cve_match = re.search(r"CVE-\d{4}-\d+", message or "")
        if not cve_match and isinstance(meta, dict):
            refs = meta.get('references', [])
            if isinstance(refs, list):
                for ref in refs:
                    m = re.search(r"CVE-\d{4}-\d+", str(ref))
                    if m:
                        cve_match = m
                        break

        if cve_match:
            cve_id = cve_match.group(0)
        elif cwe_id != "N/A":
            cve_list = CVE_MAP_BY_CWE.get(cwe_id, [])
            if cve_list:
                cve_id = choose_cve_by_most_recent(cve_list)
            else:
                try:
                    live_cves = get_cve_for_cwe(cwe_id)
                    if live_cves:
                        cve_id = choose_cve_by_most_recent(live_cves)
                except Exception:
                    pass

        print(f"[DEBUG] CWE={cwe_id} ({cwe_title}) | CVE={cve_id}")

        vuln["cwe"] = cwe_id
        vuln["cwe_title"] = cwe_title
        vuln["cve"] = cve_id
        vuln["ai_explanation"] = ai_explanation
        vulns.append(vuln)

    # --- Deduplicate final results ---
    unique = {}
    for v in vulns:
        key = (v.get("file"), v.get("line"), normalize_text(v.get("issue_text")), v.get("cwe"))
        if key not in unique:
            unique[key] = v
        else:
            sev_rank = {"low": 1, "medium": 2, "high": 3}
            if sev_rank.get((v.get("severity") or "medium").lower(), 2) > \
               sev_rank.get((unique[key].get("severity") or "medium").lower(), 2):
                unique[key] = v

    return list(unique.values())

# --- NEW FUNCTIONS ---

def generate_summary(vulns):
    """Compute trust score and counts of high/medium/low issues from vulnerabilities list using nonlinear scaling and repo size awareness."""
    import math
    import os
    counts = {"high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = (v.get("severity") or "medium").lower()
        if sev == "high" or sev == "error":
            counts["high"] += 1
        elif sev == "medium":
            counts["medium"] += 1
        elif sev in ("warning", "low", "info"):
            counts["low"] += 1
    h, m, l = counts["high"], counts["medium"], counts["low"]
    total_issues = h + m + l
    # --- Repo size factor: count all .py files recursively ---
    file_count = 0
    for root, dirs, files in os.walk("."):
        for f in files:
            if f.endswith(".py"):
                file_count += 1
    # New trust score formula (more balanced):
    # size_factor = 1 + math.log1p(file_count / 1000) * 0.5
    # base_score = 100
    # penalty_high = 5 * h
    # penalty_medium = 2 * m
    # penalty_low = 0.5 * l
    # total_penalty = penalty_high + penalty_medium + penalty_low
    # trust_score = base_score - (total_penalty * size_factor)
    # if trust_score < 5:
    #     trust_score = 5
    # trust_score_final = round(trust_score)
    size_factor = 1 + math.log1p(file_count / 1000) * 0.5 if file_count > 0 else 1.0
    base_score = 100
    penalty_high = 5 * h
    penalty_medium = 2 * m
    penalty_low = 0.5 * l
    total_penalty = penalty_high + penalty_medium + penalty_low
    trust_score = base_score - (total_penalty * size_factor)
    if trust_score < 5:
        trust_score = 5
    trust_score_final = round(trust_score)
    trust_explanation = {
        "base_score": base_score,
        "penalty_high": penalty_high,
        "penalty_medium": penalty_medium,
        "penalty_low": penalty_low,
        "file_count": file_count,
        "size_factor": round(size_factor, 2),
        "final_trust_score": trust_score_final,
        "explanation": (
            f"Trust Score = {base_score} - ((5*{h} + 2*{m} + 0.5*{l}) * {round(size_factor,2)}) "
            f"= {base_score} - ({total_penalty:.2f} * {round(size_factor,2)}) = {trust_score:.2f} (rounded to {trust_score_final}). "
            f"Repo size = {file_count} Python files, size_factor = 1 + log1p(file_count / 1000) * 0.5 = {round(size_factor,2)}."
        )
    }
    return {
        "trust_score": trust_score_final,
        "counts": counts,
        "total_issues": total_issues,
        "trust_explanation": trust_explanation
    }
    

def save_json_report(report, filename="scan_report.json"):

    output_dir = "output"

    os.makedirs(output_dir, exist_ok=True)

    # add metadata timestamp

    if 'scan_metadata' not in report:

        report['scan_metadata'] = {}

    report['scan_metadata']['timestamp'] = datetime.now().isoformat()

    with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as f:

        json.dump(report, f, indent=2)

    print(f"\n📄 Saved JSON scan report to {os.path.join(output_dir, filename)}")



def save_html_report(report, filename="scan_report.html"):

    """Generate a simple, clean HTML report from the scan results."""

    output_dir = "output"

    os.makedirs(output_dir, exist_ok=True)

    html = []

    html.append("<!DOCTYPE html>")

    html.append("<html><head><meta charset='utf-8'><title>Scan Report</title>")

    html.append("""<style>
        body { font-family: Arial, sans-serif; margin: 2em; background: #f9f9f9; }
        .score { font-size: 2em; margin-bottom: 0.5em; }
        .counts { margin-bottom: 1em; }
        .metadata { font-size: 0.95em; color: #555; margin-bottom: 1em; }
        .vuln { background: #fff; border: 1px solid #ccc; border-radius: 8px; margin: 1em 0; padding: 1em; }
        .severity-high { color: #d32f2f; font-weight: bold; }
        .severity-medium { color: #fbc02d; font-weight: bold; }
        .severity-low { color: #388e3c; font-weight: bold; }
        pre { background: #f0f0f0; padding: 0.5em; border-radius: 4px; white-space: pre-wrap; }
        .ai-explanation { background: #e3f2fd; padding: 0.75em; border-radius: 6px; margin: 0.6em 0 0.4em 0; font-size: 1.05em; border-left: 5px solid #1976d2; }
        .ai-fix { background: #dcedc8; padding: 0.75em; border-radius: 6px; margin: 0.4em 0 0.7em 0; white-space: pre-wrap; font-family: monospace; border-left: 5px solid #558b2f; font-size: 1.05em; }
        .vuln-label { font-weight: bold; color: #333; }
        .vuln-section { margin-bottom: 0.5em; }
    </style></head><body>""")

    html.append("<h1>CodeGlia Scan Report</h1>")
    # Metadata section
    html.append("<div class='metadata'>")
    html.append(f"<b>Scan Date:</b> {report.get('scan_metadata', {}).get('timestamp', '')}<br>")
    html.append("<b>Tool Versions:</b> Bandit / Semgrep (latest)<br>")
    html.append("<b>CWE/CVE Mode:</b> Dynamic via MITRE + NVD (cached)</div><br>")
    html.append(f"<div class='score'>Trust Score: <b>{report['summary']['trust_score']}</b></div>")
    # --- Trust explanation details block ---
    trust_expl = report['summary'].get('trust_explanation', {})
    html.append("<details style='margin-bottom:1em'><summary>Trust Score Computation Details</summary>")
    html.append("<div style='font-size:1em;padding:0.4em 0 0.4em 1em;'>")
    html.append(f"<b>Base Score:</b> {trust_expl.get('base_score','')}<br>")
    html.append(f"<b>Penalty (High):</b> {trust_expl.get('penalty_high','')}<br>")
    html.append(f"<b>Penalty (Medium):</b> {trust_expl.get('penalty_medium','')}<br>")
    html.append(f"<b>Penalty (Low):</b> {trust_expl.get('penalty_low','')}<br>")
    html.append(f"<b>Python File Count:</b> {trust_expl.get('file_count','')}<br>")
    html.append(f"<b>Size Factor:</b> {trust_expl.get('size_factor','')}<br>")
    html.append(f"<b>Final Trust Score:</b> {trust_expl.get('final_trust_score','')}<br>")
    html.append(f"<b>Formula:</b> {trust_expl.get('explanation','')}<br>")
    html.append("</div></details>")
    c = report['summary']['counts']
    html.append("<div class='counts'>")
    html.append(f"High: <span class='severity-high'>{c['high']}</span> &nbsp; ")
    html.append(f"Medium: <span class='severity-medium'>{c['medium']}</span> &nbsp; ")
    html.append(f"Low: <span class='severity-low'>{c['low']}</span> &nbsp; ")
    html.append(f"Total Issues: <b>{report['summary']['total_issues']}</b>")
    html.append("</div>")
    html.append("<hr>")
    # --- Group duplicates before rendering ---
    grouped = {}
    for v in report["vulnerabilities"]:
        key = (v.get("file"), v.get("cwe"), v.get("cve"), v.get("issue_text"))
        grouped.setdefault(key, []).append(v)
    for key, group in grouped.items():
        v = group[0]
        count = len(group)
        occ_label = f" (×{count} occurrences)" if count > 1 else ""
        # Fallback severity handling
        sev = (v.get("severity") or "").lower()
        if not sev:
            sev = "medium"
        display_sev = sev
        if sev == "error":
            display_sev = "high"
        elif sev == "warning" or sev == "info":
            display_sev = "low"
        sev_class = f"severity-{display_sev}" if display_sev in ("high", "medium", "low") else ""
        html.append("<div class='vuln'>")
        html.append(f"<div class='vuln-section'><span class='vuln-label'>File:</span> {v.get('file', '')}{occ_label} &nbsp; <span class='vuln-label'>Line:</span> {v.get('line', '')} &nbsp; <span class='{sev_class}'>{display_sev.upper()}</span></div>")
        # CWE and CVE with links and titles (CWE title always beside ID, always fetch title if missing)
        cwe = v.get("cwe", "N/A")
        cwe_title = v.get("cwe_title", "")
        import re
        if cwe != "N/A" and re.match(r"CWE-(\d+)", cwe):
            num = re.search(r"\d+", cwe).group(0)
            # Always ensure title is loaded for this CWE
            if not cwe_title:
                cwe_info = get_cwe_details(cwe)
                cwe_title = cwe_info.get("title", "")
            title_text = f": {cwe_title}" if cwe_title else ""
            html.append(f"<div class='vuln-section'><span class='vuln-label'>CWE:</span> <a href='https://cwe.mitre.org/data/definitions/{num}.html' target='_blank'>{cwe}{title_text}</a></div>")
        else:
            html.append(f"<div class='vuln-section'><span class='vuln-label'>CWE:</span> {cwe}</div>")
        # --- OWASP Top 10 Section ---
        owasp_label = OWASP_TOP10_MAP.get(cwe, "")
        if owasp_label:
            html.append(f"<div class='vuln-section'><span class='vuln-label'>OWASP Top 10:</span> {owasp_label}</div>")
        cve = v.get("cve", "N/A")
        if cve != "N/A" and cve != "No known CVE mapping available" and re.match(r"CVE-\d{4}-\d+", cve):
            html.append(f"<div class='vuln-section'><span class='vuln-label'>CVE:</span> <a href='https://nvd.nist.gov/vuln/detail/{cve}' target='_blank'>{cve}</a></div>")
        else:
            html.append(f"<div class='vuln-section'><span class='vuln-label'>CVE:</span> {cve}</div>")
        # CWE-CVE crosslinking: show some related CVEs for this CWE (if present)
        if cwe != "N/A" and re.match(r"CWE-\d+", cwe):
            from sys import modules as _modules
            cross_cves = []
            cross_cves = CVE_MAP_BY_CWE.get(cwe, [])
            if not cross_cves:
                cross_cves = get_cve_for_cwe(cwe)
            if cross_cves:
                crosslinks = []
                for cvc in cross_cves[:3]:
                    crosslinks.append(f"<a href='https://nvd.nist.gov/vuln/detail/{cvc}' target='_blank'>{cvc}</a>")
                html.append(f"<div class='vuln-section'><span class='vuln-label'>Related CVEs for {cwe}:</span> {' | '.join(crosslinks)}</div>")
        html.append(f"<div class='vuln-section'><span class='vuln-label'>Issue:</span> {v.get('issue_text','')}</div>")
        if v.get("code"):
            code_html = str(v['code']).replace('<', '&lt;')
            html.append(f"<div class='vuln-section'><span class='vuln-label'>Code:</span><pre>{code_html}</pre></div>")
        ai_exp = v.get("ai_explanation")
        if isinstance(ai_exp, dict):
            explanation = ai_exp.get("explanation", "")
            fix = ai_exp.get("fix", "")
            explanation_html = explanation.replace('<', '&lt;').replace('\n', '<br>')
            fix_html = fix.replace('<', '&lt;')
            if explanation_html.strip():
                html.append(f"<div class='ai-explanation'><b>Explanation:</b><br>{explanation_html}</div>")
            if fix_html.strip():
                html.append(f"<div class='ai-fix'><b>Secure Fix:</b><br>{fix_html}</div>")
        elif isinstance(ai_exp, str) and ai_exp.strip():
            explanation_html = ai_exp.replace('<', '&lt;').replace('\n', '<br>')
            html.append(f"<div class='ai-explanation'><b>Explanation:</b><br>{explanation_html}</div>")
        html.append("</div>")

    html.append("</body></html>")

    with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as f:

        f.write("\n".join(html))

    print(f"📄 Saved HTML scan report to {os.path.join(output_dir, filename)}")



if __name__ == "__main__":

    # Look for outputs in common folders (allows 'scans' or 'outputs')

    candidates = ['scans', 'outputs', '.']

    bandit_file = None

    semgrep_file = None

    for d in candidates:

        b = os.path.join(d, 'bandit_output.json')

        s = os.path.join(d, 'semgrep_output.json')

        if bandit_file is None and os.path.exists(b):

            bandit_file = b

        if semgrep_file is None and os.path.exists(s):

            semgrep_file = s


    # If neither was found, default to the 'scans' filenames so user sees the expected path in errors

    if bandit_file is None:

        bandit_file = os.path.join('scans', 'bandit_output.json')

    if semgrep_file is None:

        semgrep_file = os.path.join('scans', 'semgrep_output.json')


    print(f"Using Bandit file: {bandit_file}")

    print(f"Using Semgrep file: {semgrep_file}\n")


    bandit_vulns = parse_bandit_results(bandit_file)

    print("\n" * 2)

    semgrep_vulns = parse_semgrep_results(semgrep_file)


    all_vulns = []

    if bandit_vulns:

        all_vulns.extend(bandit_vulns)

    if semgrep_vulns:

        all_vulns.extend(semgrep_vulns)


    # Normalize severity for all_vulns before summary generation
    for v in all_vulns:
        sev = (v.get("severity") or "").lower().strip()
        if sev in ("error", "critical"):
            v["severity"] = "high"
        elif sev in ("warn", "warning", "info", "low"):
            v["severity"] = "low"
        elif sev not in ("high", "medium", "low"):
            v["severity"] = "medium"
    summary = generate_summary(all_vulns)
    report = {
        "summary": summary,
        "vulnerabilities": all_vulns
    }
    save_json_report(report)
    save_html_report(report)