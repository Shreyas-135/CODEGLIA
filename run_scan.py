#!/usr/bin/env python3
"""
run_scan.py - Master script for the CodeGlia project.
"""
import os
import subprocess
import shutil
import sys
import time
import json
import argparse

# --- Configuration ---
DATASETS_DIR = "datasets"
SCANS_DIR = "scans"
OUTPUT_DIR = "output"
PARSER_SCRIPT = "parse_results.py"

def clean_directory(dir_path):
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)
    os.makedirs(dir_path, exist_ok=True)

def run_command(command_list, description):
    print(f"\n🚀 Running {description}...")
    try:
        result = subprocess.run(command_list, capture_output=True, text=True)
        if result.returncode != 0 and result.stderr:
            # Check for the specific "config does not exist" error
            if "does not exist" in result.stderr or "failed to load rules" in result.stderr.lower():
                 return False # Treat this as a fatal error
            
        return True
    except Exception as e:
        print(f"❌ FATAL ERROR during {description}: {e}")
        return False

def count_lines_of_code(directory, extensions=None):
    total_lines = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if extensions is None or any(file.lower().endswith(ext) for ext in extensions):
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        total_lines += len(lines)
                except Exception:
                    pass
    return total_lines

def detect_local_semgrep_rule_packs():
    """
    Detect locally installed Semgrep rule packs under ~/.semgrep/rules.
    Return a set of available rule pack names (e.g. 'p/c', 'p/javascript').
    """
    local_rules_dir = os.path.expanduser("~/.semgrep/rules")
    available_packs = set()
    if os.path.isdir(local_rules_dir):
        for entry in os.listdir(local_rules_dir):
            entry_path = os.path.join(local_rules_dir, entry)
            if os.path.isdir(entry_path):
                # Include only directories starting with 'p/' or similar pattern
                if entry.startswith("p/") or entry.startswith("p-") or entry.startswith("p_"):
                    available_packs.add(entry)
                else:
                    # Sometimes the directory might be just 'c', 'javascript' etc.
                    # We add 'p/' prefix for consistency
                    available_packs.add(f"p/{entry}")
    return available_packs

def build_semgrep_command(target_dataset_dir):
    """
    Build the semgrep command using locally available rule directories
    within the 'semgrep-rules' folder inside the current working directory.
    """
    local_rules_base = "/app/semgrep-rules"

    # Define the specific rule folders to include
    local_rule_paths = [
        os.path.join(local_rules_base, "python"),
        os.path.join(local_rules_base, "java"),
        os.path.join(local_rules_base, "javascript"),
        os.path.join(local_rules_base, "php"),
        os.path.join(local_rules_base, "ruby"),
        os.path.join(local_rules_base, "perl"),
        os.path.join(local_rules_base, "c"),
        os.path.join(local_rules_base, "csharp"),
        os.path.join(local_rules_base, "generic"),
        os.path.join(local_rules_base, "security-audit"),
    ]

    # Build the semgrep command
    semgrep_command = [
        "semgrep",
        "--json",
        "--output", os.path.join(SCANS_DIR, "semgrep_output.json"),
    ]

    for path in local_rule_paths:
        if os.path.isdir(path):
            semgrep_command.extend(["--config", path])


    semgrep_command.append(target_dataset_dir)


    return semgrep_command, [os.path.basename(p) for p in local_rule_paths if os.path.isdir(p)]

def write_minimal_performance(elapsed_time):
    performance_data = {
        "total_lines_of_code": 0,
        "elapsed_scan_time_seconds": elapsed_time
    }
    performance_path = os.path.join(OUTPUT_DIR, "performance.json")
    try:
        with open(performance_path, 'w') as perf_file:
            json.dump(performance_data, perf_file, indent=4)
    except Exception as e:
        print(f"⚠️ Warning: Could not write minimal performance metrics: {e}")

def run_llm_scan(target_dir, backend="gemini", model=None):
    """
    Run LLM-based vulnerability scan.
    
    Returns:
        Tuple of (success: bool, vulnerabilities: list, stats: dict)
    """
    try:
        from llm_scanner import LLMScanner
        
        print(f"\n🚀 Running LLM Scan ({backend}" + (f"/{model}" if model else "") + ")...")
        print(f"📊 Processing files in {target_dir}...")
        
        scanner = LLMScanner(backend=backend, model=model)
        vulnerabilities, stats = scanner.scan_directory(target_dir)
        
        print(f"✅ LLM completed in {stats['elapsed_time']:.2f}s ({stats['total_issues']} vulnerabilities found)")
        
        # Save LLM results to scans directory
        llm_output_path = os.path.join(SCANS_DIR, "llm_output.json")
        with open(llm_output_path, 'w', encoding='utf-8') as f:
            json.dump({
                "results": vulnerabilities,
                "statistics": stats
            }, f, indent=2)
        
        return True, vulnerabilities, stats
    except ImportError as e:
        print(f"⚠️ LLM scanner dependencies not installed: {e}")
        return False, [], {}
    except ValueError as e:
        print(f"⚠️ LLM scanner configuration error: {e}")
        return False, [], {}
    except Exception as e:
        print(f"⚠️ LLM scan failed: {e}")
        import traceback
        traceback.print_exc()
        return False, [], {}

def parse_cli_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="CodeGlia Vulnerability Scanner")
    parser.add_argument("target_dir", nargs="?", default=DATASETS_DIR,
                       help="Target directory to scan (default: datasets)")
    parser.add_argument("--enable-llm", action="store_true",
                       help="Enable LLM scanning")
    parser.add_argument("--llm-backend", choices=["gemini", "openai", "ollama"],
                       default=None, help="LLM backend to use")
    parser.add_argument("--llm-model", type=str, default=None,
                       help="LLM model name")
    parser.add_argument("--static-only", action="store_true",
                       help="Run only static analyzers (Bandit + Semgrep)")
    parser.add_argument("--llm-only", action="store_true",
                       help="Run only LLM scanner")
    parser.add_argument("--compare", action="store_true",
                       help="Run all scanners and generate comparison report")
    return parser.parse_args()

if __name__ == "__main__":
    print("===== Starting CodeGlia Workflow =====")
    
    # Parse command-line arguments
    args = parse_cli_arguments()
    target_dataset_dir = args.target_dir
    
    # Check environment variables for LLM configuration
    llm_enabled_env = os.getenv("LLM_ENABLED", "false").lower() == "true"
    llm_backend_env = os.getenv("LLM_BACKEND", "gemini").lower()
    llm_model_env = os.getenv("LLM_MODEL")
    
    # Determine LLM settings (CLI args override env vars)
    enable_llm = args.enable_llm or args.compare or llm_enabled_env
    llm_backend = args.llm_backend or llm_backend_env
    llm_model = args.llm_model or llm_model_env
    
    # Determine which scanners to run
    run_static = not args.llm_only
    run_llm = (enable_llm or args.llm_only) and not args.static_only
    
    print(f"📁 Using target dataset directory: {target_dataset_dir}")
    if run_llm:
        print(f"🤖 LLM scanning enabled (backend: {llm_backend}, model: {llm_model or 'default'})")
    
    clean_directory(SCANS_DIR)
    clean_directory(OUTPUT_DIR)
    
    # Count total lines of code before scanning
    loc_extensions = ['.py', '.js', '.java', '.php', '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.pl']
    total_loc = count_lines_of_code(target_dataset_dir, loc_extensions)
    
    # Performance tracking
    performance_data = {
        "total_lines_of_code": total_loc,
        "scanners": {},
        "comparison": {},
        "elapsed_scan_time_seconds": 0
    }
    
    overall_start_time = time.time()
    
    # --- Run Static Analyzers ---
    bandit_success = True
    semgrep_success = True
    bandit_time = 0
    semgrep_time = 0
    bandit_vulns = 0
    semgrep_vulns = 0
    
    if run_static:
        # Bandit scan
        bandit_output_path = os.path.join(SCANS_DIR, "bandit_output.json")
        bandit_command = ["bandit", "-r", target_dataset_dir, "-f", "json", "-o", bandit_output_path]
        
        print("\n🚀 Running Bandit Scan (Python)...")
        bandit_start = time.time()
        bandit_success = run_command(bandit_command, "Bandit Scan (Python)")
        bandit_time = time.time() - bandit_start
        
        # Count Bandit vulnerabilities
        if os.path.exists(bandit_output_path):
            try:
                with open(bandit_output_path, 'r', encoding='utf-8') as f:
                    bandit_results = json.load(f)
                    bandit_vulns = len(bandit_results.get("results", []))
            except Exception:
                pass
        
        print(f"✅ Bandit completed in {bandit_time:.2f}s ({bandit_vulns} vulnerabilities found)")
        
        performance_data["scanners"]["bandit"] = {
            "time_seconds": round(bandit_time, 2),
            "vulnerabilities_found": bandit_vulns,
            "lines_per_second": round(total_loc / bandit_time, 1) if bandit_time > 0 else 0
        }
        
        # Semgrep scan
        semgrep_command, loaded_packs_summary = build_semgrep_command(target_dataset_dir)
        
        print("\n📦 Semgrep rule packs to be used:")
        for pack in loaded_packs_summary:
            print(f"   - {pack}")
        
        print("\n🚀 Running Semgrep Scan (Multi-language)...")
        semgrep_start = time.time()
        semgrep_success = run_command(semgrep_command, "Semgrep Scan (Multi-language)")
        semgrep_time = time.time() - semgrep_start
        
        # Count Semgrep vulnerabilities
        semgrep_output_file = os.path.join(SCANS_DIR, "semgrep_output.json")
        if os.path.exists(semgrep_output_file):
            try:
                with open(semgrep_output_file, 'r', encoding='utf-8') as f:
                    semgrep_results = json.load(f)
                    semgrep_vulns = len(semgrep_results.get("results", []))
            except Exception:
                pass
        
        print(f"✅ Semgrep completed in {semgrep_time:.2f}s ({semgrep_vulns} vulnerabilities found)")
        
        performance_data["scanners"]["semgrep"] = {
            "time_seconds": round(semgrep_time, 2),
            "vulnerabilities_found": semgrep_vulns,
            "lines_per_second": round(total_loc / semgrep_time, 1) if semgrep_time > 0 else 0
        }
    
    # --- Run LLM Scanner ---
    llm_success = True
    llm_time = 0
    llm_vulns = 0
    llm_files_analyzed = 0
    
    if run_llm:
        llm_start = time.time()
        llm_success, llm_vulnerabilities, llm_stats = run_llm_scan(
            target_dataset_dir,
            backend=llm_backend,
            model=llm_model
        )
        llm_time = time.time() - llm_start
        
        if llm_success:
            llm_vulns = llm_stats.get("total_issues", 0)
            llm_files_analyzed = llm_stats.get("files_scanned", 0)
            
            performance_data["scanners"]["llm"] = {
                "time_seconds": round(llm_time, 2),
                "vulnerabilities_found": llm_vulns,
                "lines_per_second": round(total_loc / llm_time, 1) if llm_time > 0 else 0,
                "model": llm_stats.get("model", llm_model or "unknown"),
                "files_analyzed": llm_files_analyzed,
                "backend": llm_backend
            }
    
    # --- Performance Comparison ---
    if run_static and run_llm and bandit_success and semgrep_success and llm_success:
        static_total_time = bandit_time + semgrep_time
        llm_total_time = llm_time
        
        print("\n📊 Performance Comparison:")
        print(f"   Static Analysis Total: {static_total_time:.1f}s")
        print(f"   LLM Analysis Total: {llm_total_time:.1f}s")
        
        if llm_total_time > static_total_time:
            factor = llm_total_time / static_total_time if static_total_time > 0 else 0
            diff = llm_total_time - static_total_time
            print(f"   LLM is {factor:.1f}x slower (+{diff:.1f}s)")
        else:
            factor = static_total_time / llm_total_time if llm_total_time > 0 else 0
            diff = static_total_time - llm_total_time
            print(f"   LLM is {factor:.1f}x faster (-{diff:.1f}s)")
        
        print(f"\n   Throughput:")
        if bandit_time > 0:
            print(f"   - Bandit: {total_loc / bandit_time:.0f} lines/sec")
        if semgrep_time > 0:
            print(f"   - Semgrep: {total_loc / semgrep_time:.0f} lines/sec")
        if llm_time > 0:
            print(f"   - LLM: {total_loc / llm_time:.0f} lines/sec")
        
        performance_data["comparison"] = {
            "static_total_time": round(static_total_time, 2),
            "llm_total_time": round(llm_total_time, 2),
            "llm_slower_by_factor": round(llm_total_time / static_total_time, 2) if static_total_time > 0 else 0,
            "llm_slower_by_seconds": round(llm_total_time - static_total_time, 2)
        }
    
    # Check if scans failed
    if run_static and (not bandit_success or not semgrep_success):
        elapsed_time = time.time() - overall_start_time
        print("\n⚠️ One or more static scans failed. Writing minimal performance metrics and exiting gracefully.")
        write_minimal_performance(elapsed_time)
        sys.exit(1)
    
    # --- Run Parser ---
    if run_static or run_llm:
        parser_command = [sys.executable, PARSER_SCRIPT]
        if run_llm:
            parser_command.append("--include-llm")
        
        parser_success = run_command(parser_command, "Parsing and AI Analysis")
        print("[DEBUG] Parsing step completed with status:", parser_success)
        print(f"[DEBUG] Checking output directory: {os.path.abspath(OUTPUT_DIR)}")
        print("[DEBUG] Files currently in output folder:", os.listdir(OUTPUT_DIR) if os.path.exists(OUTPUT_DIR) else "Output directory not found.")
        
        if not parser_success:
            elapsed_time = time.time() - overall_start_time
            print("\n⚠️ Parsing and AI Analysis failed. Writing minimal performance metrics and exiting gracefully.")
            write_minimal_performance(elapsed_time)
            sys.exit(1)
    
    elapsed_time = time.time() - overall_start_time
    performance_data["elapsed_scan_time_seconds"] = round(elapsed_time, 2)
    
    # Write performance metrics to output/performance.json
    performance_path = os.path.join(OUTPUT_DIR, "performance.json")
    try:
        with open(performance_path, 'w') as perf_file:
            json.dump(performance_data, perf_file, indent=4)
        print(f"\n📄 Performance metrics saved to {performance_path}")
    except Exception as e:
        print(f"⚠️ Warning: Could not write performance metrics: {e}")
    
    print("[DEBUG] Verifying generated report files before completion...")
    for f in ["scan_report.html", "scan_report.json", "performance.json"]:
        fpath = os.path.join(OUTPUT_DIR, f)
        print(f"   {f}: {'✅ FOUND' if os.path.exists(fpath) else '❌ MISSING'}")
    
    print("\n===== CodeGlia Workflow Finished Successfully! =====")
    print(f"📄 Final reports are in the '{OUTPUT_DIR}' directory.")
    print(f"📊 Performance Metrics:")
    print(f"   - Total lines of code scanned: {total_loc}")
    print(f"   - Total scan time (seconds): {elapsed_time:.2f}")