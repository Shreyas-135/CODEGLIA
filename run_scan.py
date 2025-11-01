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

if __name__ == "__main__":
    print("===== Starting CodeGlia Workflow =====")

    # Handle optional dataset directory from CLI argument
    target_dataset_dir = DATASETS_DIR
    if len(sys.argv) > 1:
        target_dataset_dir = sys.argv[1]
        print(f"📁 Using target dataset directory: {target_dataset_dir}")

    clean_directory(SCANS_DIR)
    clean_directory(OUTPUT_DIR)

    bandit_output_path = os.path.join(SCANS_DIR, "bandit_output.json")

    bandit_command = ["bandit", "-r", target_dataset_dir, "-f", "json", "-o", bandit_output_path]

    semgrep_command, loaded_packs_summary = build_semgrep_command(target_dataset_dir)

    parser_command = [sys.executable, PARSER_SCRIPT]

    # Count total lines of code before scanning
    # Extensions for Stage-I languages
    loc_extensions = ['.py', '.js', '.java', '.php', '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.pl']
    total_loc = count_lines_of_code(target_dataset_dir, loc_extensions)

    print("\n📦 Semgrep rule packs to be used:")
    for pack in loaded_packs_summary:
        print(f"   - {pack}")

    start_time = time.time()

    bandit_success = run_command(bandit_command, "Bandit Scan (Python)")
    semgrep_success = run_command(semgrep_command, "Semgrep Scan (Multi-language)")

    # After Semgrep scan, check number of vulnerabilities found
    semgrep_output_file = os.path.join(SCANS_DIR, "semgrep_output.json")
    if os.path.exists(semgrep_output_file):
        try:
            with open(semgrep_output_file, 'r', encoding='utf-8') as f:
                semgrep_results = json.load(f)
                vulnerabilities_count = len(semgrep_results.get("results", []))
                print(f"\n🔍 Semgrep found {vulnerabilities_count} vulnerabilities/issues.")
        except Exception as e:
            print(f"⚠️ Warning: Could not read Semgrep output file to count vulnerabilities: {e}")
    else:
        print(f"\n⚠️ Warning: Semgrep output file '{semgrep_output_file}' not found to count vulnerabilities.")

    if not bandit_success or not semgrep_success:
        elapsed_time = time.time() - start_time
        print("\n⚠️ One or more scans failed. Writing minimal performance metrics and exiting gracefully.")
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR, exist_ok=True)
        write_minimal_performance(elapsed_time)
        sys.exit(1)

    parser_success = run_command(parser_command, "Parsing and AI Analysis")
    print("[DEBUG] Parsing step completed with status:", parser_success)
    print(f"[DEBUG] Checking output directory: {os.path.abspath(OUTPUT_DIR)}")
    print("[DEBUG] Files currently in output folder:", os.listdir(OUTPUT_DIR) if os.path.exists(OUTPUT_DIR) else "Output directory not found.")
    if not parser_success:
        elapsed_time = time.time() - start_time
        print("\n⚠️ Parsing and AI Analysis failed. Writing minimal performance metrics and exiting gracefully.")
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR, exist_ok=True)
        write_minimal_performance(elapsed_time)
        sys.exit(1)

    elapsed_time = time.time() - start_time

    # Write performance metrics to output/performance.json
    performance_data = {
        "total_lines_of_code": total_loc,
        "elapsed_scan_time_seconds": elapsed_time
    }
    performance_path = os.path.join(OUTPUT_DIR, "performance.json")
    try:
        with open(performance_path, 'w') as perf_file:
            json.dump(performance_data, perf_file, indent=4)
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