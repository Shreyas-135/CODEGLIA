#!/usr/bin/env python3
"""
generate_ps01_excel.py - Generates the official PS-01 submission Excel file for CodeGlia.
Usage:
    python generate_ps01_excel.py --startup_name <Startup_Name> [--report_paths <report1.json> <report2.json> <report3.json>]
"""
import sys
import json
import os
import glob
import openpyxl
import argparse

def load_scan_report(report_path):
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Handle CodeGlia standard format
    if isinstance(data, dict):
        if "vulnerabilities" in data:
            return data["vulnerabilities"]
        elif "findings" in data:
            return data["findings"]
        elif "results" in data:
            return data["results"]
        elif "data" in data and isinstance(data["data"], list):
            return data["data"]
        else:
            possible_list = [v for v in data.values() if isinstance(v, list)]
            if possible_list:
                return possible_list[0]

    elif isinstance(data, list):
        return data

    print(f"⚠️ Unrecognized report schema in {report_path}; returning empty list.")
    return []

def generate_excel(findings, startup_name, f1, output_excel):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Stage 1 Submission"

    headers = [
        "Ser",
        "Name of Application Tested",
        "Language",
        "Vulnerability Found",
        "CVE",
        "File Name",
        "Line of Code",
        "Detection Accuracy (F1)"
    ]
    ws.append(headers)

    app_category_map = {
        "Software Stack_1": "Standalone Software Application",
        "Software Stack_2": "Web Application",
        "Software Stack_4": "Mobile Application"
    }

    for idx, item in enumerate(findings, start=1):
        # Compose stack prefix for file name
        stack_name = item.get("stack_name", "")
        file_name = os.path.basename(item.get("file", ""))
        language = file_name.split(".")[-1].upper() if file_name else ""
        vuln = item.get("issue_text", item.get("cwe_title", item.get("cwe", "N/A")))
        cve = item.get("cve", "N/A")
        line = item.get("line", "")
        file_field = f"{stack_name}/{file_name}" if stack_name else file_name
        app_category = app_category_map.get(stack_name, "General Software Application")
        ws.append([
            idx,
            f"{app_category}",
            language,
            vuln,
            cve,
            file_field,
            line,
            f"{f1:.3f}" if f1 is not None else ""
        ])

    for col in ws.columns:
        max_len = max(len(str(cell.value)) if cell.value is not None else 0 for cell in col)
        ws.column_dimensions[col[0].column_letter].width = max_len + 2

    wb.save(output_excel)
    print(f"✅ Excel generated: {output_excel}")

def main():
    parser = argparse.ArgumentParser(description="Generate PS-01 Excel submission for CodeGlia.")
    parser.add_argument("--startup_name", required=True, help="Name of the Startup")
    parser.add_argument("--report_paths", nargs=3, required=False, help="Paths to up to three JSON report files")
    args = parser.parse_args()

    if args.report_paths is None:
        # Auto-detect up to three most recent JSON files in report/
        json_files = sorted(glob.glob("report/*.json"), key=os.path.getmtime, reverse=True)
        if not json_files:
            print("⚠️ No JSON report files found in report/ directory.")
            sys.exit(1)
        if len(json_files) < 3:
            print(f"⚠️ Only found {len(json_files)} JSON report file(s) in report/ directory; continuing with available files.")
        args.report_paths = json_files[:3]
        print(f"Auto-detected report files: {', '.join(args.report_paths)}")

    all_findings = []
    stack_map = {
        "stack1": "Software Stack_1",
        "stack2": "Software Stack_2",
        "stack4": "Software Stack_4"
    }
    for report_path in args.report_paths:
        if not os.path.isfile(report_path):
            print(f"⚠️ Report file not found: {report_path}")
            sys.exit(1)
        findings = load_scan_report(report_path)
        # Derive stack name from file name
        base = os.path.basename(report_path).lower()
        stack_name = ""
        for k, v in stack_map.items():
            if k in base:
                stack_name = v
                break
        # Add stack_name to each finding
        for finding in findings:
            finding["stack_name"] = stack_name
        all_findings.extend(findings)

    f1 = None

    output_excel = f"GC_PS_01_{args.startup_name}.xlsx"
    print(f"Using report files: {', '.join(args.report_paths)}")
    generate_excel(all_findings, args.startup_name, f1, output_excel)

if __name__ == "__main__":
    main()