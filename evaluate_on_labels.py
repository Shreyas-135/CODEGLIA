#!/usr/bin/env python3
"""
evaluate_on_labels.py - Computes Precision, Recall, and F1 score for CodeGlia results.
Usage:
    python evaluate_on_labels.py ground_truth.csv output/scan_report.json

The script expects:
  - ground_truth.csv : CSV with columns [file_name, line_no, cwe_id]
  - scan_report.json : CodeGlia's output file containing detected vulnerabilities.
"""
import sys
import csv
import json
import os
from collections import defaultdict

def load_ground_truth(csv_path):
    truth = defaultdict(set)
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            file_name = os.path.basename(row['file_name']).strip()
            line_no = int(row['line_no'])
            cwe = row.get('cwe_id', '').strip()
            truth[file_name].add((line_no, cwe))
    return truth

def load_predictions(json_path):
    preds = defaultdict(set)
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        for item in data.get('findings', data):  # handle list or dict schema
            file_name = os.path.basename(item.get('file', ''))
            line_no = item.get('line', 0)
            cwe = item.get('cwe', '')
            if isinstance(line_no, str) and line_no.isdigit():
                line_no = int(line_no)
            preds[file_name].add((line_no, cwe))
    return preds

def match_vulnerabilities(truth, preds, tolerance=2):
    TP = 0
    FP = 0
    FN = 0
    matched_truth = set()
    
    for file_name, pred_set in preds.items():
        truth_set = truth.get(file_name, set())
        for (pline, pcwe) in pred_set:
            matched = False
            for (tline, tcwe) in truth_set:
                if abs(pline - tline) <= tolerance and (pcwe == tcwe or not pcwe or not tcwe):
                    matched = True
                    matched_truth.add((file_name, tline, tcwe))
                    break
            if matched:
                TP += 1
            else:
                FP += 1

    for file_name, truth_set in truth.items():
        for (tline, tcwe) in truth_set:
            if (file_name, tline, tcwe) not in matched_truth:
                FN += 1

    return TP, FP, FN

def compute_metrics(TP, FP, FN):
    precision = TP / (TP + FP) if TP + FP else 0.0
    recall = TP / (TP + FN) if TP + FN else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1

def main():
    if len(sys.argv) != 3:
        print("Usage: python evaluate_on_labels.py ground_truth.csv output/scan_report.json")
        sys.exit(1)

    truth_path = sys.argv[1]
    preds_path = sys.argv[2]

    truth = load_ground_truth(truth_path)
    preds = load_predictions(preds_path)

    TP, FP, FN = match_vulnerabilities(truth, preds)
    precision, recall, f1 = compute_metrics(TP, FP, FN)

    print("===== Evaluation Summary =====")
    print(f"True Positives (TP): {TP}")
    print(f"False Positives (FP): {FP}")
    print(f"False Negatives (FN): {FN}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    print(f"F1 Score: {f1:.3f}")

    os.makedirs('evaluation', exist_ok=True)
    summary_path = os.path.join('evaluation', 'evaluation_summary.txt')
    with open(summary_path, 'w') as f:
        f.write(f"Precision: {precision:.3f}\n")
        f.write(f"Recall: {recall:.3f}\n")
        f.write(f"F1 Score: {f1:.3f}\n")

    print(f"\n📊 Results saved to {summary_path}")

if __name__ == '__main__':
    main()