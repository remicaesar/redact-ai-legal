#!/usr/bin/env python3
"""Evaluate scanner accuracy against a manually labeled mini-gold dataset."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from legal_analyzer.extraction import extract_text
from legal_analyzer.privacy import analyze_privacy

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_LABELS = PROJECT_DIR / "gold" / "gold_labels.example.json"


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").casefold().strip()


def label_matches_finding(label: dict, finding: dict) -> bool:
    if label.get("category") and label["category"] != finding["category"]:
        return False
    label_text = normalize(label.get("text", ""))
    sample = normalize(finding.get("sample", ""))
    if not label_text:
        return False
    return label_text in sample or sample in label_text


def score_findings(required_labels: list[dict], findings: list[dict]) -> tuple[set[int], list[dict], list[dict]]:
    """Score findings against gold labels at the entity level.

    A label is covered if ANY finding matches it; a finding is a true positive if
    it matches ANY label. Scoring deliberately does not pair each label with a
    single finding: the gold set labels an entity once, while a real document
    mentions it repeatedly ("Mehmet Yılmaz" in the party clause and again in the
    signature block). One-to-one pairing scored those later, correct mentions as
    false positives and understated precision.

    Returns (matched_label_indexes, false_negatives, false_positives).
    """
    matched_label_indexes: set[int] = set()
    matched_finding_indexes: set[int] = set()
    false_negatives: list[dict] = []

    for label_index, label in enumerate(required_labels):
        for finding_index, finding in enumerate(findings):
            if label_matches_finding(label, finding):
                matched_label_indexes.add(label_index)
                matched_finding_indexes.add(finding_index)
        if label_index not in matched_label_indexes:
            false_negatives.append(label)

    false_positives = [
        finding
        for finding_index, finding in enumerate(findings)
        if finding_index not in matched_finding_indexes
    ]
    return matched_label_indexes, false_negatives, false_positives


def audit_document(item: dict, labels_path: Path) -> dict:
    doc_path = Path(item["path"])
    if not doc_path.is_absolute():
        doc_path = (labels_path.parent / doc_path).resolve()

    text, warning = extract_text(doc_path)
    privacy = analyze_privacy(doc_path.name, text, warning)
    findings = privacy["risk_map"]
    labels = item.get("labels", [])
    required_labels = [label for label in labels if label.get("required", True)]

    matched_label_indexes, false_negatives, false_positives = score_findings(required_labels, findings)

    expected_risk = item.get("expected_residual_risk")
    actual_risk = privacy["residual_risk"]["level"]
    false_low = bool(actual_risk == "Low" and (false_negatives or expected_risk in {"Medium", "High", "Unknown"}))

    result = {
        "id": item.get("id", doc_path.name),
        "path": str(doc_path),
        "expected_residual_risk": expected_risk,
        "actual_residual_risk": actual_risk,
        "extraction_status": privacy["extraction_status"]["status"],
        "external_llm_readiness": privacy["external_llm_readiness"],
        "labels": len(required_labels),
        "findings": len(findings),
        "true_positive_labels": len(matched_label_indexes),
        "false_negative_count": len(false_negatives),
        "false_positive_count": len(false_positives),
        "false_low": false_low,
        "false_negatives": false_negatives,
        "false_positives": [
            {
                "category": finding["category"],
                "risk": finding["risk"],
                "sample": finding["sample"],
            }
            for finding in false_positives[:50]
        ],
    }
    if item.get("ocr_text"):
        result["post_ocr"] = audit_text_against_labels(
            doc_path.name,
            item["ocr_text"],
            required_labels,
            expected_risk,
            ocr_status="accepted",
        )
    return result


def audit_text_against_labels(
    filename: str,
    text: str,
    required_labels: list[dict],
    expected_risk: str | None,
    ocr_status: str = "not_required",
) -> dict:
    privacy = analyze_privacy(filename, text, None, ocr_status=ocr_status)
    findings = privacy["risk_map"]
    matched_label_indexes, false_negatives, false_positives = score_findings(required_labels, findings)
    actual_risk = privacy["residual_risk"]["level"]
    false_low = bool(actual_risk == "Low" and (false_negatives or expected_risk in {"Medium", "High", "Unknown"}))
    return {
        "actual_residual_risk": actual_risk,
        "extraction_status": privacy["extraction_status"]["status"],
        "ocr_status": ocr_status,
        "external_llm_readiness": privacy["external_llm_readiness"],
        "labels": len(required_labels),
        "findings": len(findings),
        "true_positive_labels": len(matched_label_indexes),
        "false_negative_count": len(false_negatives),
        "false_positive_count": len(false_positives),
        "false_low": false_low,
    }


def safe_divide(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def run_audit(labels_path: Path) -> dict:
    spec = json.loads(labels_path.read_text(encoding="utf-8"))
    documents = spec.get("documents", [])
    results = [audit_document(item, labels_path) for item in documents]

    total_labels = sum(result["labels"] for result in results)
    total_findings = sum(result["findings"] for result in results)
    true_positive_labels = sum(result["true_positive_labels"] for result in results)
    false_negative_count = sum(result["false_negative_count"] for result in results)
    false_positive_count = sum(result["false_positive_count"] for result in results)
    false_low_documents = [result for result in results if result["false_low"]]
    post_ocr_results = [result["post_ocr"] for result in results if result.get("post_ocr")]
    post_ocr_false_low_documents = [result for result in post_ocr_results if result["false_low"]]

    metrics = {
        "recall": safe_divide(true_positive_labels, total_labels),
        "precision": safe_divide(total_findings - false_positive_count, total_findings),
        "total_gold_labels": total_labels,
        "total_findings": total_findings,
        "true_positive_labels": true_positive_labels,
        "false_negative_count": false_negative_count,
        "false_positive_count": false_positive_count,
        "false_low_count": len(false_low_documents),
        "false_low_goal": 0,
    }
    if post_ocr_results:
        post_ocr_labels = sum(result["labels"] for result in post_ocr_results)
        post_ocr_findings = sum(result["findings"] for result in post_ocr_results)
        post_ocr_true_positive_labels = sum(result["true_positive_labels"] for result in post_ocr_results)
        post_ocr_false_positive_count = sum(result["false_positive_count"] for result in post_ocr_results)
        metrics["post_ocr"] = {
            "documents": len(post_ocr_results),
            "recall": safe_divide(post_ocr_true_positive_labels, post_ocr_labels),
            "precision": safe_divide(post_ocr_findings - post_ocr_false_positive_count, post_ocr_findings),
            "false_low_count": len(post_ocr_false_low_documents),
            "false_low_goal": 0,
        }

    return {
        "input": {
            "labels_path": str(labels_path),
            "documents": len(documents),
            "note": spec.get("note", ""),
        },
        "metrics": metrics,
        "documents": results,
        "recommendation": (
            "Do not treat Low as externally safe unless false_low_count is 0 and recall has been reviewed "
            "for names, client/counterparty identifiers, addresses, IDs, case numbers, signatures/stamps, "
            "financial data, confidential terms, and contextual identifiers."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--output", type=Path, default=PROJECT_DIR / "accuracy_report.json")
    args = parser.parse_args()

    if not args.labels.exists():
        raise SystemExit(f"Gold label file not found: {args.labels}")

    report = run_audit(args.labels)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Accuracy report written: {args.output}")


if __name__ == "__main__":
    main()
