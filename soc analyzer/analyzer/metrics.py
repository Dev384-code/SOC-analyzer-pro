from collections.abc import Iterable
from collections import defaultdict


def evaluate_findings(findings: Iterable[dict], labels: Iterable[dict], total_cases: int | None = None) -> dict:
    findings = list(findings)
    labels = list(labels)
    predicted = {(item.get("line"), item["type"]) for item in findings}
    expected = {(int(item["line"]), item["type"]) for item in labels}
    true_positive = len(predicted & expected)
    false_positive = len(predicted - expected)
    false_negative = len(expected - predicted)
    precision = true_positive / len(predicted) if predicted else 0.0
    recall = true_positive / len(expected) if expected else 0.0
    negative_cases = max(0, (total_cases or len(predicted)) - len(expected))
    false_positive_rate = false_positive / negative_cases if negative_cases else 0.0
    result = {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "false_positive_rate": round(false_positive_rate, 3),
    }
    predicted_by_type = defaultdict(set)
    expected_by_type = defaultdict(set)
    for line, alert_type in predicted:
        predicted_by_type[alert_type].add(line)
    for line, alert_type in expected:
        expected_by_type[alert_type].add(line)
    result["by_type"] = {}
    for alert_type in sorted(set(predicted_by_type) | set(expected_by_type)):
        actual = predicted_by_type[alert_type]
        expected_lines = expected_by_type[alert_type]
        true_positive = len(actual & expected_lines)
        false_positive = len(actual - expected_lines)
        false_negative = len(expected_lines - actual)
        negative_cases = max(0, (total_cases or len(actual)) - len(expected_lines))
        result["by_type"][alert_type] = {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "support": len(expected_lines),
            "precision": round(true_positive / len(actual), 3) if actual else 0.0,
            "recall": round(true_positive / len(expected_lines), 3) if expected_lines else 0.0,
            "false_positive_rate": round(false_positive / negative_cases, 3) if negative_cases else 0.0,
        }
    return result
