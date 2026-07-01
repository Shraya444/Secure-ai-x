"""
SecureAI X — Risk Engine
Converts a list of findings into an overall security score / posture.
"""

from typing import List, Dict

SEVERITY_DEDUCTION = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
}

# Diminishing returns so 3 criticals don't push score negative in a boring way
def _diminishing(count: int, base: int) -> int:
    total = 0
    penalty = base
    for _ in range(count):
        total += penalty
        penalty = max(4, int(penalty * 0.55))
    return total


def calculate_risk(findings: List[Dict]) -> Dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f["severity"] if isinstance(f, dict) else f.severity
        if sev in counts:
            counts[sev] += 1

    score = 100
    for sev, count in counts.items():
        score -= _diminishing(count, SEVERITY_DEDUCTION[sev])
    score = max(0, min(100, score))

    if score >= 90:
        posture, label = "safe", "Excellent"
    elif score >= 75:
        posture, label = "moderate-low", "Good"
    elif score >= 50:
        posture, label = "moderate", "Moderate Risk"
    elif score >= 25:
        posture, label = "high", "High Risk"
    else:
        posture, label = "critical", "Critical Risk"

    return {
        "score": score,
        "posture": posture,
        "label": label,
        "counts": counts,
        "total_findings": sum(counts.values()),
    }
