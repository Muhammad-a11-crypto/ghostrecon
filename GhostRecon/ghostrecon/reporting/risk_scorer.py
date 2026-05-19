"""
Risk Scorer Module
Calculates a 0-100 risk score from findings and correlation deltas.
"""

from typing import Tuple


class RiskScorer:
    """
    Translates vulnerability findings into a normalized 0-100 risk score
    with a qualitative risk label.

    Scoring weights per severity:
        Critical  → 20 pts each (max 3 counted)
        High      → 10 pts each (max 5 counted)
        Medium    →  5 pts each (max 6 counted)
        Low       →  2 pts each (max 10 counted)
        Info      →  0 pts
    """

    WEIGHTS = {
        "Critical": 20,
        "High": 10,
        "Medium": 5,
        "Low": 2,
        "Info": 0,
    }

    CAPS = {
        "Critical": 3,
        "High": 5,
        "Medium": 6,
        "Low": 10,
        "Info": 0,
    }

    LABELS = [
        (0, 10, "Minimal"),
        (11, 25, "Low"),
        (26, 45, "Medium"),
        (46, 65, "High"),
        (66, 80, "Very High"),
        (81, 100, "Critical"),
    ]

    def calculate(self, findings: list, correlation_delta: int = 0) -> Tuple[int, str]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1

        score = 0
        for severity, weight in self.WEIGHTS.items():
            capped_count = min(counts[severity], self.CAPS[severity])
            score += capped_count * weight

        # Add correlation intelligence bonus
        score += correlation_delta

        # Clamp to 0-100
        score = max(0, min(100, score))

        label = "Unknown"
        for low, high, lbl in self.LABELS:
            if low <= score <= high:
                label = lbl
                break

        return score, label
