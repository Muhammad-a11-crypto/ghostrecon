"""
GhostRecon — Passive Web Intelligence & Security Correlation Engine
Core engine: orchestrates all analysis modules
Author: 0xdzubair
"""

import requests
import time
import warnings
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional

from .modules.header_analyzer import HeaderAnalyzer
from .modules.cookie_inspector import CookieInspector
from .modules.html_parser import HTMLParser
from .modules.js_analyzer import JSAnalyzer
from .modules.tech_fingerprinter import TechFingerprinter
from .modules.param_detector import ParamDetector
from .correlation.correlator import VulnerabilityCorrelator
from .reporting.risk_scorer import RiskScorer


class ScanTarget:
    """Represents a scan target with metadata"""

    def __init__(self, url: str):
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            parsed = urlparse(url)
        self.raw_url  = url
        self.scheme   = parsed.scheme
        self.host     = parsed.netloc
        self.path     = parsed.path or "/"
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    def __str__(self):
        return self.raw_url


class ScanResult:
    """Aggregated result from all scan modules"""

    def __init__(self, target: ScanTarget):
        self.target                = target
        self.scan_time             = datetime.utcnow().isoformat() + "Z"
        self.duration_seconds      = 0
        self.findings: list        = []
        self.raw_data: dict        = {}
        self.risk_score: int       = 0
        self.risk_label: str       = "Unknown"
        self.correlation_insights: list = []
        self.tech_stack: list      = []
        self.summary: dict         = {}

    def to_dict(self) -> dict:
        return {
            "meta": {
                "tool":             "GhostRecon — Passive Web Intelligence Engine",
                "version":          "2.0.0",
                "author":           "0xdzubair",
                "github":           "https://github.com/0xdzubair/ghostrecon",
                "linkedin":         "https://linkedin.com/in/0xdzubair",
                "target":           str(self.target),
                "scan_time":        self.scan_time,
                "duration_seconds": round(self.duration_seconds, 2),
            },
            "risk": {
                "score": self.risk_score,
                "label": self.risk_label,
            },
            "summary":               self.summary,
            "tech_stack":            self.tech_stack,
            "findings":              [f.to_dict() for f in self.findings],
            "correlation_insights":  self.correlation_insights,
        }


class Finding:
    """A single vulnerability or security observation"""

    SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"]

    def __init__(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        recommendation: str,
        evidence: Optional[str] = None,
        cwe: Optional[str] = None,
        location: Optional[str] = None,
    ):
        self.title          = title
        self.severity       = severity if severity in self.SEVERITIES else "Info"
        self.category       = category
        self.description    = description
        self.recommendation = recommendation
        self.evidence       = evidence
        self.cwe            = cwe
        self.location       = location   # NEW: where this was found

    def to_dict(self) -> dict:
        return {
            "title":          self.title,
            "severity":       self.severity,
            "category":       self.category,
            "description":    self.description,
            "recommendation": self.recommendation,
            "evidence":       self.evidence,
            "cwe":            self.cwe,
            "location":       self.location,
        }


class GhostReconEngine:
    """
    Main orchestration engine for GhostRecon.
    Coordinates all passive scanning modules and produces correlated results.
    No exploits. No payloads. No noise.
    """

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; GhostRecon/2.0; "
            "+https://github.com/0xdzubair/ghostrecon)"
        ),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
        "DNT":             "1",
    }

    # Keep old name as alias so existing code still works
    SWVCEEngine = None  # set below

    def __init__(self, timeout: int = 15, follow_redirects: bool = True):
        self.timeout          = timeout
        self.follow_redirects = follow_redirects
        self.session          = requests.Session()
        self.session.headers.update(self.HEADERS)

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url, timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=False,
            )
        except requests.exceptions.SSLError:
            try:
                return self.session.get(
                    url, timeout=self.timeout,
                    allow_redirects=self.follow_redirects, verify=False
                )
            except Exception:
                return None
        except Exception:
            return None

    def scan(self, url: str) -> ScanResult:
        warnings.filterwarnings("ignore")

        target = ScanTarget(url)
        result = ScanResult(target)
        start  = time.time()

        print(f"\n  \033[90m[*]\033[0m Fetching target: \033[96m{target.raw_url}\033[0m")
        response = self._fetch(target.raw_url)

        if response is None:
            result.findings.append(
                Finding(
                    title="Target Unreachable",
                    severity="Critical",
                    category="Connectivity",
                    description="Could not establish a connection to the target URL.",
                    recommendation="Verify the URL is correct and the target is online.",
                    location=target.raw_url,
                )
            )
            result.duration_seconds = time.time() - start
            return result

        print(f"  \033[92m[+]\033[0m Response: HTTP {response.status_code} "
              f"({len(response.content):,} bytes)  "
              f"\033[90m{response.url}\033[0m")

        modules = [
            ("Headers",     HeaderAnalyzer()),
            ("Cookies",     CookieInspector()),
            ("HTML",        HTMLParser()),
            ("JavaScript",  JSAnalyzer()),
            ("Fingerprint", TechFingerprinter()),
            ("Parameters",  ParamDetector()),
        ]

        raw_data = {"response": response}

        for name, module in modules:
            print(f"  \033[90m[~]\033[0m Analyzing \033[96m{name}\033[0m ...")
            try:
                module_findings, module_data = module.analyze(
                    response, target, self.session, self.timeout
                )
                # Inject location into every finding that doesn't have one
                for f in module_findings:
                    if not getattr(f, "location", None):
                        f.location = response.url
                result.findings.extend(module_findings)
                raw_data[name.lower()] = module_data
            except Exception as e:
                print(f"  \033[91m[!]\033[0m Module {name} error: {e}")

        result.raw_data = raw_data

        fp_data = raw_data.get("fingerprint", {})
        result.tech_stack = fp_data.get("technologies", [])

        print("  \033[90m[~]\033[0m Running correlation engine ...")
        correlator = VulnerabilityCorrelator()
        insights, score_delta = correlator.correlate(result.findings, raw_data)
        result.correlation_insights = insights

        scorer = RiskScorer()
        result.risk_score, result.risk_label = scorer.calculate(result.findings, score_delta)

        sev_counts = {s: 0 for s in Finding.SEVERITIES}
        for f in result.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        result.summary = {
            "total_findings":       len(result.findings),
            "by_severity":          sev_counts,
            "correlation_insights": len(result.correlation_insights),
        }

        result.duration_seconds = time.time() - start
        print(f"  \033[92m[+]\033[0m Scan complete in \033[1m{result.duration_seconds:.2f}s\033[0m")
        return result


# Backward-compat alias
SWVCEEngine = GhostReconEngine
