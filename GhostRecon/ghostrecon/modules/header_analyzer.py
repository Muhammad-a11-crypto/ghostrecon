"""
Header Analyzer Module
Inspects HTTP response headers for missing or misconfigured security headers.
"""

from typing import Tuple, List, Dict, Any


class HeaderAnalyzer:
    """
    Analyzes HTTP response headers against security best practices.
    Checks for presence, value correctness, and dangerous configurations.
    """

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "High",
            "cwe": "CWE-319",
            "description": (
                "HTTP Strict Transport Security (HSTS) is missing. "
                "This allows downgrade attacks and cookie hijacking over HTTP."
            ),
            "recommendation": (
                "Add: Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload"
            ),
        },
        "X-Frame-Options": {
            "severity": "Medium",
            "cwe": "CWE-1021",
            "description": (
                "X-Frame-Options is missing. The page may be vulnerable to "
                "Clickjacking attacks by embedding it in an iframe."
            ),
            "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        },
        "X-Content-Type-Options": {
            "severity": "Low",
            "cwe": "CWE-430",
            "description": (
                "X-Content-Type-Options is missing. Browsers may MIME-sniff "
                "responses, enabling content injection attacks."
            ),
            "recommendation": "Add: X-Content-Type-Options: nosniff",
        },
        "Content-Security-Policy": {
            "severity": "Medium",
            "cwe": "CWE-693",
            "description": (
                "Content Security Policy (CSP) is absent. Without CSP, "
                "the application is more susceptible to XSS and data injection."
            ),
            "recommendation": (
                "Define a strict CSP policy. Start with: "
                "Content-Security-Policy: default-src 'self'"
            ),
        },
        "Referrer-Policy": {
            "severity": "Low",
            "cwe": "CWE-200",
            "description": (
                "Referrer-Policy is not set. Sensitive URL parameters "
                "may be leaked to third-party sites via the Referer header."
            ),
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "severity": "Low",
            "cwe": "CWE-693",
            "description": (
                "Permissions-Policy (formerly Feature-Policy) is absent. "
                "Browser features like geolocation or camera may be exploitable."
            ),
            "recommendation": (
                "Add Permissions-Policy to restrict browser features: "
                "Permissions-Policy: geolocation=(), microphone=()"
            ),
        },
        "X-XSS-Protection": {
            "severity": "Info",
            "cwe": "CWE-80",
            "description": (
                "X-XSS-Protection is not set. While modern browsers ignore "
                "this header, older ones benefit from it."
            ),
            "recommendation": "Add: X-XSS-Protection: 1; mode=block (legacy support)",
        },
    }

    DANGEROUS_HEADERS = {
        "Server": {
            "severity": "Low",
            "description": "Server header exposes technology version information.",
            "recommendation": "Suppress or genericize the Server header.",
            "cwe": "CWE-200",
        },
        "X-Powered-By": {
            "severity": "Low",
            "description": "X-Powered-By reveals backend framework/language details.",
            "recommendation": "Remove the X-Powered-By header entirely.",
            "cwe": "CWE-200",
        },
        "X-AspNet-Version": {
            "severity": "Low",
            "description": "X-AspNet-Version exposes .NET framework version.",
            "recommendation": "Disable via <httpRuntime enableVersionHeader='false'/>",
            "cwe": "CWE-200",
        },
        "X-AspNetMvc-Version": {
            "severity": "Low",
            "description": "X-AspNetMvc-Version reveals ASP.NET MVC version.",
            "recommendation": "Remove in Global.asax: MvcHandler.DisableMvcResponseHeader = true",
            "cwe": "CWE-200",
        },
    }

    def analyze(self, response, target, session, timeout) -> Tuple[List, Dict[str, Any]]:
        findings = []
        headers = dict(response.headers)
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for missing security headers
        for header, meta in self.SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title=f"Missing Security Header: {header}",
                    severity=meta["severity"],
                    category="HTTP Headers",
                    description=meta["description"],
                    recommendation=meta["recommendation"],
                    evidence=f"Header '{header}' not present in response",
                    cwe=meta["cwe"],
                ))

        # Check for dangerous/informational headers
        for header, meta in self.DANGEROUS_HEADERS.items():
            if header.lower() in headers_lower:
                value = headers_lower[header.lower()]
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title=f"Information Disclosure via Header: {header}",
                    severity=meta["severity"],
                    category="Information Disclosure",
                    description=meta["description"],
                    recommendation=meta["recommendation"],
                    evidence=f"{header}: {value}",
                    cwe=meta["cwe"],
                ))

        # Check CSP quality if present
        csp_value = headers_lower.get("content-security-policy", "")
        if csp_value:
            self._check_csp_quality(csp_value, findings)

        # Check HSTS quality if present
        hsts_value = headers_lower.get("strict-transport-security", "")
        if hsts_value:
            self._check_hsts_quality(hsts_value, findings)

        # Check for CORS misconfiguration
        self._check_cors(headers_lower, response, findings)

        module_data = {
            "all_headers": dict(response.headers),
            "security_headers_present": [
                h for h in self.SECURITY_HEADERS
                if h.lower() in headers_lower
            ],
            "security_headers_missing": [
                h for h in self.SECURITY_HEADERS
                if h.lower() not in headers_lower
            ],
        }

        return findings, module_data

    def _check_csp_quality(self, csp: str, findings: list):
        from ghostrecon.engine import Finding
        csp_lower = csp.lower()

        if "unsafe-inline" in csp_lower:
            findings.append(Finding(
                title="Weak CSP: 'unsafe-inline' Directive",
                severity="Medium",
                category="HTTP Headers",
                description=(
                    "The Content Security Policy uses 'unsafe-inline', which "
                    "significantly weakens XSS protection."
                ),
                recommendation="Replace 'unsafe-inline' with nonces or hashes.",
                evidence=f"CSP: {csp[:200]}",
                cwe="CWE-693",
            ))

        if "unsafe-eval" in csp_lower:
            findings.append(Finding(
                title="Weak CSP: 'unsafe-eval' Directive",
                severity="Medium",
                category="HTTP Headers",
                description=(
                    "The CSP allows 'unsafe-eval', permitting eval() and "
                    "similar constructs which enable code injection."
                ),
                recommendation="Remove 'unsafe-eval'. Refactor code to avoid eval().",
                evidence=f"CSP: {csp[:200]}",
                cwe="CWE-693",
            ))

        if "* " in csp_lower or csp_lower.startswith("*"):
            findings.append(Finding(
                title="Weak CSP: Wildcard Source",
                severity="High",
                category="HTTP Headers",
                description="CSP uses a wildcard (*) as a source, allowing any origin.",
                recommendation="Specify explicit trusted origins instead of wildcards.",
                evidence=f"CSP: {csp[:200]}",
                cwe="CWE-693",
            ))

    def _check_hsts_quality(self, hsts: str, findings: list):
        from ghostrecon.engine import Finding
        hsts_lower = hsts.lower()

        try:
            max_age = int(
                hsts_lower.split("max-age=")[1].split(";")[0].strip()
            )
            if max_age < 31536000:
                findings.append(Finding(
                    title="Weak HSTS: Short max-age Duration",
                    severity="Low",
                    category="HTTP Headers",
                    description=(
                        f"HSTS max-age is set to {max_age}s (< 1 year). "
                        "Short durations reduce protection against downgrade attacks."
                    ),
                    recommendation="Set max-age to at least 31536000 (1 year).",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    cwe="CWE-319",
                ))
        except (IndexError, ValueError):
            pass

        if "includesubdomains" not in hsts_lower:
            findings.append(Finding(
                title="HSTS Missing includeSubDomains",
                severity="Info",
                category="HTTP Headers",
                description="HSTS does not include the includeSubDomains directive.",
                recommendation="Add includeSubDomains to HSTS header.",
                evidence=f"Strict-Transport-Security: {hsts}",
                cwe="CWE-319",
            ))

    def _check_cors(self, headers_lower: dict, response, findings: list):
        from ghostrecon.engine import Finding
        acao = headers_lower.get("access-control-allow-origin", "")
        if acao == "*":
            findings.append(Finding(
                title="CORS: Wildcard Allow-Origin",
                severity="Medium",
                category="CORS Misconfiguration",
                description=(
                    "Access-Control-Allow-Origin is set to '*', allowing any "
                    "origin to read cross-origin responses. This can expose "
                    "sensitive data if combined with credentials."
                ),
                recommendation=(
                    "Restrict ACAO to specific trusted origins. "
                    "Never use '*' with Access-Control-Allow-Credentials: true."
                ),
                evidence="Access-Control-Allow-Origin: *",
                cwe="CWE-942",
            ))

        acac = headers_lower.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(Finding(
                title="CORS: Critical Misconfiguration (Wildcard + Credentials)",
                severity="Critical",
                category="CORS Misconfiguration",
                description=(
                    "ACAO is '*' AND Allow-Credentials is 'true'. This is a "
                    "critical CORS misconfiguration that allows credential theft."
                ),
                recommendation="Never combine wildcard origin with credentials.",
                evidence=f"ACAO: * | Allow-Credentials: {acac}",
                cwe="CWE-942",
            ))
