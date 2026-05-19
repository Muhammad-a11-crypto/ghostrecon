"""
Parameter Detector Module
Detects hidden parameters, URL query parameters, and suggests fuzzing candidates.
"""

import re
from typing import Tuple, List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup


class ParamDetector:
    """
    Detects:
    - URL query parameters already present
    - Hidden form fields
    - Parameters discovered in JavaScript
    - Suggests common hidden parameter names
    - Identifies potentially dangerous parameter patterns
    """

    # High-value parameter names that may indicate vulnerabilities
    DANGEROUS_PARAM_PATTERNS = [
        (r"(?i)^(redirect|return|url|next|goto|dest|destination|target|redir|location)$",
         "Open Redirect", "Medium", "CWE-601"),
        (r"(?i)^(file|path|page|include|doc|document|folder|root|pg|style|template)$",
         "Path Traversal", "High", "CWE-22"),
        (r"(?i)^(id|user_id|uid|account|member|customer|order|invoice|record)$",
         "IDOR (Insecure Direct Object Reference)", "High", "CWE-639"),
        (r"(?i)^(cmd|command|exec|run|shell|system|ping|query|sql|search)$",
         "Command/SQL Injection", "Critical", "CWE-89"),
        (r"(?i)^(callback|jsonp|cb|function|handler)$",
         "JSONP/Callback Injection", "Medium", "CWE-79"),
        (r"(?i)^(debug|test|trace|verbose|mode|dev)$",
         "Debug Parameter", "Low", "CWE-215"),
        (r"(?i)^(token|auth|key|api_key|access_token|secret)$",
         "Auth Token in URL", "High", "CWE-598"),
        (r"(?i)^(lang|locale|language|region|country)$",
         "Locale Injection", "Low", "CWE-20"),
        (r"(?i)^(xml|data|input|body|payload|content)$",
         "XXE/Injection", "Medium", "CWE-611"),
    ]

    def analyze(self, response, target, session, timeout) -> Tuple[List, Dict[str, Any]]:
        findings = []

        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            return findings, {}

        # 1. Analyze existing URL parameters
        url_params = self._extract_url_params(target.raw_url)

        # 2. Collect all forms and their parameters
        form_params = self._extract_form_params(soup)

        # 3. Extract parameters from JS content
        js_params = self._extract_js_params(response.text)

        # 4. Combine all discovered parameters
        all_params = list(set(url_params + form_params + js_params))

        # 5. Analyze each parameter for risk
        flagged = set()
        for param in all_params:
            for pattern, vuln_type, severity, cwe in self.DANGEROUS_PARAM_PATTERNS:
                if re.match(pattern, param) and vuln_type not in flagged:
                    from ghostrecon.engine import Finding
                    flagged.add(vuln_type)
                    findings.append(Finding(
                        title=f"Potentially Vulnerable Parameter: '{param}' ({vuln_type})",
                        severity=severity,
                        category="Parameter Security",
                        description=(
                            f"Parameter '{param}' matches patterns associated with "
                            f"{vuln_type} vulnerabilities. This is a manual testing suggestion."
                        ),
                        recommendation=self._get_recommendation(vuln_type),
                        evidence=f"Parameter '{param}' detected in: "
                                 f"{'URL' if param in url_params else 'Form/JS'}",
                        cwe=cwe,
                    ))

        # Check for auth tokens in URLs
        self._check_tokens_in_url(target.raw_url, findings)

        # Check for sensitive data in URL query string
        self._check_sensitive_url_params(url_params, target.raw_url, findings)

        module_data = {
            "url_parameters": url_params,
            "form_parameters": list(set(form_params)),
            "js_parameters": list(set(js_params)),
            "all_unique_parameters": all_params,
            "flagged_parameters": list(flagged),
        }

        return findings, module_data

    def _extract_url_params(self, url: str) -> list:
        parsed = urlparse(url)
        if parsed.query:
            return list(parse_qs(parsed.query).keys())
        return []

    def _extract_form_params(self, soup) -> list:
        params = []
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name", "")
                if name:
                    params.append(name)
        return params

    def _extract_js_params(self, html_content: str) -> list:
        """Extract parameter names from JavaScript code patterns"""
        params = []
        patterns = [
            r"['\"`]([a-zA-Z_][a-zA-Z0-9_]{1,30})['\"`]\s*:",  # JSON keys
            r"getParameter(?:s)?\(['\"`]([a-zA-Z_][a-zA-Z0-9_]{1,30})['\"`]\)",  # getParameter
            r"params\[(['\"`])([a-zA-Z_][a-zA-Z0-9_]{1,30})\1\]",  # params['key']
            r"URLSearchParams.*?get\(['\"`]([a-zA-Z_][a-zA-Z0-9_]{1,30})['\"`]\)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html_content)
            for match in matches:
                p = match if isinstance(match, str) else match[-1]
                if len(p) > 1 and p.lower() not in ("function", "return", "const",
                                                      "let", "var", "true", "false"):
                    params.append(p)

        return list(set(params))[:50]

    def _check_tokens_in_url(self, url: str, findings: list):
        parsed = urlparse(url)
        query = parsed.query.lower()
        token_params = ["token", "access_token", "api_key", "key", "secret", "auth"]

        for param in token_params:
            if f"{param}=" in query:
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title="Authentication Token/Key Passed in URL",
                    severity="High",
                    category="Sensitive Data Exposure",
                    description=(
                        f"Parameter '{param}' appears to pass a token/key in the URL. "
                        "URLs are logged in browser history, server logs, and referrer headers."
                    ),
                    recommendation=(
                        "Move authentication tokens to HTTP headers "
                        "(Authorization: Bearer <token>) or request body."
                    ),
                    evidence=f"URL parameter '{param}' detected in query string",
                    cwe="CWE-598",
                ))
                break

    def _check_sensitive_url_params(self, params: list, url: str, findings: list):
        sensitive = []
        sensitive_names = [
            "password", "passwd", "pwd", "pass", "ssn", "credit_card",
            "card_number", "cvv", "social_security", "dob", "birth",
        ]
        for param in params:
            if any(s in param.lower() for s in sensitive_names):
                sensitive.append(param)

        if sensitive:
            from ghostrecon.engine import Finding
            findings.append(Finding(
                title="Sensitive Data Transmitted in URL Query String",
                severity="High",
                category="Sensitive Data Exposure",
                description=(
                    f"Potentially sensitive parameter(s) detected in URL: {sensitive}. "
                    "This data is exposed in browser history, server logs, and referrer headers."
                ),
                recommendation=(
                    "Never pass sensitive data in URL parameters. "
                    "Use POST requests with body parameters and HTTPS."
                ),
                evidence=f"Parameters in URL: {', '.join(sensitive)}",
                cwe="CWE-598",
            ))

    def _get_recommendation(self, vuln_type: str) -> str:
        recommendations = {
            "Open Redirect": (
                "Validate and whitelist redirect URLs. Never redirect to "
                "user-supplied URLs without strict validation."
            ),
            "Path Traversal": (
                "Canonicalize file paths and validate against a whitelist. "
                "Never pass raw user input to file system operations."
            ),
            "IDOR (Insecure Direct Object Reference)": (
                "Implement object-level authorization checks for every request. "
                "Use indirect references (UUIDs) instead of sequential IDs."
            ),
            "Command/SQL Injection": (
                "Use parameterized queries for all database operations. "
                "Never pass user input to shell commands."
            ),
            "JSONP/Callback Injection": (
                "Validate callback parameter against a strict whitelist of "
                "allowed function names."
            ),
            "Debug Parameter": (
                "Disable debug parameters in production. "
                "Remove or gate debug functionality behind authentication."
            ),
            "Auth Token in URL": (
                "Move tokens to Authorization headers. "
                "Invalidate any token exposed in a URL."
            ),
            "Locale Injection": (
                "Validate locale values against an allowlist. "
                "Do not use locale values in file paths."
            ),
            "XXE/Injection": (
                "Disable external entity processing in XML parsers. "
                "Validate and sanitize all input thoroughly."
            ),
        }
        return recommendations.get(vuln_type, "Validate and sanitize all user inputs.")
