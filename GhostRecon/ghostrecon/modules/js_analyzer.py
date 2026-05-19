"""
JavaScript Analyzer Module
Discovers JS files and extracts API endpoints, secrets, and risky patterns.
"""

import re
from typing import Tuple, List, Dict, Any
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class JSAnalyzer:
    """
    Discovers JavaScript files linked from the target page,
    fetches and analyzes them for:
    - API endpoint extraction
    - Hardcoded secrets or credentials
    - Dangerous JS patterns
    - Internal path discovery
    """

    MAX_JS_FILES = 10        # Limit JS files to fetch (passive only)
    MAX_JS_SIZE = 512 * 1024 # 512KB max per file

    # Endpoint patterns to discover from JS
    ENDPOINT_PATTERNS = [
        r"['\"`](\/[a-zA-Z0-9_\-\/\.]{3,80})['\"`]",
        r"(?:url|endpoint|path|api)\s*[:=]\s*['\"`](\/[^'\"` ]{3,80})['\"`]",
        r"fetch\s*\(\s*['\"`](\/[^'\"` ]{3,80})['\"`]",
        r"axios\.[a-z]+\s*\(\s*['\"`](\/[^'\"` ]{3,80})['\"`]",
        r"\$\.(?:get|post|ajax)\s*\(\s*['\"`](\/[^'\"` ]{3,80})['\"`]",
    ]

    # Secret patterns in JS
    SECRET_PATTERNS = [
        (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"`]([A-Za-z0-9\-_]{16,})['\"`]",
         "API Key", "High", "CWE-312"),
        (r"(?i)(aws[_-]?secret|aws[_-]?access)[_-]?key\s*[:=]\s*['\"`]([A-Za-z0-9+/]{20,})['\"`]",
         "AWS Credentials", "Critical", "CWE-312"),
        (r"(?i)(password|passwd)\s*[:=]\s*['\"`]([^'\"` ]{4,})['\"`]",
         "Password", "Critical", "CWE-259"),
        (r"(?i)(client[_-]?secret|app[_-]?secret)\s*[:=]\s*['\"`]([A-Za-z0-9\-_]{8,})['\"`]",
         "OAuth Secret", "High", "CWE-312"),
        (r"AKIA[0-9A-Z]{16}",
         "AWS Access Key ID", "Critical", "CWE-312"),
        (r"(?i)(firebase[_-]?key|firebase[_-]?config)\s*[:=]\s*['\"`]([A-Za-z0-9\-_]{20,})['\"`]",
         "Firebase Key", "High", "CWE-312"),
        (r"(?i)(stripe[_-]?key|stripe[_-]?secret)\s*[:=]\s*['\"`](sk_[A-Za-z0-9]{24,})['\"`]",
         "Stripe Secret Key", "Critical", "CWE-312"),
        (r"gh[pousr]_[A-Za-z0-9]{36}",
         "GitHub Token", "Critical", "CWE-312"),
    ]

    # Dangerous JS sinks
    DANGEROUS_SINKS = [
        (r"eval\s*\(", "eval()"),
        (r"setTimeout\s*\(\s*['\"]", "setTimeout with string arg"),
        (r"setInterval\s*\(\s*['\"]", "setInterval with string arg"),
        (r"document\.write\s*\(", "document.write()"),
        (r"\.innerHTML\s*=", "innerHTML assignment"),
        (r"\.outerHTML\s*=", "outerHTML assignment"),
        (r"location\.href\s*=", "location.href redirect"),
        (r"window\.open\s*\(", "window.open()"),
    ]

    def analyze(self, response, target, session, timeout) -> Tuple[List, Dict[str, Any]]:
        findings = []
        soup = BeautifulSoup(response.text, "html.parser")

        # Collect JS file URLs
        js_urls = self._collect_js_urls(soup, target)

        all_endpoints = []
        all_js_data = []

        for js_url in js_urls[:self.MAX_JS_FILES]:
            try:
                js_resp = session.get(js_url, timeout=timeout, verify=False)
                if js_resp.status_code != 200:
                    continue

                js_content = js_resp.text[:self.MAX_JS_SIZE]
                js_info = {"url": js_url, "size": len(js_content)}

                # Extract endpoints
                endpoints = self._extract_endpoints(js_content)
                js_info["endpoints"] = endpoints
                all_endpoints.extend(endpoints)

                # Detect secrets
                self._scan_secrets(js_content, js_url, findings)

                # Detect dangerous sinks
                self._detect_dangerous_sinks(js_content, js_url, findings)

                all_js_data.append(js_info)

            except Exception:
                continue

        # Deduplicate and classify endpoints
        unique_endpoints = list(set(all_endpoints))
        self._classify_endpoints(unique_endpoints, target, findings)

        module_data = {
            "js_files_found": len(js_urls),
            "js_files_analyzed": len(all_js_data),
            "endpoints_discovered": unique_endpoints[:50],
            "js_files": all_js_data,
        }

        return findings, module_data

    def _collect_js_urls(self, soup, target) -> list:
        js_urls = []
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                full_url = urljoin(target.raw_url, src)
                # Only include same-domain JS (passive)
                if target.host in full_url or full_url.startswith("/"):
                    js_urls.append(full_url)
        return list(set(js_urls))

    def _extract_endpoints(self, js_content: str) -> list:
        endpoints = []
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_content)
            for match in matches:
                ep = match if isinstance(match, str) else match[0]
                # Filter noise
                if len(ep) >= 3 and "." not in ep.split("/")[-1]:
                    endpoints.append(ep)
                elif "/" in ep and len(ep) >= 5:
                    endpoints.append(ep)
        return list(set(endpoints))[:100]

    def _scan_secrets(self, js_content: str, js_url: str, findings: list):
        for pattern, label, severity, cwe in self.SECRET_PATTERNS:
            matches = re.findall(pattern, js_content)
            if matches:
                from ghostrecon.engine import Finding
                evidence = str(matches[0])[:80] if matches else ""
                findings.append(Finding(
                    title=f"Secret Exposed in JavaScript: {label}",
                    severity=severity,
                    category="Information Disclosure",
                    description=(
                        f"A {label} was found hardcoded in a JavaScript file. "
                        "This gives attackers direct access to protected resources."
                    ),
                    recommendation=(
                        f"Remove all {label} values from JavaScript. "
                        "Use server-side proxies and environment variable injection."
                    ),
                    evidence=f"Found in {js_url.split('/')[-1]}: {evidence}",
                    cwe=cwe,
                ))

    def _detect_dangerous_sinks(self, js_content: str, js_url: str, findings: list):
        for pattern, label in self.DANGEROUS_SINKS:
            if re.search(pattern, js_content):
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title=f"Dangerous JavaScript Sink Detected: {label}",
                    severity="Medium",
                    category="Cross-Site Scripting",
                    description=(
                        f"JavaScript sink '{label}' detected in a script file. "
                        "If user-controlled data flows into this sink, XSS is possible."
                    ),
                    recommendation=(
                        f"Audit all data flows into {label}. "
                        "Sanitize input with DOMPurify before DOM manipulation."
                    ),
                    evidence=f"Pattern '{label}' in {js_url.split('/')[-1]}",
                    cwe="CWE-79",
                ))

    def _classify_endpoints(self, endpoints: list, target, findings: list):
        admin_like = [e for e in endpoints if re.search(
            r"(?i)/(admin|dashboard|management|control|staff|internal)", e
        )]
        api_like = [e for e in endpoints if re.search(
            r"(?i)/(api|rest|graphql|v\d+)/", e
        )]
        auth_like = [e for e in endpoints if re.search(
            r"(?i)/(login|logout|auth|oauth|token|signin|signup|register)", e
        )]

        if admin_like:
            from ghostrecon.engine import Finding
            findings.append(Finding(
                title="Admin/Management Endpoints Discovered via JavaScript",
                severity="High",
                category="Information Disclosure",
                description=(
                    f"{len(admin_like)} admin-like endpoint(s) discovered in JavaScript files. "
                    "Attackers can target these for unauthorized access."
                ),
                recommendation=(
                    "Restrict admin endpoints behind strong authentication. "
                    "Consider IP allowlisting for sensitive management interfaces."
                ),
                evidence=f"Endpoints: {', '.join(admin_like[:5])}",
                cwe="CWE-200",
            ))

        if api_like:
            from ghostrecon.engine import Finding
            findings.append(Finding(
                title="API Endpoints Discovered via JavaScript",
                severity="Info",
                category="Information Disclosure",
                description=(
                    f"{len(api_like)} API endpoint(s) were extracted from JavaScript. "
                    "These may expose business logic or sensitive data operations."
                ),
                recommendation=(
                    "Ensure all API endpoints enforce authentication and authorization. "
                    "Implement rate limiting and input validation."
                ),
                evidence=f"Endpoints: {', '.join(api_like[:5])}",
                cwe="CWE-200",
            ))

        if auth_like:
            from ghostrecon.engine import Finding
            findings.append(Finding(
                title="Authentication Endpoints Identified",
                severity="Info",
                category="Information Disclosure",
                description=(
                    f"Authentication-related endpoints found: {auth_like[:3]}. "
                    "These should be hardened against brute-force attacks."
                ),
                recommendation="Implement rate limiting, CAPTCHA, and account lockout on auth endpoints.",
                evidence=f"Auth paths: {', '.join(auth_like[:5])}",
                cwe="CWE-307",
            ))
