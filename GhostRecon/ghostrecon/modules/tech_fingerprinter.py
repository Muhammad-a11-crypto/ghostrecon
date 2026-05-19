"""
Technology Fingerprinter Module
Identifies technologies, frameworks, and servers from response characteristics.
"""

import re
from typing import Tuple, List, Dict, Any


class TechFingerprinter:
    """
    Passively fingerprints the technology stack using:
    - Response headers
    - Cookie names
    - HTML meta tags
    - File paths and extensions
    - Error patterns
    """

    SIGNATURES = {
        # Web Servers
        "Apache": {
            "patterns": [
                ("header", "Server", r"(?i)apache"),
                ("header", "Server", r"(?i)Apache/(\d+\.\d+)"),
            ],
            "category": "Web Server",
        },
        "Nginx": {
            "patterns": [
                ("header", "Server", r"(?i)nginx"),
            ],
            "category": "Web Server",
        },
        "IIS": {
            "patterns": [
                ("header", "Server", r"(?i)Microsoft-IIS"),
                ("header", "X-Powered-By", r"(?i)ASP\.NET"),
            ],
            "category": "Web Server",
        },
        # Backend Frameworks
        "PHP": {
            "patterns": [
                ("header", "X-Powered-By", r"(?i)PHP/(\d+\.\d+)"),
                ("cookie", "PHPSESSID", r".*"),
                ("header", "Set-Cookie", r"(?i)PHPSESSID"),
            ],
            "category": "Backend Language",
        },
        "ASP.NET": {
            "patterns": [
                ("header", "X-AspNet-Version", r".*"),
                ("header", "X-Powered-By", r"(?i)ASP\.NET"),
                ("cookie", "ASP.NET_SessionId", r".*"),
                ("cookie", "__RequestVerificationToken", r".*"),
            ],
            "category": "Backend Framework",
        },
        "Django": {
            "patterns": [
                ("cookie", "csrftoken", r".*"),
                ("cookie", "sessionid", r".*"),
                ("header", "X-Frame-Options", r"(?i)SAMEORIGIN"),
            ],
            "category": "Backend Framework",
        },
        "Ruby on Rails": {
            "patterns": [
                ("cookie", "_session_id", r".*"),
                ("header", "X-Powered-By", r"(?i)Phusion Passenger"),
            ],
            "category": "Backend Framework",
        },
        "Laravel": {
            "patterns": [
                ("cookie", "laravel_session", r".*"),
                ("cookie", "XSRF-TOKEN", r".*"),
            ],
            "category": "Backend Framework",
        },
        "Express.js": {
            "patterns": [
                ("header", "X-Powered-By", r"(?i)Express"),
            ],
            "category": "Backend Framework",
        },
        # CMS
        "WordPress": {
            "patterns": [
                ("html", None, r"(?i)/wp-content/"),
                ("html", None, r"(?i)/wp-includes/"),
                ("cookie", "wordpress_", r".*"),
            ],
            "category": "CMS",
        },
        "Drupal": {
            "patterns": [
                ("html", None, r"(?i)/sites/default/"),
                ("cookie", "Drupal.visitor", r".*"),
                ("header", "X-Generator", r"(?i)Drupal"),
            ],
            "category": "CMS",
        },
        "Joomla": {
            "patterns": [
                ("html", None, r"(?i)/components/com_"),
                ("html", None, r"(?i)Joomla!"),
            ],
            "category": "CMS",
        },
        # Frontend Frameworks
        "React": {
            "patterns": [
                ("html", None, r'data-reactroot|data-reactid|__react'),
                ("html", None, r"(?i)react\.production\.min\.js"),
            ],
            "category": "Frontend Framework",
        },
        "Angular": {
            "patterns": [
                ("html", None, r"ng-version=|ng-app=|angular\.js"),
                ("html", None, r"(?i)angular\.min\.js"),
            ],
            "category": "Frontend Framework",
        },
        "Vue.js": {
            "patterns": [
                ("html", None, r"(?i)vue\.js|vue\.min\.js|__vue"),
            ],
            "category": "Frontend Framework",
        },
        # CDN / Infrastructure
        "Cloudflare": {
            "patterns": [
                ("header", "CF-Ray", r".*"),
                ("header", "Server", r"(?i)cloudflare"),
            ],
            "category": "CDN/WAF",
        },
        "AWS CloudFront": {
            "patterns": [
                ("header", "Via", r"(?i)CloudFront"),
                ("header", "X-Amz-Cf-Id", r".*"),
            ],
            "category": "CDN",
        },
        # Databases (via error messages)
        "MySQL": {
            "patterns": [
                ("html", None, r"(?i)MySQL server|mysql_connect|mysqli_"),
            ],
            "category": "Database (Error Disclosure)",
        },
        "MongoDB": {
            "patterns": [
                ("html", None, r"(?i)MongoError|mongodb://"),
            ],
            "category": "Database (Error Disclosure)",
        },
    }

    def analyze(self, response, target, session, timeout) -> Tuple[List, Dict[str, Any]]:
        findings = []
        technologies = []
        headers = dict(response.headers)
        headers_lower = {k.lower(): v for k, v in headers.items()}
        cookies = {c.name: c.value for c in response.cookies}
        html_content = response.text[:100000]  # First 100KB

        for tech_name, config in self.SIGNATURES.items():
            detected = False
            evidence_parts = []

            for pat_type, pat_key, pat_val in config["patterns"]:
                if detected:
                    break

                if pat_type == "header":
                    header_val = headers_lower.get(pat_key.lower(), "")
                    if header_val and re.search(pat_val, header_val):
                        detected = True
                        evidence_parts.append(f"{pat_key}: {header_val[:60]}")

                elif pat_type == "cookie":
                    for cookie_name in cookies:
                        if pat_key.lower() in cookie_name.lower():
                            if re.search(pat_val, cookies[cookie_name]):
                                detected = True
                                evidence_parts.append(f"Cookie: {cookie_name}")
                                break

                elif pat_type == "html":
                    if re.search(pat_val, html_content):
                        detected = True
                        match = re.search(pat_val, html_content)
                        if match:
                            evidence_parts.append(f"HTML: ...{match.group(0)[:50]}...")

            if detected:
                category = config["category"]
                technologies.append({
                    "name": tech_name,
                    "category": category,
                    "evidence": "; ".join(evidence_parts),
                })

                # Flag database errors as critical finding
                if "Error Disclosure" in category:
                    from ghostrecon.engine import Finding
                    findings.append(Finding(
                        title=f"Database Error Message Disclosed: {tech_name}",
                        severity="High",
                        category="Information Disclosure",
                        description=(
                            f"{tech_name} error messages are exposed in the page response. "
                            "This reveals database technology and aids SQL injection attacks."
                        ),
                        recommendation=(
                            "Suppress all database error messages in production. "
                            "Use generic error pages and log errors server-side only."
                        ),
                        evidence="; ".join(evidence_parts),
                        cwe="CWE-209",
                    ))

        # Check for version disclosure
        self._check_version_disclosure(headers_lower, findings)

        # Add summary finding about tech fingerprinting
        if technologies:
            from ghostrecon.engine import Finding
            tech_names = [t["name"] for t in technologies]
            findings.append(Finding(
                title="Technology Stack Identified",
                severity="Info",
                category="Fingerprinting",
                description=(
                    f"The following technologies were passively identified: "
                    f"{', '.join(tech_names)}. "
                    "Knowing the stack helps attackers target specific CVEs."
                ),
                recommendation=(
                    "Minimize technology disclosure through headers and error messages. "
                    "Keep all identified technologies patched and up to date."
                ),
                evidence=f"Technologies: {', '.join(tech_names)}",
                cwe="CWE-200",
            ))

        module_data = {
            "technologies": technologies,
            "tech_count": len(technologies),
        }

        return findings, module_data

    def _check_version_disclosure(self, headers_lower: dict, findings: list):
        version_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
        version_re = r"\d+\.\d+[\.\d]*"

        for h in version_headers:
            val = headers_lower.get(h, "")
            if val and re.search(version_re, val):
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title=f"Version Number Disclosed in Header: {h.title()}",
                    severity="Low",
                    category="Information Disclosure",
                    description=(
                        f"The '{h}' header reveals a specific version number: '{val}'. "
                        "Version disclosure helps attackers identify known CVEs."
                    ),
                    recommendation=f"Remove or genericize the '{h}' header to hide version info.",
                    evidence=f"{h}: {val}",
                    cwe="CWE-200",
                ))
