"""
Vulnerability Correlator — Intelligence Layer
Correlates individual findings to detect compounded risks and attack chains.
"""

from typing import Tuple, List, Dict


class VulnerabilityCorrelator:
    """
    The intelligence layer. Instead of just listing findings independently,
    this module looks for dangerous combinations that compound risk:

    Examples:
    - Missing HttpOnly + XSS sink → session hijack chain
    - Missing CSP + unsafe-inline JS + XSS param → high XSS confidence
    - Admin panel found + no HTTPS → credential theft risk
    - API endpoints in JS + no auth headers → API exposure
    - Version disclosure + known CVE tech → targeted exploitation risk
    """

    def correlate(
        self, findings: list, raw_data: dict
    ) -> Tuple[List[Dict], int]:
        """
        Returns:
            insights: list of correlation insight dicts
            score_delta: additional risk points from compound findings
        """
        insights = []
        score_delta = 0

        finding_titles = [f.title for f in findings]
        finding_categories = [f.category for f in findings]
        finding_severities = [f.severity for f in findings]

        # -------------------------------------------------------
        # CHAIN 1: XSS Compound Risk
        # Missing HttpOnly + XSS sink/pattern → session theft chain
        # -------------------------------------------------------
        has_missing_httponly = any("HttpOnly" in t for t in finding_titles)
        has_xss_sink = any("XSS" in c or "Cross-Site Scripting" in c for c in finding_categories)

        if has_missing_httponly and has_xss_sink:
            insights.append({
                "type": "Attack Chain",
                "severity": "Critical",
                "title": "XSS + HttpOnly Absence = Session Hijack Chain",
                "description": (
                    "Cookies lack the HttpOnly flag AND dangerous JavaScript sinks "
                    "were detected. An XSS vulnerability could allow an attacker to "
                    "steal session cookies via document.cookie, leading to full account takeover."
                ),
                "components": ["Missing HttpOnly Flag", "XSS Sink/Pattern"],
                "recommendation": (
                    "1. Add HttpOnly to all session cookies immediately.\n"
                    "2. Audit and fix all identified XSS sinks.\n"
                    "3. Implement a strict Content Security Policy."
                ),
            })
            score_delta += 15

        # -------------------------------------------------------
        # CHAIN 2: CSP Weakness + XSS
        # -------------------------------------------------------
        has_missing_csp = any("Content-Security-Policy" in t and "Missing" in t
                              for t in finding_titles)
        has_weak_csp = any("unsafe-inline" in t or "unsafe-eval" in t
                           for t in finding_titles)

        if (has_missing_csp or has_weak_csp) and has_xss_sink:
            insights.append({
                "type": "Defense Gap",
                "severity": "High",
                "title": "No Effective CSP + XSS Vectors Present",
                "description": (
                    "Content Security Policy is absent or misconfigured, and XSS "
                    "vectors were identified. There is no browser-level last line of "
                    "defense against script injection attacks."
                ),
                "components": ["Missing/Weak CSP", "XSS Vectors"],
                "recommendation": (
                    "Deploy a strict CSP without 'unsafe-inline' or 'unsafe-eval'. "
                    "Use nonces or hashes for legitimate inline scripts."
                ),
            })
            score_delta += 10

        # -------------------------------------------------------
        # CHAIN 3: CSRF Triple Threat
        # Missing SameSite + Missing CSRF Token + Sensitive Form
        # -------------------------------------------------------
        has_no_samesite = any("SameSite" in t and "Missing" in t for t in finding_titles)
        has_no_csrf = any("CSRF Token" in t for t in finding_titles)

        if has_no_samesite and has_no_csrf:
            insights.append({
                "type": "Attack Chain",
                "severity": "High",
                "title": "CSRF Triple Threat: No SameSite + No CSRF Token",
                "description": (
                    "Cookies lack SameSite protection AND forms have no CSRF tokens. "
                    "This is a textbook CSRF vulnerability — an attacker can trick "
                    "authenticated users into performing unintended actions."
                ),
                "components": ["Missing SameSite Cookie Attribute", "Missing CSRF Token"],
                "recommendation": (
                    "1. Add SameSite=Strict or Lax to session cookies.\n"
                    "2. Implement CSRF tokens on all state-changing forms.\n"
                    "3. Verify the Origin/Referer header server-side."
                ),
            })
            score_delta += 12

        # -------------------------------------------------------
        # CHAIN 4: Admin Panel + Weak Auth Indicators
        # -------------------------------------------------------
        has_admin = any("Admin" in t and ("Discovered" in t or "Panel" in t)
                        for t in finding_titles)
        has_no_hsts = any("HSTS" in t and "Missing" in t for t in finding_titles)

        if has_admin and has_no_hsts:
            insights.append({
                "type": "Attack Chain",
                "severity": "High",
                "title": "Admin Panel Exposed Without HSTS",
                "description": (
                    "An admin or management panel was discovered, and the site "
                    "lacks HSTS. A downgrade attack (SSLstrip) could intercept "
                    "admin credentials in transit."
                ),
                "components": ["Admin Endpoint Discovery", "Missing HSTS"],
                "recommendation": (
                    "1. Enable HSTS with max-age ≥ 1 year.\n"
                    "2. Require MFA for all admin interfaces.\n"
                    "3. Restrict admin access by IP allowlist."
                ),
            })
            score_delta += 12

        # -------------------------------------------------------
        # CHAIN 5: Information Overload (Multiple Disclosure Issues)
        # -------------------------------------------------------
        disclosure_count = sum(1 for c in finding_categories if c == "Information Disclosure")
        if disclosure_count >= 4:
            insights.append({
                "type": "Pattern",
                "severity": "Medium",
                "title": "Significant Information Disclosure Surface",
                "description": (
                    f"{disclosure_count} separate information disclosure findings were detected. "
                    "Collectively, they give an attacker a detailed picture of the technology "
                    "stack, internal architecture, and potential attack vectors."
                ),
                "components": [f.title for f in findings if f.category == "Information Disclosure"],
                "recommendation": (
                    "Apply a 'defense in depth' approach: suppress headers, genericize "
                    "error messages, remove comments, and restrict path exposure."
                ),
            })
            score_delta += 8

        # -------------------------------------------------------
        # CHAIN 6: API Exposure Without Rate Limiting Signal
        # -------------------------------------------------------
        js_data = raw_data.get("javascript", {})
        api_endpoints = [
            ep for ep in js_data.get("endpoints_discovered", [])
            if "/api/" in ep.lower()
        ]
        headers_data = raw_data.get("headers", {})
        all_headers_present = [
            h.lower() for h in headers_data.get("all_headers", {}).keys()
        ]
        has_rate_limit_header = any(
            kw in " ".join(all_headers_present)
            for kw in ["x-ratelimit", "retry-after", "x-rate-limit"]
        )

        if api_endpoints and not has_rate_limit_header:
            insights.append({
                "type": "Pattern",
                "severity": "Medium",
                "title": "API Endpoints Exposed With No Visible Rate Limiting",
                "description": (
                    f"{len(api_endpoints)} API endpoint(s) were discovered in JavaScript, "
                    "and no rate-limiting headers (X-RateLimit-*) were observed. "
                    "These APIs may be vulnerable to brute-force or enumeration attacks."
                ),
                "components": api_endpoints[:5],
                "recommendation": (
                    "Implement rate limiting on all API endpoints. "
                    "Return X-RateLimit-Limit and X-RateLimit-Remaining headers. "
                    "Use API keys or OAuth for all API access."
                ),
            })
            score_delta += 7

        # -------------------------------------------------------
        # CHAIN 7: Secret in JS + Wildcard CORS
        # -------------------------------------------------------
        has_secret_in_js = any("Secret Exposed in JavaScript" in t for t in finding_titles)
        has_wildcard_cors = any("Wildcard Allow-Origin" in t for t in finding_titles)

        if has_secret_in_js and has_wildcard_cors:
            insights.append({
                "type": "Attack Chain",
                "severity": "Critical",
                "title": "JavaScript Secret + CORS Wildcard = Credential Theft",
                "description": (
                    "A secret/key was found hardcoded in JavaScript AND CORS is "
                    "configured with a wildcard origin. Any malicious website can "
                    "make authenticated cross-origin requests using the exposed secret."
                ),
                "components": ["Secret in JavaScript", "CORS Wildcard"],
                "recommendation": (
                    "1. Rotate all exposed secrets immediately.\n"
                    "2. Move secrets to server-side only.\n"
                    "3. Restrict CORS to specific trusted origins."
                ),
            })
            score_delta += 20

        # -------------------------------------------------------
        # CHAIN 8: Technology Fingerprint + Version Disclosure
        # -------------------------------------------------------
        has_version_disclosure = any("Version Number Disclosed" in t for t in finding_titles)
        fp_data = raw_data.get("fingerprint", {})
        tech_count = len(fp_data.get("technologies", []))

        if has_version_disclosure and tech_count >= 2:
            insights.append({
                "type": "Pattern",
                "severity": "Low",
                "title": "Detailed Technology Fingerprint Possible",
                "description": (
                    f"{tech_count} technologies were identified along with specific "
                    "version numbers. An attacker can cross-reference these with CVE "
                    "databases to find known, unpatched vulnerabilities."
                ),
                "components": [t["name"] for t in fp_data.get("technologies", [])],
                "recommendation": (
                    "Suppress version numbers from all response headers. "
                    "Keep all identified technologies patched to latest stable versions. "
                    "Subscribe to security advisories for each identified technology."
                ),
            })
            score_delta += 5

        return insights, score_delta
