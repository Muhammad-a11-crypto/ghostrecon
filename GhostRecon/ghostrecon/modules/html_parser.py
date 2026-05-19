"""
HTML Parser Module
Parses page HTML for sensitive information exposure and security indicators.
"""

import re
from typing import Tuple, List, Dict, Any
from bs4 import BeautifulSoup


class HTMLParser:
    """
    Parses HTML content to detect:
    - Hidden form fields with sensitive names
    - Hardcoded credentials or API keys in source
    - Exposed internal paths or comments
    - Insecure form configurations (no CSRF token, HTTP action)
    - Email addresses and phone numbers
    - Inline JavaScript with dangerous patterns
    """

    # Patterns for API keys / credentials in HTML source
    SENSITIVE_PATTERNS = [
        (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{16,})['\"]",
         "API Key", "High", "CWE-312"),
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
         "Hardcoded Password", "Critical", "CWE-259"),
        (r"(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{8,})['\"]",
         "Secret Key", "High", "CWE-312"),
        (r"(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9\-_.]{16,})['\"]",
         "Access Token", "High", "CWE-312"),
        (r"AKIA[0-9A-Z]{16}",
         "AWS Access Key", "Critical", "CWE-312"),
        (r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}",
         "Bearer Token", "High", "CWE-312"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
         "Private Key", "Critical", "CWE-312"),
        (r"(?i)(db[_-]?pass|database[_-]?password)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
         "Database Password", "Critical", "CWE-312"),
    ]

    # Internal path patterns
    PATH_PATTERNS = [
        r"(?i)/(admin|administrator|wp-admin|phpMyAdmin|phpmyadmin)",
        r"(?i)/api/v\d+/",
        r"(?i)/(dashboard|internal|private|secure|staff|management)",
        r"(?i)/\.(git|svn|env|htaccess|htpasswd)",
        r"(?i)/backup[s]?/",
        r"(?i)/config[uration]?/",
    ]

    def analyze(self, response, target, session, timeout) -> Tuple[List, Dict[str, Any]]:
        findings = []
        content = response.text

        try:
            soup = BeautifulSoup(content, "html.parser")
        except Exception:
            return findings, {}

        # Scan for sensitive patterns in raw HTML
        self._scan_sensitive_patterns(content, findings)

        # Analyze forms
        forms_data = self._analyze_forms(soup, target, findings)

        # Scan HTML comments
        comments_data = self._scan_comments(soup, findings)

        # Detect admin/sensitive paths in links
        paths_found = self._detect_sensitive_paths(soup, target, findings)

        # Detect email addresses
        emails = self._find_emails(content, findings)

        # Check for inline JavaScript risks
        self._check_inline_scripts(soup, findings)

        # Check for mixed content
        self._check_mixed_content(soup, target, findings)

        module_data = {
            "forms": forms_data,
            "comments_found": len(comments_data),
            "sensitive_paths": paths_found,
            "emails_found": emails,
            "page_title": soup.title.string if soup.title else None,
        }

        return findings, module_data

    def _scan_sensitive_patterns(self, content: str, findings: list):
        for pattern, label, severity, cwe in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                from ghostrecon.engine import Finding
                evidence = str(matches[0])[:100] if matches else ""
                findings.append(Finding(
                    title=f"Hardcoded Sensitive Data: {label}",
                    severity=severity,
                    category="Information Disclosure",
                    description=(
                        f"Potential {label} found exposed in HTML source. "
                        "This can allow attackers to gain unauthorized access."
                    ),
                    recommendation=(
                        f"Remove all {label} values from client-side code. "
                        "Use environment variables and server-side secret management."
                    ),
                    evidence=f"Pattern match: {evidence}",
                    cwe=cwe,
                ))

    def _analyze_forms(self, soup, target, findings: list) -> list:
        forms_data = []
        forms = soup.find_all("form")

        for i, form in enumerate(forms):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            inputs = form.find_all("input")

            input_names = [inp.get("name", "") for inp in inputs]
            hidden_inputs = [
                inp for inp in inputs if inp.get("type", "").lower() == "hidden"
            ]

            form_info = {
                "index": i,
                "action": action,
                "method": method,
                "input_count": len(inputs),
                "hidden_inputs": [h.get("name", "") for h in hidden_inputs],
            }
            forms_data.append(form_info)

            # Check for CSRF token in forms
            has_csrf = any(
                "csrf" in name.lower() or "token" in name.lower() or "xsrf" in name.lower()
                for name in input_names
            )
            if method == "POST" and not has_csrf:
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title="Form Missing CSRF Token",
                    severity="Medium",
                    category="CSRF",
                    description=(
                        f"Form #{i+1} (action='{action}') uses POST method but "
                        "no CSRF token field was detected. Vulnerable to CSRF."
                    ),
                    recommendation=(
                        "Add a cryptographically random CSRF token to all "
                        "state-changing forms and validate server-side."
                    ),
                    evidence=f"Form action='{action}', method=POST, inputs={input_names[:5]}",
                    cwe="CWE-352",
                ))

            # Check for form action over HTTP on HTTPS site
            if (action.startswith("http://") and target.scheme == "https"):
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title="Form Submits to Insecure HTTP Endpoint",
                    severity="High",
                    category="Mixed Content",
                    description=(
                        f"Form #{i+1} submits data to an HTTP endpoint: '{action}'. "
                        "Data will be transmitted unencrypted."
                    ),
                    recommendation="Change form action to use HTTPS.",
                    evidence=f"<form action='{action}' method='{method}'>",
                    cwe="CWE-319",
                ))

            # Check for autocomplete on sensitive inputs
            for inp in inputs:
                inp_type = inp.get("type", "text").lower()
                inp_name = inp.get("name", "").lower()
                autocomplete = inp.get("autocomplete", "").lower()

                is_sensitive = any(
                    kw in inp_name for kw in
                    ["password", "card", "cvv", "ssn", "credit", "pin"]
                )
                if inp_type == "password" or is_sensitive:
                    if autocomplete not in ("off", "new-password", "current-password"):
                        from ghostrecon.engine import Finding
                        findings.append(Finding(
                            title=f"Sensitive Input Missing autocomplete=off: '{inp.get('name','')}' ",
                            severity="Low",
                            category="Information Disclosure",
                            description=(
                                "Sensitive input field does not have autocomplete=off. "
                                "Browsers may cache this data."
                            ),
                            recommendation="Add autocomplete='off' to sensitive inputs.",
                            evidence=f"<input type='{inp_type}' name='{inp.get('name','')}'>",
                            cwe="CWE-200",
                        ))

        return forms_data

    def _scan_comments(self, soup, findings: list) -> list:
        from bs4 import Comment
        comments = soup.find_all(string=lambda t: isinstance(t, Comment))
        suspicious_comments = []

        suspicious_keywords = [
            "todo", "fixme", "hack", "password", "credential", "token",
            "api", "key", "secret", "debug", "admin", "remove", "internal",
            "prod", "staging", "database", "connection string", "bug",
        ]

        for comment in comments:
            comment_text = str(comment).strip()
            comment_lower = comment_text.lower()
            if any(kw in comment_lower for kw in suspicious_keywords):
                suspicious_comments.append(comment_text[:200])
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title="Sensitive Information in HTML Comment",
                    severity="Low",
                    category="Information Disclosure",
                    description=(
                        "An HTML comment contains potentially sensitive keywords. "
                        "Developers sometimes leave credentials or internal notes in comments."
                    ),
                    recommendation="Remove all sensitive or internal notes from HTML comments.",
                    evidence=f"<!-- {comment_text[:120]}... -->",
                    cwe="CWE-615",
                ))
                break  # Report once, don't flood

        return suspicious_comments

    def _detect_sensitive_paths(self, soup, target, findings: list) -> list:
        found_paths = []
        all_links = [a.get("href", "") for a in soup.find_all("a", href=True)]

        sensitive_path_re = [
            (r"(?i)/(admin|administrator|wp-admin|cpanel|phpmyadmin)", "Admin Panel"),
            (r"(?i)/api/(v\d+/)?", "API Endpoint"),
            (r"(?i)/(\.env|\.git|\.svn|\.htaccess|\.htpasswd|web\.config)", "Sensitive File"),
            (r"(?i)/(backup|dump|export|import)s?/", "Backup Directory"),
            (r"(?i)/(dashboard|internal|private|staff)", "Internal Area"),
        ]

        reported = set()
        for link in all_links:
            for pattern, label in sensitive_path_re:
                if re.search(pattern, link) and label not in reported:
                    found_paths.append({"link": link, "type": label})
                    reported.add(label)
                    from ghostrecon.engine import Finding
                    findings.append(Finding(
                        title=f"Sensitive Path Discovered: {label}",
                        severity="Medium" if "API" in label else "High",
                        category="Information Disclosure",
                        description=(
                            f"A link to a potentially sensitive path was found in the HTML: "
                            f"'{link}' classified as '{label}'."
                        ),
                        recommendation=(
                            "Restrict access to sensitive paths with authentication. "
                            "Remove unnecessary links from public pages."
                        ),
                        evidence=f"<a href='{link}'>",
                        cwe="CWE-200",
                    ))

        return found_paths

    def _find_emails(self, content: str, findings: list) -> list:
        email_pattern = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        emails = list(set(re.findall(email_pattern, content)))

        # Filter out image/file references
        emails = [e for e in emails if not any(
            e.endswith(ext) for ext in [".png", ".jpg", ".gif", ".svg", ".css"]
        )]

        if emails:
            from ghostrecon.engine import Finding
            findings.append(Finding(
                title="Email Addresses Exposed in Page Source",
                severity="Info",
                category="Information Disclosure",
                description=(
                    f"Found {len(emails)} email address(es) in the page source. "
                    "These can be harvested for phishing or spam campaigns."
                ),
                recommendation="Use contact forms instead of exposing raw emails. Obfuscate if needed.",
                evidence=f"Emails: {', '.join(emails[:5])}",
                cwe="CWE-200",
            ))

        return emails

    def _check_inline_scripts(self, soup, findings: list):
        scripts = soup.find_all("script", src=False)
        dangerous_patterns = [
            (r"eval\s*\(", "eval() Usage"),
            (r"document\.write\s*\(", "document.write() Usage"),
            (r"innerHTML\s*=", "Unsafe innerHTML Assignment"),
            (r"window\.location\s*=", "Unvalidated Redirect"),
        ]

        for script in scripts:
            script_text = script.string or ""
            for pattern, label in dangerous_patterns:
                if re.search(pattern, script_text):
                    from ghostrecon.engine import Finding
                    findings.append(Finding(
                        title=f"Dangerous JavaScript Pattern: {label}",
                        severity="Medium",
                        category="Cross-Site Scripting",
                        description=(
                            f"Potentially dangerous JavaScript pattern detected: {label}. "
                            "This may enable XSS if user input flows into it."
                        ),
                        recommendation=(
                            f"Audit all uses of {label}. "
                            "Sanitize user input before passing to JavaScript sinks."
                        ),
                        evidence=f"Pattern '{pattern}' found in inline script",
                        cwe="CWE-79",
                    ))
                    break

    def _check_mixed_content(self, soup, target, findings: list):
        if target.scheme != "https":
            return

        mixed = []
        for tag, attr in [("img", "src"), ("script", "src"), ("link", "href")]:
            for el in soup.find_all(tag):
                url = el.get(attr, "")
                if url.startswith("http://"):
                    mixed.append(url[:80])

        if mixed:
            from ghostrecon.engine import Finding
            findings.append(Finding(
                title="Mixed Content: HTTP Resources on HTTPS Page",
                severity="Medium",
                category="Mixed Content",
                description=(
                    f"The HTTPS page loads {len(mixed)} resource(s) over HTTP. "
                    "This weakens SSL/TLS protection and may trigger browser warnings."
                ),
                recommendation="Update all resource URLs to use HTTPS.",
                evidence=f"HTTP resources: {', '.join(mixed[:3])}",
                cwe="CWE-319",
            ))
