"""
Cookie Inspector Module
Analyzes cookie security attributes and flags insecure configurations.
"""

from typing import Tuple, List, Dict, Any


class CookieInspector:
    """
    Inspects cookies set by the target for missing security attributes.
    Identifies session cookies, sensitive naming patterns, and bad flags.
    """

    # Patterns that suggest a cookie is session-related (high value target)
    SESSION_PATTERNS = [
        "sess", "session", "auth", "token", "jwt", "sid", "user",
        "login", "account", "csrf", "xsrf", "remember", "uid", "id",
    ]

    def analyze(self, response, target, session, timeout) -> Tuple[List, Dict[str, Any]]:
        findings = []
        cookies = response.cookies

        all_cookies_data = []

        for cookie in cookies:
            cookie_info = self._inspect_cookie(cookie, target)
            all_cookies_data.append(cookie_info)

            is_session = cookie_info["likely_session"]

            # HttpOnly check
            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "_rest", {}).get("HttpOnly"):
                http_only = False
                for attr in (cookie._rest if hasattr(cookie, "_rest") else {}):
                    if attr.lower() == "httponly":
                        http_only = True
            else:
                http_only = True

            # Re-check via raw set-cookie header
            raw_sc = self._get_raw_set_cookie(response, cookie.name)
            http_only = "httponly" in raw_sc.lower()
            secure_flag = "secure" in raw_sc.lower()
            samesite = self._extract_samesite(raw_sc)

            severity_base = "High" if is_session else "Medium"

            if not http_only:
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title=f"Cookie Missing HttpOnly Flag: '{cookie.name}'",
                    severity=severity_base,
                    category="Cookie Security",
                    description=(
                        f"Cookie '{cookie.name}' lacks the HttpOnly attribute. "
                        "JavaScript can read this cookie, enabling session theft via XSS."
                    ),
                    recommendation=(
                        f"Set HttpOnly on cookie '{cookie.name}': "
                        "Set-Cookie: name=value; HttpOnly"
                    ),
                    evidence=f"Set-Cookie: {cookie.name}=<value>; (HttpOnly missing)",
                    cwe="CWE-1004",
                ))

            if not secure_flag and target.scheme == "https":
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title=f"Cookie Missing Secure Flag: '{cookie.name}'",
                    severity=severity_base,
                    category="Cookie Security",
                    description=(
                        f"Cookie '{cookie.name}' is served over HTTPS but lacks the "
                        "Secure flag. The cookie may be transmitted over HTTP."
                    ),
                    recommendation=f"Add Secure flag to cookie '{cookie.name}'.",
                    evidence=f"Set-Cookie: {cookie.name}=<value>; (Secure missing)",
                    cwe="CWE-614",
                ))

            if samesite is None:
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title=f"Cookie Missing SameSite Attribute: '{cookie.name}'",
                    severity="Low" if not is_session else "Medium",
                    category="Cookie Security",
                    description=(
                        f"Cookie '{cookie.name}' lacks the SameSite attribute, "
                        "making it vulnerable to CSRF attacks."
                    ),
                    recommendation="Set SameSite=Strict or SameSite=Lax.",
                    evidence=f"Set-Cookie: {cookie.name}=<value>; (SameSite missing)",
                    cwe="CWE-352",
                ))
            elif samesite.lower() == "none" and not secure_flag:
                from ghostrecon.engine import Finding
                findings.append(Finding(
                    title=f"Cookie: SameSite=None Without Secure: '{cookie.name}'",
                    severity="Medium",
                    category="Cookie Security",
                    description=(
                        f"Cookie '{cookie.name}' has SameSite=None but no Secure flag. "
                        "Modern browsers will reject this cookie."
                    ),
                    recommendation="Add Secure flag when using SameSite=None.",
                    evidence=f"SameSite=None; Secure missing for '{cookie.name}'",
                    cwe="CWE-614",
                ))

            # Check for suspicious cookie values (potential info disclosure)
            self._check_cookie_value(cookie, findings)

        module_data = {
            "total_cookies": len(all_cookies_data),
            "cookies": all_cookies_data,
        }

        return findings, module_data

    def _get_raw_set_cookie(self, response, cookie_name: str) -> str:
        """Extract raw Set-Cookie header for a given cookie name"""
        for key, value in response.headers.items():
            if key.lower() == "set-cookie":
                if value.lower().startswith(cookie_name.lower() + "="):
                    return value
        return ""

    def _extract_samesite(self, raw_sc: str):
        """Extract SameSite value from raw Set-Cookie string"""
        import re
        match = re.search(r"samesite=(\w+)", raw_sc, re.IGNORECASE)
        return match.group(1) if match else None

    def _is_session_cookie(self, name: str) -> bool:
        name_lower = name.lower()
        return any(pattern in name_lower for pattern in self.SESSION_PATTERNS)

    def _inspect_cookie(self, cookie, target) -> dict:
        return {
            "name": cookie.name,
            "domain": cookie.domain,
            "path": cookie.path,
            "expires": str(cookie.expires),
            "likely_session": self._is_session_cookie(cookie.name),
        }

    def _check_cookie_value(self, cookie, findings: list):
        """Detect base64/JWT patterns in cookie values that shouldn't be exposed"""
        import re
        value = cookie.value or ""

        # Detect JWT
        jwt_pattern = r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$"
        if re.match(jwt_pattern, value) and len(value) > 50:
            from ghostrecon.engine import Finding
            findings.append(Finding(
                title=f"JWT Token Detected in Cookie: '{cookie.name}'",
                severity="Info",
                category="Cookie Security",
                description=(
                    f"Cookie '{cookie.name}' appears to contain a JWT token. "
                    "Ensure the token is properly signed and validated server-side."
                ),
                recommendation=(
                    "Verify JWT uses strong algorithms (RS256/ES256). "
                    "Ensure signature verification is enforced."
                ),
                evidence=f"Cookie '{cookie.name}' matches JWT pattern (3-part base64url)",
                cwe="CWE-287",
            ))
