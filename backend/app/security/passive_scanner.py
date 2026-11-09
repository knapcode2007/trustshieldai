"""
TrustShield AI - Passive Website Security Assessment Engine
Assesses HTTPS availability, redirect behavior, HSTS, Content-Security-Policy,
X-Content-Type-Options, Referrer-Policy, Clickjacking defenses, and observable cookie security attributes.

Policy Guiding Principles:
1. Low-impact & Passive: HEAD/capped GET requests only, strict timeouts (3.5s), max 3 redirects.
   No port scanning, no directory brute-forcing, no exploit attempts, no credential stuffing.
2. Privacy Preserving: Cookie security attributes (Secure, HttpOnly, SameSite) are analyzed
   WITHOUT collecting or storing sensitive cookie values.
3. Verdict Separation: A website's defensive security posture (missing headers/hardening)
   is strictly separated from its phishing classification. Missing headers alone NEVER cause a malicious verdict.
"""

import http.client
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from backend.app.models.schemas import SecurityHeaderItem, SecurityHeadersSummary
from backend.app.security.ssrf import SSRFSecurityException, SSRFValidator


class CookieSecurityAttribute:
    """Represents security flags of an observable Set-Cookie header without storing secret values."""

    def __init__(self, name: str, is_secure: bool, is_http_only: bool, same_site: str):
        self.name = name  # Sanitized cookie key name
        self.is_secure = is_secure
        self.is_http_only = is_http_only
        self.same_site = same_site  # "Strict", "Lax", "None", or "Unspecified"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "is_secure": self.is_secure,
            "is_http_only": self.is_http_only,
            "same_site": self.same_site,
        }


class PassiveSecurityAssessment:
    """Encapsulates the complete findings of a passive website security inspection."""

    def __init__(
        self,
        target_url: str,
        final_url: str,
        https_available: bool,
        redirect_chain: List[Dict[str, Any]],
        headers_evaluated: Dict[str, str],
        cookie_findings: List[CookieSecurityAttribute],
        weaknesses: List[Dict[str, Any]],
        header_items: List[SecurityHeaderItem],
        score: int,
        grade: str,
        missing_critical_count: int,
        notes: List[str],
    ):
        self.target_url = target_url
        self.final_url = final_url
        self.https_available = https_available
        self.redirect_chain = redirect_chain
        self.headers_evaluated = headers_evaluated
        self.cookie_findings = cookie_findings
        self.weaknesses = weaknesses
        self.header_items = header_items
        self.score = score
        self.grade = grade
        self.missing_critical_count = missing_critical_count
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "https_available": self.https_available,
            "redirect_chain": self.redirect_chain,
            "cookie_security": [c.to_dict() for c in self.cookie_findings],
            "weaknesses": self.weaknesses,
            "score": self.score,
            "grade": self.grade,
            "headers": [
                h.model_dump() if hasattr(h, "model_dump") else h.__dict__
                for h in self.header_items
            ],
            "missing_critical_count": self.missing_critical_count,
            "verdict_separation_note": (
                "Security Posture vs. Phishing Verdict: Configuration weaknesses (e.g. missing CSP or HSTS) "
                "reflect defensive hardening posture and DO NOT indicate malicious intent. Missing headers alone never trigger a malicious or phishing verdict."
            ),
            "notes": self.notes,
        }


class PassiveSecurityScanner:
    """Executes safe, low-impact passive HTTP and defensive header auditing."""

    @classmethod
    def parse_cookie_attributes(cls, set_cookie_headers: List[str]) -> List[CookieSecurityAttribute]:
        """
        Extracts cookie security attributes (Secure, HttpOnly, SameSite)
        WITHOUT saving or storing sensitive cookie values (session secrets/auth tokens).
        """
        cookie_results: List[CookieSecurityAttribute] = []

        for header_val in set_cookie_headers:
            parts = [p.strip() for p in header_val.split(";")]
            if not parts or not parts[0]:
                continue

            # Extract cookie name only, redact value
            first_pair = parts[0].split("=", 1)
            raw_cookie_name = first_pair[0].strip()
            # Clean name for display
            clean_name = re.sub(r"[^\w\-.]", "", raw_cookie_name)[:40]

            is_secure = False
            is_http_only = False
            same_site = "Unspecified"

            for attr in parts[1:]:
                attr_lower = attr.lower()
                if attr_lower == "secure":
                    is_secure = True
                elif attr_lower == "httponly":
                    is_http_only = True
                elif attr_lower.startswith("samesite="):
                    val = attr.split("=", 1)[1].strip().capitalize()
                    same_site = val if val in ("Strict", "Lax", "None") else "Unspecified"

            cookie_results.append(
                CookieSecurityAttribute(
                    name=clean_name,
                    is_secure=is_secure,
                    is_http_only=is_http_only,
                    same_site=same_site,
                )
            )

        return cookie_results

    @classmethod
    def analyze_csp(cls, csp_header: Optional[str]) -> Tuple[bool, List[str], List[Dict[str, Any]]]:
        """Analyzes Content-Security-Policy for unsafe directives, wildcards, and frame-ancestors."""
        if not csp_header:
            return False, [], [
                {
                    "code": "WEAKNESS_NO_CSP",
                    "severity": "medium",
                    "title": "Missing Content-Security-Policy",
                    "description": "No CSP header declared. Browser cannot restrict unauthorized script sources or data injection.",
                    "remediation": "Deploy a Content-Security-Policy with default-src 'self' and authorized asset sources.",
                }
            ]

        csp_lower = csp_header.lower()
        findings: List[Dict[str, Any]] = []
        tags: List[str] = []

        if "'unsafe-inline'" in csp_lower:
            tags.append("unsafe-inline")
            findings.append({
                "code": "WEAKNESS_CSP_UNSAFE_INLINE",
                "severity": "medium",
                "title": "CSP Allows Unsafe Inline Scripts",
                "description": "'unsafe-inline' directive enables execution of inline JavaScript, weakening XSS mitigation.",
                "remediation": "Replace inline scripts with cryptographic nonces (nonce-...) or SHA-256 hashes.",
            })

        if "'unsafe-eval'" in csp_lower:
            tags.append("unsafe-eval")
            findings.append({
                "code": "WEAKNESS_CSP_UNSAFE_EVAL",
                "severity": "medium",
                "title": "CSP Allows eval() Execution",
                "description": "'unsafe-eval' allows dynamic string-to-code compilation (eval, Function), facilitating DOM XSS.",
                "remediation": "Eliminate eval() usages in front-end dependencies and remove 'unsafe-eval'.",
            })

        if "frame-ancestors" in csp_lower:
            tags.append("frame-ancestors-present")
        else:
            tags.append("no-frame-ancestors")

        return True, tags, findings

    @classmethod
    def analyze_hsts(cls, hsts_header: Optional[str], is_https: bool) -> Tuple[bool, Optional[int], List[Dict[str, Any]]]:
        """Validates Strict-Transport-Security duration, subdomains, and preloading."""
        findings: List[Dict[str, Any]] = []

        if not is_https:
            return False, None, [
                {
                    "code": "WEAKNESS_HSTS_OVER_HTTP",
                    "severity": "medium",
                    "title": "HSTS Not Applicable on Cleartext HTTP",
                    "description": "Strict-Transport-Security is ignored by browsers when served over unencrypted HTTP per RFC 6797.",
                    "remediation": "Upgrade all endpoints to HTTPS and emit HSTS exclusively over secure connections.",
                }
            ]

        if not hsts_header:
            return False, None, [
                {
                    "code": "WEAKNESS_NO_HSTS",
                    "severity": "medium",
                    "title": "Missing Strict-Transport-Security",
                    "description": "HSTS header is missing. Visitors can be subjected to SSL-stripping man-in-the-middle attacks.",
                    "remediation": "Enable Strict-Transport-Security with max-age >= 31536000 and includeSubDomains.",
                }
            ]

        # Parse max-age
        match = re.search(r"max-age=(\d+)", hsts_header, re.IGNORECASE)
        max_age = int(match.group(1)) if match else 0

        if max_age < 31536000:
            findings.append({
                "code": "WEAKNESS_HSTS_SHORT_DURATION",
                "severity": "low",
                "title": "HSTS Duration Less than 1 Year",
                "description": f"HSTS max-age is {max_age} seconds. Industry standard (and browser preload requirement) is >= 31536000 (1 year).",
                "remediation": "Increase max-age to 31536000 (or 63072000).",
            })

        if "includesubdomains" not in hsts_header.lower():
            findings.append({
                "code": "WEAKNESS_HSTS_NO_SUBDOMAINS",
                "severity": "low",
                "title": "HSTS Does Not Protect Subdomains",
                "description": "includeSubDomains directive missing. Sibling subdomains remain exposed to cleartext interception.",
                "remediation": "Add 'includeSubDomains' to Strict-Transport-Security header.",
            })

        return True, max_age, findings

    @classmethod
    def assess_url(
        cls,
        target_url: str,
        max_redirects: int = 3,
        timeout: float = 3.5,
    ) -> PassiveSecurityAssessment:
        """
        Executes a passive-only HTTP/HTTPS inspection.
        Uses HEAD requests, honors redirect limits, prevents loops, and revalidates SSRF on every hop.
        """
        current_url = target_url if "://" in target_url else f"https://{target_url}"
        headers_dict: Dict[str, str] = {}
        raw_set_cookies: List[str] = []
        redirect_chain: List[Dict[str, Any]] = []
        visited_urls: Set[str] = set()
        weaknesses: List[Dict[str, Any]] = []
        notes: List[str] = []
        https_available = False
        redirect_count = 0

        while redirect_count <= max_redirects:
            # Check redirect loop
            if current_url in visited_urls:
                weaknesses.append({
                    "code": "ERROR_REDIRECT_LOOP",
                    "severity": "high",
                    "title": "Redirect Loop Detected",
                    "description": f"URL redirected back to previously visited destination: {current_url}",
                    "remediation": "Fix web server rewrite/redirection rules to terminate loop.",
                })
                break
            visited_urls.add(current_url)

            # Re-validate destination against SSRF firewall on EVERY hop
            try:
                canonical, hostname, port, pinned_ip = SSRFValidator.validate_url(current_url)
            except SSRFSecurityException as e:
                weaknesses.append({
                    "code": "SSRF_REDIRECT_BLOCKED",
                    "severity": "critical",
                    "title": "Prohibited Redirection Target",
                    "description": f"Redirect hop to '{current_url}' blocked under SSRF defense: {e.message}",
                    "remediation": "Ensure web application does not redirect clients to private or metadata addresses.",
                })
                break

            parsed = urlparse(canonical)
            is_https = parsed.scheme == "https"
            if is_https:
                https_available = True

            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            # Create connection using pinned IP (DNS rebinding defense)
            if is_https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # Passive check allows inspecting headers even with untrusted cert
                conn = http.client.HTTPSConnection(pinned_ip, port=port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(pinned_ip, port=port, timeout=timeout)

            status_code = None
            try:
                conn.request("HEAD", path, headers={"Host": hostname, "User-Agent": "TrustShieldAI/1.0 (Passive Security Scanner)"})
                resp = conn.getresponse()
                status_code = resp.status

                # Record headers
                for k, v in resp.getheaders():
                    k_lower = k.lower()
                    headers_dict[k_lower] = v
                    if k_lower == "set-cookie":
                        raw_set_cookies.append(v)

                redirect_chain.append({
                    "hop": redirect_count + 1,
                    "url": current_url,
                    "status_code": status_code,
                    "is_https": is_https,
                })

                # Check for redirection
                if status_code in (301, 302, 303, 307, 308):
                    loc = resp.getheader("Location")
                    if not loc:
                        conn.close()
                        break

                    next_url = urljoin(current_url, loc)

                    # Check for insecure downgrade (HTTPS -> HTTP)
                    if is_https and next_url.startswith("http://"):
                        weaknesses.append({
                            "code": "WEAKNESS_INSECURE_DOWNGRADE",
                            "severity": "critical",
                            "title": "Insecure Protocol Downgrade (HTTPS to HTTP)",
                            "description": f"Destination redirected from secure HTTPS to unencrypted cleartext HTTP: {next_url}",
                            "remediation": "Ensure HTTPS connections never redirect to HTTP.",
                        })

                    current_url = next_url
                    redirect_count += 1
                    conn.close()
                    continue

                conn.close()
                break

            except (socket.timeout, http.client.RemoteDisconnected):
                notes.append(f"Connection timeout contacting {hostname}:{port}")
                conn.close()
                break
            except Exception as e:
                notes.append(f"Passive probe connection error: {str(e)}")
                conn.close()
                break

        # Check initial scheme
        initial_is_http = target_url.startswith("http://")
        if initial_is_http and not any(hop["is_https"] for hop in redirect_chain[1:]):
            weaknesses.append({
                "code": "WEAKNESS_HTTP_NOT_UPGRADED",
                "severity": "high",
                "title": "Cleartext HTTP Not Upgraded to HTTPS",
                "description": "Website remains accessible over unencrypted HTTP without automated upgrade to HTTPS.",
                "remediation": "Configure HTTP 301 permanent redirect from HTTP port 80 to HTTPS port 443.",
            })

        # Parse Cookie Security Attributes
        cookie_findings = cls.parse_cookie_attributes(raw_set_cookies)
        for c in cookie_findings:
            if not c.is_secure and https_available:
                weaknesses.append({
                    "code": "WEAKNESS_COOKIE_NOT_SECURE",
                    "severity": "medium",
                    "title": f"Cookie '{c.name}' Missing Secure Flag",
                    "description": "Cookie transmitted over HTTPS lacks the Secure flag, permitting transmission over cleartext HTTP.",
                    "remediation": "Add 'Secure' attribute to Set-Cookie header.",
                })
            if not c.is_http_only:
                weaknesses.append({
                    "code": "WEAKNESS_COOKIE_NOT_HTTPONLY",
                    "severity": "low",
                    "title": f"Cookie '{c.name}' Missing HttpOnly Flag",
                    "description": "Cookie lacks HttpOnly flag and can be read by JavaScript (vulnerable to XSS theft).",
                    "remediation": "Add 'HttpOnly' attribute to sensitive session cookies.",
                })
            if c.same_site == "Unspecified":
                weaknesses.append({
                    "code": "WEAKNESS_COOKIE_NO_SAMESITE",
                    "severity": "low",
                    "title": f"Cookie '{c.name}' Missing SameSite Directive",
                    "description": "Cookie lacks explicit SameSite attribute (Lax or Strict), exposing cross-site request context.",
                    "remediation": "Add 'SameSite=Lax' or 'SameSite=Strict' to Set-Cookie header.",
                })

        # Deep Header Checks
        csp = headers_dict.get("content-security-policy")
        hsts = headers_dict.get("strict-transport-security")
        xfo = headers_dict.get("x-frame-options")
        xcto = headers_dict.get("x-content-type-options")
        ref = headers_dict.get("referrer-policy")
        perm = headers_dict.get("permissions-policy")

        # CSP Analysis
        has_csp, _, csp_weaknesses = cls.analyze_csp(csp)
        weaknesses.extend(csp_weaknesses)

        # HSTS Analysis
        has_hsts, _, hsts_weaknesses = cls.analyze_hsts(hsts, https_available)
        weaknesses.extend(hsts_weaknesses)

        # X-Content-Type-Options
        has_xcto = bool(xcto and "nosniff" in xcto.lower())
        if not has_xcto:
            weaknesses.append({
                "code": "WEAKNESS_NO_NOSNIFF",
                "severity": "medium",
                "title": "Missing X-Content-Type-Options: nosniff",
                "description": "Browser may attempt MIME-sniffing on declared static files, enabling script injection.",
                "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
            })

        # Clickjacking Defense (CSP frame-ancestors OR X-Frame-Options)
        has_clickjacking_def = bool(xfo or (csp and "frame-ancestors" in csp.lower()))
        if not has_clickjacking_def:
            weaknesses.append({
                "code": "WEAKNESS_NO_CLICKJACKING_DEFENSE",
                "severity": "medium",
                "title": "Missing Clickjacking Protection",
                "description": "Neither X-Frame-Options nor CSP frame-ancestors is present. Site can be embedded in hostile iframes.",
                "remediation": "Configure X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.",
            })

        # Standard Security Header Items
        header_items = [
            SecurityHeaderItem(
                name="Content-Security-Policy",
                value=csp,
                present=bool(csp),
                status="pass" if bool(csp) else "fail",
                description="Prevents Cross-Site Scripting (XSS) and data injection by specifying authorized script sources.",
                recommendation="Implement a strict Content-Security-Policy to mitigate unauthorized script execution.",
            ),
            SecurityHeaderItem(
                name="Strict-Transport-Security",
                value=hsts,
                present=bool(hsts),
                status="pass" if bool(hsts) else "fail",
                description="Enforces secure HTTPS connections and prevents SSL stripping man-in-the-middle attacks.",
                recommendation="Enable HSTS with max-age >= 31536000 and includeSubDomains to force HTTPS.",
            ),
            SecurityHeaderItem(
                name="X-Frame-Options",
                value=xfo,
                present=bool(xfo),
                status="pass" if bool(xfo) else "fail",
                description="Guards against Clickjacking by forbidding embedding this page in external iframes.",
                recommendation="Set X-Frame-Options: DENY or SAMEORIGIN to prevent framing and UI redressing attacks.",
            ),
            SecurityHeaderItem(
                name="X-Content-Type-Options",
                value=xcto,
                present=has_xcto,
                status="pass" if has_xcto else "fail",
                description="Instructs browsers not to override the declared MIME type (prevents MIME confusion attacks).",
                recommendation="Configure X-Content-Type-Options: nosniff on all responses.",
            ),
            SecurityHeaderItem(
                name="Referrer-Policy",
                value=ref,
                present=bool(ref),
                status="pass" if bool(ref) else "warn",
                description="Governs how much referrer information is sent along with requests to other origins.",
                recommendation="Set Referrer-Policy: strict-origin-when-cross-origin to protect user privacy.",
            ),
            SecurityHeaderItem(
                name="Permissions-Policy",
                value=perm,
                present=bool(perm),
                status="pass" if bool(perm) else "warn",
                description="Restricts browser feature access such as camera, microphone, and geolocation.",
                recommendation="Define a Permissions-Policy header to disable unused device APIs.",
            ),
        ]

        # Calculate Score & Posture Grade
        pass_count = sum(1 for h in header_items if h.status == "pass")
        score = int((pass_count / len(header_items)) * 100)
        missing_critical = sum(
            1 for h in header_items if not h.present and h.name in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options")
        )

        grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "F"

        return PassiveSecurityAssessment(
            target_url=target_url,
            final_url=current_url,
            https_available=https_available,
            redirect_chain=redirect_chain,
            headers_evaluated=headers_dict,
            cookie_findings=cookie_findings,
            weaknesses=weaknesses,
            header_items=header_items,
            score=score,
            grade=grade,
            missing_critical_count=missing_critical,
            notes=notes,
        )


passive_scanner = PassiveSecurityScanner()
