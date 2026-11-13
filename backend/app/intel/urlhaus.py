"""
TrustShield AI - abuse.ch URLhaus Adapter
Complies with abuse.ch URLhaus API documentation.

Integration Requirements:
- Endpoints: https://urlhaus-api.abuse.ch/v1/url/ and https://urlhaus-api.abuse.ch/v1/host/
- Credentials: Server-side URLHAUS_API_KEY (Auth-Key HTTP header). Mandatory for all API lookups.
- Key Portal: Free Auth-Key registration at https://auth.abuse.ch/
- License: abuse.ch URLhaus is licensed under CC0 / Open Source and dedicated to sharing malware URLs.
"""

import os
import json
import urllib.parse
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from backend.app.intel.base import BaseThreatIntelAdapter, ThreatFeedResult


class URLhausAdapter(BaseThreatIntelAdapter):
    """Adapter for abuse.ch URLhaus Malware & Phishing URL/Host Database."""

    URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
    HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

    RESERVED_DOCUMENTATION_DOMAINS = {
        "example.com",
        "example.net",
        "example.org",
        "localhost",
    }

    def __init__(self):
        super().__init__(
            provider_id="urlhaus",
            provider_name="abuse.ch URLhaus",
            attribution="URLhaus © abuse.ch. Project dedicated to sharing malicious URLs used for malware distribution.",
            failure_threshold=3,
            recovery_timeout=45.0,
        )

    @staticmethod
    def get_api_key() -> str:
        """Retrieves URLHAUS_API_KEY from environment or settings safely."""
        key = os.getenv("URLHAUS_API_KEY", "").strip()
        if not key:
            try:
                from backend.app.core.config import settings
                key = getattr(settings, "URLHAUS_API_KEY", "").strip()
            except Exception:
                pass
        return key

    def is_configured(self) -> bool:
        """
        abuse.ch URLhaus requires a valid Auth-Key for API lookups (free from https://auth.abuse.ch).
        Guarantees that unconfigured environments cleanly report 'unavailable' rather than crashing with HTTP 401.
        """
        enabled = os.getenv("URLHAUS_ENABLED", "true").lower() in ("true", "1", "yes")
        has_key = bool(self.get_api_key())
        return enabled and has_key

    def _execute_lookup(self, sanitized_url: str, domain: str) -> ThreatFeedResult:
        clean_domain = domain.lower().strip(".")
        is_reserved = (
            clean_domain in self.RESERVED_DOCUMENTATION_DOMAINS
            or clean_domain.endswith((".example", ".test", ".invalid", ".localhost"))
        )

        # Fast-path for root reserved documentation domains (RFC 2606 / RFC 6761).
        # Avoids unnecessary external API roundtrips for bare documentation hosts.
        # Specific sub-paths continue to exact URL lookup so malicious paths/payloads are never bypassed.
        url_path = urllib.parse.urlsplit(sanitized_url).path
        if is_reserved and url_path in ("", "/"):
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="no_match",
                matched=False,
                match_type="none",
                confidence=95,
                details=f"Host '{domain}' is an IANA-reserved documentation domain (RFC 2606/6761). Benign by specification.",
                attribution=self.attribution,
            )

        auth_key = self.get_api_key()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "TrustShieldAI/1.0 (+https://trustshield.ai)",
            "Auth-Key": auth_key,
        }

        # 1. Exact URL lookup
        form_data = urllib.parse.urlencode({"url": sanitized_url}).encode("utf-8")
        req = urllib.request.Request(self.URL_ENDPOINT, data=form_data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                query_status = data.get("query_status")

                if query_status == "ok":
                    threat = data.get("threat", "malware_download")
                    url_status = data.get("url_status", "unknown")
                    reference = data.get("urlhaus_reference")
                    tags = data.get("tags") or []

                    # Map threat classification to phishing vs malware taxonomy
                    tags_lower = [str(t).lower() for t in tags]
                    combined_threat_str = f"{threat} {' '.join(tags_lower)}".lower()
                    is_phishing = any(term in combined_threat_str for term in ("phish", "social", "credential", "steal", "fake", "login"))
                    threat_category = "phishing" if is_phishing else ("malware" if "malware" in threat.lower() else threat)

                    is_online = str(url_status).lower() == "online"
                    status_desc = "active" if is_online else f"historical ({url_status})"
                    confidence = 98 if is_online else 92

                    return ThreatFeedResult(
                        provider=self.provider_id,
                        provider_name=self.provider_name,
                        status="available",
                        matched=True,
                        match_type="exact_url",
                        threat_type=threat_category,
                        confidence=confidence,
                        details=f"URLhaus confirmed {status_desc} {threat_category} distribution URL: {threat} (Status: {url_status}, Tags: {', '.join(tags) if tags else 'none'})",
                        reference_url=reference,
                        attribution=self.attribution,
                        raw_evidence=data,
                    )

                if query_status == "no_results":
                    # Fallback to host check to detect active malicious infrastructure
                    host_res = self._check_host(domain, headers)
                    if host_res:
                        return host_res

                    return ThreatFeedResult(
                        provider=self.provider_id,
                        provider_name=self.provider_name,
                        status="no_match",
                        matched=False,
                        match_type="none",
                        confidence=90,
                        details="Target URL and host not indexed in URLhaus malware database.",
                        attribution=self.attribution,
                    )

                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="no_match",
                    matched=False,
                    match_type="none",
                    details=f"URLhaus query status: {query_status}",
                    attribution=self.attribution,
                )

        except urllib.error.HTTPError as e:
            if e.code == 429:
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="rate_limited",
                    matched=False,
                    match_type="none",
                    rate_limited=True,
                    details="URLhaus API rate limit reached (HTTP 429).",
                    attribution=self.attribution,
                )
            elif e.code in (401, 403):
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="error",
                    matched=False,
                    match_type="none",
                    details=f"URLhaus authentication failed (HTTP {e.code}). Verify URLHAUS_API_KEY.",
                    attribution=self.attribution,
                )
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                details=f"URLhaus HTTP error: {e.code}",
                attribution=self.attribution,
            )
        except urllib.error.URLError as e:
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                details=f"URLhaus connection error: {str(e.reason)}",
                attribution=self.attribution,
            )
        except Exception as e:
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                details=f"URLhaus connection error: {str(e)}",
                attribution=self.attribution,
            )

    def _check_host(self, domain: str, headers: Dict[str, str]) -> Optional[ThreatFeedResult]:
        """
        Inspects host reputation for live malicious infrastructure.
        Integrity rules:
        1. IANA reserved documentation domains (RFC 2606/6761) are never flagged as malicious.
        2. A host only qualifies as a genuine threat match if it has ACTIVE (online) payloads
           or is actively listed on Spamhaus DBL / SURBL.
        3. Stale/offline historical takedowns never trigger a positive threat match on a clean URL.
        """
        clean_domain = domain.lower().strip(".")
        if clean_domain in self.RESERVED_DOCUMENTATION_DOMAINS or clean_domain.endswith((".example", ".test", ".invalid", ".localhost")):
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="no_match",
                matched=False,
                match_type="none",
                confidence=95,
                details=f"Host '{domain}' is an IANA-reserved documentation domain (RFC 2606/6761). Benign by specification.",
                attribution=self.attribution,
            )

        try:
            form_data = urllib.parse.urlencode({"host": domain}).encode("utf-8")
            req = urllib.request.Request(self.HOST_ENDPOINT, data=form_data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("query_status") == "ok":
                    reference = data.get("urlhaus_reference")
                    urls = data.get("urls") or []

                    try:
                        total_historical = int(data.get("url_count") or 0)
                    except (ValueError, TypeError):
                        total_historical = len(urls)

                    # Check DNSBL blacklists (Spamhaus DBL, SURBL)
                    blacklists = data.get("blacklists") or {}
                    spamhaus_dbl = str(blacklists.get("spamhaus_dbl", "")).lower()
                    surbl = str(blacklists.get("surbl", "")).lower()
                    is_blacklisted = (
                        ("listed" in spamhaus_dbl and "not listed" not in spamhaus_dbl) or
                        ("listed" in surbl and "not listed" not in surbl)
                    )

                    # Count active/online payloads only
                    online_payloads = [
                        u for u in urls
                        if isinstance(u, dict) and str(u.get("url_status", "")).lower() == "online"
                    ]
                    online_count = len(online_payloads)

                    # Only declare a threat match if the host has LIVE online malware or active blacklist listing
                    if online_count > 0 or is_blacklisted:
                        active_threats = [u.get("threat", "") for u in (online_payloads or urls) if isinstance(u, dict)]
                        active_tags = []
                        for u in (online_payloads or urls):
                            if isinstance(u, dict) and u.get("tags"):
                                active_tags.extend(u.get("tags"))
                        combined_host_str = f"{' '.join(active_threats)} {' '.join(str(t) for t in active_tags)}".lower()
                        is_phishing_host = any(term in combined_host_str for term in ("phish", "credential", "steal", "social", "fake"))
                        threat_type = "phishing_host" if is_phishing_host else "malware_host"

                        if is_blacklisted and online_count > 0:
                            details = f"Host '{domain}' is blacklisted (Spamhaus/SURBL) and actively serving {online_count} live payload(s) in URLhaus."
                        elif is_blacklisted:
                            details = f"Host '{domain}' is actively blacklisted on Spamhaus DBL/SURBL via URLhaus ({total_historical} cataloged submissions)."
                        else:
                            details = f"Host '{domain}' is actively serving {online_count} live {threat_type.replace('_host', '')} payload(s) in URLhaus."

                        return ThreatFeedResult(
                            provider=self.provider_id,
                            provider_name=self.provider_name,
                            status="available",
                            matched=True,
                            match_type="host",
                            threat_type=threat_type,
                            confidence=90 if (online_count >= 3 or is_blacklisted) else 80,
                            details=details,
                            reference_url=reference,
                            attribution=self.attribution,
                            raw_evidence=data,
                        )
                    else:
                        # 0 online payloads and not blacklisted: historical takedowns do not implicate this clean URL
                        if total_historical > 0:
                            details = f"Target URL is clean. Host '{domain}' has {total_historical} historical takedown(s) in URLhaus, but 0 active online payloads."
                        else:
                            details = f"Target URL and host '{domain}' not actively indexed in URLhaus."

                        return ThreatFeedResult(
                            provider=self.provider_id,
                            provider_name=self.provider_name,
                            status="no_match",
                            matched=False,
                            match_type="none",
                            confidence=90,
                            details=details,
                            reference_url=reference,
                            attribution=self.attribution,
                            raw_evidence=data,
                        )
        except Exception:
            pass
        return None
