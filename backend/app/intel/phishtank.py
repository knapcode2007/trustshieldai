"""
TrustShield AI - PhishTank Adapter
Complies with PhishTank API documentation and Developer Terms.

Integration Requirements:
- Endpoint: https://checkurl.phishtank.com/checkurl/
- Credentials: Server-side PHISHTANK_API_KEY (registered developer app_key)
- License: PhishTank © Cisco Systems, Inc. Developer Terms of Service apply.
"""

import os
import json
import urllib.parse
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from backend.app.intel.base import BaseThreatIntelAdapter, ThreatFeedResult


class PhishTankAdapter(BaseThreatIntelAdapter):
    """Adapter for Cisco / OpenDNS PhishTank Verified Phishing Database."""

    API_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self):
        super().__init__(
            provider_id="phishtank",
            provider_name="PhishTank",
            attribution="PhishTank © Cisco Systems, Inc. / OpenDNS. Data licensed under PhishTank Developer Terms.",
            failure_threshold=3,
            recovery_timeout=45.0,
        )

    def is_configured(self) -> bool:
        return bool(os.getenv("PHISHTANK_API_KEY", "").strip())

    def _execute_lookup(self, sanitized_url: str, domain: str) -> ThreatFeedResult:
        app_key = os.getenv("PHISHTANK_API_KEY", "").strip()

        form_data = urllib.parse.urlencode({
            "url": sanitized_url,
            "format": "json",
            "app_key": app_key,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.API_ENDPOINT,
            data=form_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "phishtank/trustshield-ai-security-platform",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", {})

                in_database = results.get("in_database", False)
                if in_database:
                    verified = results.get("verified") == "y"
                    phish_id = results.get("phish_id")
                    phish_detail = results.get("phish_detail_page")

                    return ThreatFeedResult(
                        provider=self.provider_id,
                        provider_name=self.provider_name,
                        status="available",
                        matched=True,
                        match_type="exact_url",
                        threat_type="phishing",
                        confidence=96 if verified else 75,
                        details=f"PhishTank confirmed phishing submission (ID: {phish_id}, Community verified: {'Yes' if verified else 'Pending validation'})",
                        reference_url=phish_detail,
                        attribution=self.attribution,
                        raw_evidence=results,
                    )

                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="no_match",
                    matched=False,
                    match_type="none",
                    confidence=90,
                    details="URL not found in PhishTank phishing database.",
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
                    details="PhishTank API query rate limit exceeded (HTTP 429).",
                    attribution=self.attribution,
                )
            elif e.code in (401, 403):
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="error",
                    matched=False,
                    match_type="none",
                    details="PhishTank developer key invalid or rejected. Check PHISHTANK_API_KEY.",
                    attribution=self.attribution,
                )
            else:
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="error",
                    matched=False,
                    match_type="none",
                    details=f"PhishTank upstream HTTP error: {e.code}",
                    attribution=self.attribution,
                )
        except Exception as e:
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                details=f"PhishTank connection error: {str(e)}",
                attribution=self.attribution,
            )
