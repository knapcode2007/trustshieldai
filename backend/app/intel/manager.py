"""
TrustShield AI - Threat Intelligence Orchestrator
Coordinates Google Safe Browsing, abuse.ch URLhaus, PhishTank, and OpenPhish adapters.
"""

import concurrent.futures
from typing import Dict, Any, List, Optional

from backend.app.intel.base import ThreatFeedResult, URLQuerySanitizer
from backend.app.intel.google_safe_browsing import GoogleSafeBrowsingAdapter
from backend.app.intel.urlhaus import URLhausAdapter
from backend.app.intel.phishtank import PhishTankAdapter
from backend.app.intel.openphish import OpenPhishAdapter


class ThreatIntelManager:
    """Orchestrates threat intelligence lookups across configured provider adapters."""

    def __init__(self):
        self.adapters = [
            GoogleSafeBrowsingAdapter(),
            URLhausAdapter(),
            PhishTankAdapter(),
            OpenPhishAdapter(),
        ]

    def check_all(self, raw_url: str, domain: str, max_workers: int = 4) -> List[ThreatFeedResult]:
        """
        Executes lookups across all adapters concurrently with strict error isolation.
        Guarantees that unconfigured or failed providers are never represented as clean.
        """
        results: List[ThreatFeedResult] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_adapter = {
                executor.submit(adapter.lookup, raw_url, domain): adapter
                for adapter in self.adapters
            }

            for future in concurrent.futures.as_completed(future_to_adapter):
                adapter = future_to_adapter[future]
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    # Never represent an unexpected crash as a clean result!
                    results.append(
                        ThreatFeedResult(
                            provider=adapter.provider_id,
                            provider_name=adapter.provider_name,
                            status="error",
                            matched=False,
                            match_type="none",
                            details=f"Lookup failed unexpectedly: {str(e)}",
                            attribution=adapter.attribution,
                        )
                    )

        # Sort predictably by provider_id
        results.sort(key=lambda r: r.provider)
        return results

    def aggregate_summary(self, results: List[ThreatFeedResult]) -> Dict[str, Any]:
        """Calculates risk engine telemetry from threat feed results."""
        matched_results = [r for r in results if r.matched]
        matched_count = len(matched_results)
        operational_count = len([r for r in results if r.status in ("available", "no_match")])
        rate_limited_count = len([r for r in results if r.status == "rate_limited"])
        unavailable_count = len([r for r in results if r.status == "unavailable"])
        error_count = len([r for r in results if r.status == "error"])

        # Determine highest match type and confidence
        has_exact_url_match = any(r.match_type == "exact_url" for r in matched_results)
        has_host_match = any(r.match_type in ("host", "domain") for r in matched_results)

        max_confidence = max([r.confidence for r in matched_results], default=0)

        # Map threat categories
        threat_types = list({r.threat_type for r in matched_results if r.threat_type})

        return {
            "total_providers": len(results),
            "operational_count": operational_count,
            "matched_count": matched_count,
            "rate_limited_count": rate_limited_count,
            "unavailable_count": unavailable_count,
            "error_count": error_count,
            "has_exact_url_match": has_exact_url_match,
            "has_host_match": has_host_match,
            "max_confidence": max_confidence,
            "threat_types": threat_types,
            "results": [r.to_dict() for r in results],
        }


threat_intel_manager = ThreatIntelManager()
