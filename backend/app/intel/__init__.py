"""
TrustShield AI - Threat Intelligence Package
"""

from backend.app.intel.base import (
    BaseThreatIntelAdapter,
    ThreatFeedResult,
    CircuitBreaker,
    MemoryCache,
    URLQuerySanitizer,
)
from backend.app.intel.google_safe_browsing import GoogleSafeBrowsingAdapter
from backend.app.intel.urlhaus import URLhausAdapter
from backend.app.intel.phishtank import PhishTankAdapter
from backend.app.intel.openphish import OpenPhishAdapter
from backend.app.intel.virustotal import VirusTotalAdapter
from backend.app.intel.manager import ThreatIntelManager, threat_intel_manager

__all__ = [
    "BaseThreatIntelAdapter",
    "ThreatFeedResult",
    "CircuitBreaker",
    "MemoryCache",
    "URLQuerySanitizer",
    "GoogleSafeBrowsingAdapter",
    "URLhausAdapter",
    "PhishTankAdapter",
    "OpenPhishAdapter",
    "VirusTotalAdapter",
    "ThreatIntelManager",
    "threat_intel_manager",
]
