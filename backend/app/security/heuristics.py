from typing import List, Dict, Any
from urllib.parse import urlparse
from backend.app.models.schemas import HeuristicFinding, HeuristicResults
from backend.app.ml.pipeline import PhishingFeatureExtractor

class SecurityHeuristicsEngine:
    """Security rule engine evaluating domain typosquatting, lexical red flags, and structural anomalies."""
    
    HIGH_PROFILE_BRANDS = [
        "paypal", "google", "microsoft", "apple", "netflix", "chase", "wellsfargo",
        "bankofamerica", "amazon", "facebook", "instagram", "coinbase", "binance"
    ]

    @classmethod
    def evaluate(cls, url: str) -> HeuristicResults:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        domain = parsed.netloc.lower().split(":")[0]
        path = parsed.path.lower()
        full_string = f"{domain}{path}"
        
        findings: List[HeuristicFinding] = []
        features = PhishingFeatureExtractor.extract_features(url)
        detected_brands: List[str] = []

        # Check for brand squatting
        for brand in cls.HIGH_PROFILE_BRANDS:
            if brand in full_string and not domain.endswith(f".{brand}.com") and domain != f"{brand}.com":
                detected_brands.append(brand)
                findings.append(HeuristicFinding(
                    rule_id="RULE_BRAND_SPOOF_01",
                    category="brand_impersonation",
                    severity="high",
                    description=f"Potential brand squatting detected targeting legitimate brand '{brand}'",
                    score_impact=35
                ))

        # Check for raw IP address
        if features["has_ip"]:
            findings.append(HeuristicFinding(
                rule_id="RULE_IP_HOST_02",
                category="evasion",
                severity="high",
                description="Target host utilizes a raw IPv4 address rather than a registered domain name",
                score_impact=30
            ))

        # Check for excessive subdomains
        if features["subdomain_count"] >= 3:
            findings.append(HeuristicFinding(
                rule_id="RULE_SUBDOMAIN_DEEP_03",
                category="structure",
                severity="medium",
                description=f"Deep subdomain nesting detected ({features['subdomain_count']} levels)",
                score_impact=15
            ))

        # Check for suspicious keywords
        if features["keyword_match_count"] > 0:
            findings.append(HeuristicFinding(
                rule_id="RULE_SUSP_KEYWORDS_04",
                category="lexical",
                severity="medium",
                description=f"Authentication/security tokens detected in path: {', '.join(features['suspicious_keywords'])}",
                score_impact=min(25, features["keyword_match_count"] * 10)
            ))

        # High entropy URL
        if features["entropy"] > 4.1:
            findings.append(HeuristicFinding(
                rule_id="RULE_HIGH_ENTROPY_05",
                category="obfuscation",
                severity="low",
                description=f"High character entropy ({features['entropy']:.2f}) indicates possible hash or obfuscated token",
                score_impact=10
            ))

        return HeuristicResults(
            suspicious_keywords=features["suspicious_keywords"],
            has_ip_in_url=bool(features["has_ip"]),
            subdomain_count=features["subdomain_count"],
            url_entropy=features["entropy"],
            detected_brand_squats=detected_brands,
            findings=findings
        )

heuristics_engine = SecurityHeuristicsEngine()
