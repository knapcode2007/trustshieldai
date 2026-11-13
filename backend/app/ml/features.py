"""
TrustShield AI - URL Feature Extraction Engine
Extracts lexical, structural, information-theoretic, and brand impersonation features
suitable for training scikit-learn classifiers (Random Forest, Gradient Boosting, etc.).
"""

import math
import re
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


class URLFeatureExtractor:
    """Production-grade feature extraction for phishing and malicious website detection."""

    # High-value target brands frequently targeted by spear-phishing & credential theft
    TARGET_BRANDS: Dict[str, Set[str]] = {
        "paypal": {"paypal.com", "paypal-communication.com", "paypal-corp.com"},
        "google": {"google.com", "accounts.google.com", "google.co.uk", "gmail.com"},
        "microsoft": {"microsoft.com", "login.microsoftonline.com", "live.com", "office.com", "outlook.com"},
        "apple": {"apple.com", "icloud.com", "appleid.apple.com"},
        "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"},
        "netflix": {"netflix.com"},
        "chase": {"chase.com"},
        "wellsfargo": {"wellsfargo.com"},
        "bankofamerica": {"bankofamerica.com"},
        "citibank": {"citi.com", "citibank.com"},
        "steam": {"steampowered.com", "steamcommunity.com"},
        "facebook": {"facebook.com", "fb.com", "meta.com"},
        "instagram": {"instagram.com"},
        "whatsapp": {"whatsapp.com"},
        "dropbox": {"dropbox.com"},
        "coinbase": {"coinbase.com"},
        "binance": {"binance.com"},
        "dhl": {"dhl.com"},
        "fedex": {"fedex.com"},
        "usps": {"usps.com"},
    }

    # Suspicious keywords organized by semantic category
    AUTH_KEYWORDS = [
        "login", "signin", "sign-in", "log-in", "auth", "authenticate", "sso", "session",
        "credential", "password", "passcode", "security-key"
    ]
    SECURITY_KEYWORDS = [
        "verify", "verification", "secure", "security", "protect", "safe", "confirm",
        "confirmation", "validate", "validation", "checkpoint", "re-authenticate"
    ]
    FINANCIAL_KEYWORDS = [
        "banking", "bank", "wallet", "crypto", "payment", "pay", "invoice", "bill",
        "refund", "cash", "wire", "transfer", "credit-card", "debit"
    ]
    URGENCY_KEYWORDS = [
        "account", "update", "suspend", "suspended", "locked", "alert", "recover",
        "recovery", "urgent", "notice", "action-required", "expire", "expiration"
    ]

    ALL_KEYWORDS = list(set(AUTH_KEYWORDS + SECURITY_KEYWORDS + FINANCIAL_KEYWORDS + URGENCY_KEYWORDS))

    # High-risk TLDs disproportionately associated with disposable abuse domains
    HIGH_RISK_TLDS = {
        "xyz", "top", "work", "click", "buzz", "loan", "tk", "ml", "ga", "cf", "gq",
        "fit", "country", "surf", "racing", "gdn", "date", "stream", "men", "party"
    }

    IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    HEX_STRING_PATTERN = re.compile(r"[0-9a-fA-F]{16,}")

    # Standardized 25 numerical feature names for machine learning models
    FEATURE_NAMES: List[str] = [
        "url_length",
        "domain_length",
        "path_length",
        "query_length",
        "subdomain_count",
        "subdomain_length",
        "has_subdomain",
        "is_high_risk_tld",
        "domain_digit_ratio",
        "domain_vowel_ratio",
        "url_entropy",
        "domain_entropy",
        "path_entropy",
        "auth_keyword_count",
        "security_keyword_count",
        "financial_keyword_count",
        "urgency_keyword_count",
        "total_keyword_count",
        "is_punycode",
        "has_ip_literal",
        "count_dots",
        "count_hyphens",
        "count_underscores",
        "count_at",
        "count_delimiters",
        "brand_squatting_detected",
        "brand_in_subdomain",
        "consecutive_hyphens",
        "has_hex_pattern",
        "is_https",
    ]

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Computes Shannon entropy (information density) of a string."""
        if not text:
            return 0.0
        length = len(text)
        prob_dist = [text.count(c) / length for c in set(text)]
        return round(-sum(p * math.log2(p) for p in prob_dist), 4)

    @classmethod
    def extract_domain_info(cls, netloc: str) -> Dict[str, Any]:
        """Parses fully qualified domain into registered domain, subdomains, and TLD."""
        clean_netloc = netloc.split(":")[0].lower()
        parts = clean_netloc.split(".")

        if len(parts) <= 1:
            return {
                "clean_domain": clean_netloc,
                "registered_domain": clean_netloc,
                "tld": "",
                "subdomains": [],
                "subdomain_count": 0,
            }

        # Handle two-part TLDs like .co.uk, .com.au, .gov.uk
        two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.uk", "co.jp", "com.br"}
        joined_last_two = ".".join(parts[-2:])
        if len(parts) >= 3 and joined_last_two in two_part_tlds:
            tld = joined_last_two
            registered_domain = ".".join(parts[-3:])
            subdomains = parts[:-3]
        else:
            tld = parts[-1]
            registered_domain = ".".join(parts[-2:])
            subdomains = parts[:-2]

        return {
            "clean_domain": clean_netloc,
            "registered_domain": registered_domain,
            "tld": tld,
            "subdomains": subdomains,
            "subdomain_count": len(subdomains),
        }

    @classmethod
    def check_brand_squatting(cls, netloc: str, path: str) -> Tuple[bool, bool, List[str]]:
        """
        Detects misleading brand tokens appearing in subdomains or path
        when the registered domain is not legitimate.
        """
        domain_info = cls.extract_domain_info(netloc)
        reg_domain = domain_info["registered_domain"]
        subdomain_str = ".".join(domain_info["subdomains"]).lower()
        path_lower = path.lower()

        squatted_brands: List[str] = []
        brand_in_subdomain = False
        brand_squatting = False

        for brand, legitimate_domains in cls.TARGET_BRANDS.items():
            is_legit = any(reg_domain == leg or reg_domain.endswith("." + leg) for leg in legitimate_domains)
            
            # Check if brand appears in subdomain or path while registered domain is NOT legitimate
            if not is_legit:
                if brand in subdomain_str:
                    brand_in_subdomain = True
                    brand_squatting = True
                    squatted_brands.append(brand)
                elif brand in path_lower and any(kw in path_lower for kw in ["login", "signin", "auth", "verify", "secure"]):
                    brand_squatting = True
                    squatted_brands.append(brand)

        return brand_squatting, brand_in_subdomain, squatted_brands

    @classmethod
    def extract_features(cls, url: str) -> Dict[str, Any]:
        """Extracts complete feature dictionary containing both scalar and list properties."""
        if not url:
            url = ""

        # Normalize URL for parsing
        test_url = url if "://" in url else f"https://{url}"
        parsed = urlparse(test_url)

        netloc = (parsed.netloc or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        full_text = f"{netloc}{path}?{query}" if query else f"{netloc}{path}"

        domain_info = cls.extract_domain_info(netloc)
        clean_domain = domain_info["clean_domain"]
        reg_domain = domain_info["registered_domain"]
        tld = domain_info["tld"]
        subdomain_count = domain_info["subdomain_count"]
        subdomain_str = ".".join(domain_info["subdomains"])

        # Check IP literal
        has_ip = bool(cls.IP_PATTERN.match(clean_domain))

        # Check Punycode and perform safe Unicode normalization
        is_punycode_ace = "xn--" in clean_domain
        has_non_ascii = any(ord(c) > 127 for c in clean_domain)
        is_punycode = is_punycode_ace or has_non_ascii

        # Decode IDN for natural language entropy and character distribution calculations
        decoded_domain = clean_domain
        if is_punycode_ace:
            try:
                # RFC 3492 / IDNA 2008 decode with NFC normalization
                decoded_domain = unicodedata.normalize("NFC", clean_domain.encode("ascii").decode("idna"))
            except Exception:
                # Malformed IDN / Punycode falls back safely to raw ASCII
                decoded_domain = clean_domain
        elif has_non_ascii:
            try:
                decoded_domain = unicodedata.normalize("NFC", clean_domain)
            except Exception:
                decoded_domain = clean_domain

        # Calculate character ratios in domain (using decoded domain if IDN)
        domain_len = len(clean_domain)
        digit_count = sum(1 for c in clean_domain if c.isdigit())
        vowel_count = sum(1 for c in clean_domain if c in "aeiou")
        domain_digit_ratio = round(digit_count / max(1, domain_len), 4)
        domain_vowel_ratio = round(vowel_count / max(1, domain_len), 4)

        # Entropies (using normalized decoded domain for domain_entropy to avoid Punycode inflation)
        url_entropy = cls.calculate_entropy(url)
        domain_entropy = cls.calculate_entropy(decoded_domain)
        path_entropy = cls.calculate_entropy(path)

        # Keyword matching
        text_lower = full_text.lower()
        auth_matches = [kw for kw in cls.AUTH_KEYWORDS if kw in text_lower]
        sec_matches = [kw for kw in cls.SECURITY_KEYWORDS if kw in text_lower]
        fin_matches = [kw for kw in cls.FINANCIAL_KEYWORDS if kw in text_lower]
        urg_matches = [kw for kw in cls.URGENCY_KEYWORDS if kw in text_lower]
        all_matches = list(set(auth_matches + sec_matches + fin_matches + urg_matches))

        # Delimiters and unusual characters
        count_dots = full_text.count(".")
        count_hyphens = full_text.count("-")
        count_underscores = full_text.count("_")
        count_at = full_text.count("@")
        count_delimiters = sum(full_text.count(ch) for ch in ["-", "_", "@", "?", "=", "&", "%", "~"])

        # Brand spoofing heuristics
        brand_squatting, brand_in_subdomain, squatted_brands = cls.check_brand_squatting(netloc, path)

        # Patterns: Consecutive hyphens check (ignore the protocol 'xn--' prefix in IDNs)
        text_without_ace = re.sub(r'(^|[\./])xn--', r'\1', full_text)
        consecutive_hyphens = 1 if "--" in text_without_ace else 0
        has_hex = 1 if bool(cls.HEX_STRING_PATTERN.search(path)) else 0
        is_https = 1 if parsed.scheme == "https" else 0
        is_high_risk_tld = 1 if tld in cls.HIGH_RISK_TLDS else 0

        features: Dict[str, Any] = {
            # Metadata
            "raw_url": url,
            "registered_domain": reg_domain,
            "clean_domain": clean_domain,
            "tld": tld,
            # Numerical features matching FEATURE_NAMES
            "url_length": len(url),
            "domain_length": domain_len,
            "path_length": len(path),
            "query_length": len(query),
            "subdomain_count": subdomain_count,
            "subdomain_length": len(subdomain_str),
            "has_subdomain": 1 if subdomain_count > 0 else 0,
            "is_high_risk_tld": is_high_risk_tld,
            "domain_digit_ratio": domain_digit_ratio,
            "domain_vowel_ratio": domain_vowel_ratio,
            "url_entropy": url_entropy,
            "domain_entropy": domain_entropy,
            "path_entropy": path_entropy,
            "auth_keyword_count": len(auth_matches),
            "security_keyword_count": len(sec_matches),
            "financial_keyword_count": len(fin_matches),
            "urgency_keyword_count": len(urg_matches),
            "total_keyword_count": len(all_matches),
            "is_punycode": 1 if is_punycode else 0,
            "has_ip_literal": 1 if has_ip else 0,
            "count_dots": count_dots,
            "count_hyphens": count_hyphens,
            "count_underscores": count_underscores,
            "count_at": count_at,
            "count_delimiters": count_delimiters,
            "brand_squatting_detected": 1 if brand_squatting else 0,
            "brand_in_subdomain": 1 if brand_in_subdomain else 0,
            "consecutive_hyphens": consecutive_hyphens,
            "has_hex_pattern": has_hex,
            "is_https": is_https,
            # Explanatory properties
            "matched_keywords": all_matches,
            "squatted_brands": squatted_brands,
            # Backwards compatibility aliases
            "has_ip": 1 if has_ip else 0,
            "entropy": url_entropy,
            "suspicious_keywords": all_matches,
            "keyword_match_count": len(all_matches),
        }

        return features

    @classmethod
    def to_feature_vector(cls, features: Dict[str, Any]) -> List[float]:
        """Maps an extracted feature dictionary into the canonical numerical feature vector."""
        return [float(features.get(name, 0.0)) for name in cls.FEATURE_NAMES]
