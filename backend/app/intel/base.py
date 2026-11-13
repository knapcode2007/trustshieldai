"""
TrustShield AI - Modular Threat Intelligence Framework
Base Adapter, Sanitization, Circuit Breaker, and Result Schemas.

Integrity Guarantees:
1. Failed or unconfigured lookups are NEVER represented as clean ("no_match").
   Statuses strictly differentiate: 'available', 'no_match', 'unavailable', 'rate_limited', and 'error'.
2. Sensitive URL query tokens are sanitized before outbound queries to prevent credential leaks.
3. Resilience via TTL caching, bounded retries with backoff, and circuit breakers.
4. Attribution and terms of service compliance for all external providers.
"""

import time
import re
import urllib.parse
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone


class URLQuerySanitizer:
    """
    Strips or redacts sensitive query parameters (e.g. passwords, bearer tokens, API keys)
    and sensitive URL path components (e.g. password-reset tokens, JWTs, UUIDs, user emails)
    from target URLs before outbound transmission to external threat feeds.
    """

    SENSITIVE_KEY_PATTERNS = [
        re.compile(r"token", re.I),
        re.compile(r"auth", re.I),
        re.compile(r"pass(word)?", re.I),
        re.compile(r"secret", re.I),
        re.compile(r"key", re.I),
        re.compile(r"session", re.I),
        re.compile(r"code", re.I),
        re.compile(r"sig(nature)?", re.I),
        re.compile(r"cred(ential)?", re.I),
        re.compile(r"api_?key", re.I),
        re.compile(r"access_?token", re.I),
        re.compile(r"refresh_?token", re.I),
        re.compile(r"jwt", re.I),
        re.compile(r"state", re.I),
        re.compile(r"email", re.I),
    ]

    SENSITIVE_PATH_ACTIONS = {
        "reset-password",
        "password-reset",
        "forgot-password",
        "verify-email",
        "email-verification",
        "magic-link",
        "auth-callback",
        "invitation",
        "invite",
        "otp",
        "mfa",
        "2fa",
    }

    JWT_PATTERN = re.compile(r"^eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}$")
    UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

    @classmethod
    def sanitize(cls, raw_url: str) -> Tuple[str, bool, List[str]]:
        """
        Sanitizes sensitive path tokens and query parameters.
        Returns:
            (sanitized_url, was_sanitized, list_of_redacted_param_names)
        """
        try:
            parsed = urllib.parse.urlsplit(raw_url)
            redacted_keys: List[str] = []
            path_changed = False
            new_path = parsed.path

            # 1. Sanitize sensitive path segments
            if parsed.path and parsed.path != "/":
                segments = parsed.path.split("/")
                sanitized_segments = []
                for i, seg in enumerate(segments):
                    prev_seg = segments[i - 1].lower() if i > 0 else ""
                    if prev_seg in cls.SENSITIVE_PATH_ACTIONS and seg and seg != "[REDACTED_TOKEN]":
                        sanitized_segments.append("[REDACTED_TOKEN]")
                        redacted_keys.append(f"path:{prev_seg}")
                        path_changed = True
                    elif cls.JWT_PATTERN.match(seg):
                        sanitized_segments.append("[REDACTED_JWT]")
                        redacted_keys.append("path:jwt")
                        path_changed = True
                    elif cls.UUID_PATTERN.match(seg):
                        sanitized_segments.append("[REDACTED_UUID]")
                        redacted_keys.append("path:uuid")
                        path_changed = True
                    elif cls.EMAIL_PATTERN.match(seg):
                        sanitized_segments.append("[REDACTED_EMAIL]")
                        redacted_keys.append("path:email")
                        path_changed = True
                    else:
                        sanitized_segments.append(seg)
                if path_changed:
                    new_path = "/".join(sanitized_segments)

            # 2. Sanitize sensitive query parameters
            query_changed = False
            new_query = parsed.query
            if parsed.query:
                query_dict = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                sanitized_query_pairs = []

                for k, values in query_dict.items():
                    is_sensitive = any(pattern.search(k) for pattern in cls.SENSITIVE_KEY_PATTERNS)
                    if is_sensitive:
                        redacted_keys.append(k)
                        query_changed = True
                        for _ in values:
                            sanitized_query_pairs.append((k, "[REDACTED]"))
                    else:
                        for val in values:
                            sanitized_query_pairs.append((k, val))

                if query_changed:
                    new_query = urllib.parse.urlencode(sanitized_query_pairs)

            if not path_changed and not query_changed:
                return raw_url, False, []

            sanitized_url = urllib.parse.urlunsplit((
                parsed.scheme,
                parsed.netloc,
                new_path,
                new_query,
                parsed.fragment
            ))
            return sanitized_url, True, redacted_keys
        except Exception:
            # On parse failure, return raw URL unchanged
            return raw_url, False, []


class ThreatFeedResult:
    """Normalized threat intelligence result representation across all providers."""

    def __init__(
        self,
        provider: str,
        provider_name: str,
        status: str,  # "available", "no_match", "unavailable", "rate_limited", "error"
        matched: bool = False,
        match_type: str = "none",  # "exact_url", "host", "domain", "none"
        threat_type: Optional[str] = None,  # "malware", "social_engineering", "phishing", "unwanted_software", "c2"
        confidence: int = 0,
        details: str = "",
        reference_url: Optional[str] = None,
        attribution: str = "",
        checked_at: Optional[str] = None,
        cached: bool = False,
        rate_limited: bool = False,
        query_sanitized: bool = False,
        redacted_params: Optional[List[str]] = None,
        raw_evidence: Optional[Dict[str, Any]] = None,
    ):
        self.provider = provider
        self.provider_name = provider_name
        self.status = status
        self.matched = matched
        self.match_type = match_type
        self.threat_type = threat_type
        self.confidence = confidence
        self.details = details
        self.reference_url = reference_url
        self.attribution = attribution
        self.checked_at = checked_at or datetime.now(timezone.utc).isoformat()
        self.cached = cached
        self.rate_limited = rate_limited
        self.query_sanitized = query_sanitized
        self.redacted_params = redacted_params or []
        self.raw_evidence = raw_evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "provider_name": self.provider_name,
            "status": self.status,
            "matched": self.matched,
            "match_type": self.match_type,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "details": self.details,
            "reference_url": self.reference_url,
            "attribution": self.attribution,
            "checked_at": self.checked_at,
            "cached": self.cached,
            "rate_limited": self.rate_limited,
            "query_sanitized": self.query_sanitized,
            "redacted_params": self.redacted_params,
            "raw_evidence": self.raw_evidence,
        }


class CircuitBreaker:
    """
    Prevents repeated cascading failures to external threat feed APIs.
    Trips to OPEN state after consecutive failures; resets after recovery timeout.
    """

    STATE_CLOSED = "CLOSED"
    STATE_OPEN = "OPEN"
    STATE_HALF_OPEN = "HALF_OPEN"

    def __init__(self, failure_threshold: int = 3, recovery_timeout_seconds: float = 45.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout_seconds
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = self.STATE_CLOSED

    def can_execute(self) -> bool:
        now = time.time()
        if self.state == self.STATE_OPEN:
            if now - self.last_failure_time > self.recovery_timeout:
                self.state = self.STATE_HALF_OPEN
                return True
            return False
        return True

    def record_success(self):
        self.failure_count = 0
        self.state = self.STATE_CLOSED

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = self.STATE_OPEN


class MemoryCache:
    """In-memory TTL cache for threat feed lookups."""

    def __init__(self):
        self._store: Dict[str, Tuple[ThreatFeedResult, float]] = {}

    def get(self, key: str) -> Optional[ThreatFeedResult]:
        item = self._store.get(key)
        if not item:
            return None
        res, expire_time = item
        if time.time() > expire_time:
            self._store.pop(key, None)
            return None
        # Return a copy marked as cached
        return ThreatFeedResult(
            provider=res.provider,
            provider_name=res.provider_name,
            status=res.status,
            matched=res.matched,
            match_type=res.match_type,
            threat_type=res.threat_type,
            confidence=res.confidence,
            details=res.details,
            reference_url=res.reference_url,
            attribution=res.attribution,
            checked_at=res.checked_at,
            cached=True,
            rate_limited=res.rate_limited,
            query_sanitized=res.query_sanitized,
            redacted_params=res.redacted_params,
            raw_evidence=res.raw_evidence,
        )

    def set(self, key: str, result: ThreatFeedResult, ttl_seconds: int = 300):
        self._store[key] = (result, time.time() + ttl_seconds)

    def clear(self):
        self._store.clear()


class BaseThreatIntelAdapter:
    """Abstract base class for all threat intelligence providers."""

    def __init__(
        self,
        provider_id: str,
        provider_name: str,
        attribution: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 45.0,
    ):
        self.provider_id = provider_id
        self.provider_name = provider_name
        self.attribution = attribution
        self.circuit_breaker = CircuitBreaker(failure_threshold, recovery_timeout)
        self.cache = MemoryCache()

    def is_configured(self) -> bool:
        """Returns True if required credentials or network access are enabled."""
        raise NotImplementedError

    def lookup(self, raw_url: str, domain: str) -> ThreatFeedResult:
        """Public lookup entrypoint handling sanitization, caching, circuit breaker, and dispatch."""
        # 1. Sanitize sensitive query parameters
        sanitized_url, was_sanitized, redacted_keys = URLQuerySanitizer.sanitize(raw_url)

        # 2. Check configuration
        if not self.is_configured():
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="unavailable",
                matched=False,
                match_type="none",
                details=f"{self.provider_name} API credentials not configured in environment.",
                attribution=self.attribution,
                query_sanitized=was_sanitized,
                redacted_params=redacted_keys,
            )

        # 3. Check Cache
        cache_key = f"{self.provider_id}:{sanitized_url}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        # 4. Check Circuit Breaker
        if not self.circuit_breaker.can_execute():
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="unavailable",
                matched=False,
                match_type="none",
                details=f"Circuit breaker OPEN for {self.provider_name} due to repeated upstream failures. Cooldown active.",
                attribution=self.attribution,
                query_sanitized=was_sanitized,
                redacted_params=redacted_keys,
            )

        # 5. Execute Provider Adapter
        try:
            result = self._execute_lookup(sanitized_url, domain)
            result.query_sanitized = was_sanitized
            result.redacted_params = redacted_keys

            if result.status == "rate_limited":
                # Rate limited is not a hard crash, but don't cache for too long
                self.circuit_breaker.record_failure()
                self.cache.set(cache_key, result, ttl_seconds=60)
            elif result.status == "error":
                self.circuit_breaker.record_failure()
            else:
                self.circuit_breaker.record_success()
                ttl = 1800 if result.matched else 300
                self.cache.set(cache_key, result, ttl_seconds=ttl)

            return result
        except Exception as e:
            self.circuit_breaker.record_failure()
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                details=f"{self.provider_name} lookup fault: {str(e)}",
                attribution=self.attribution,
                query_sanitized=was_sanitized,
                redacted_params=redacted_keys,
            )

    def _execute_lookup(self, sanitized_url: str, domain: str) -> ThreatFeedResult:
        """Must be implemented by concrete adapters."""
        raise NotImplementedError
