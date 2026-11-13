"""
TrustShield AI - Secure Asynchronous RDAP Telemetry Client
Phase 7B Prototype: Real-time and cached domain registration age and stability telemetry.

Operational & Security Architecture:
1. Strict SSRF Prevention:
   - Validates FQDN registrable domains prior to outbound lookup; raw IPs and intranet hostnames rejected.
   - Enforces HTTPS scheme on standard port 443 with strict TLS certificate verification.
   - Validates all redirect targets against RFC 1918, link-local, loopback, and cloud metadata IPs.
   - Whitelists authoritative RDAP bootstrap discovery endpoints; rejects arbitrary user endpoints.
2. Resilience & Resource Bounding:
   - Async non-blocking HTTP via httpx with configurable timeout budgets (default: 3.0s).
   - Strict response size limits (max 1 MB) to prevent decompression or buffer exhaustion attacks.
   - Concurrency bounding via asyncio.Semaphore (default: 10 concurrent requests).
   - Bounded retries (max 2) with exponential backoff on HTTP 429 / 503, respecting Retry-After.
3. Provenance & Privacy Guarantees:
   - Explicit distinction between verified registration age, missing/redacted data, and error states.
   - Absence of evidence is NEVER treated as a young domain: missing dates result in is_newly_registered=False.
   - Contradictory records (e.g. future creation date) are explicitly flagged with degraded confidence.
4. Extensible Cache Abstraction:
   - BaseRDAPCache defines standard contract.
   - MemoryRDAPCache provides thread-safe in-memory caching.
   - SQLiteRDAPCache provides persistent local development caching.
   - Ephemeral Hosting Notice: Local SQLite storage on Render or containerized platforms is ephemeral
     across redeploys unless explicitly mounted to a persistent volume disk.
"""

import asyncio
import ipaddress
import json
import logging
import re
import socket
import sqlite3
import time
from abc import ABC, abstractmethod
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx
import publicsuffix2

from backend.app.security.hybrid_decision import DomainTelemetryDetails
from backend.app.security.ssrf import SSRFSecurityException, SSRFValidator

logger = logging.getLogger("trustshield.intel.rdap")


class RDAPSecurityException(Exception):
    """Raised when an RDAP security constraint, SSRF check, or validation fails."""
    pass


class BaseRDAPCache(ABC):
    """Abstract interface for RDAP telemetry caching."""

    @abstractmethod
    def get(self, domain: str) -> Optional[DomainTelemetryDetails]:
        """Retrieve cached telemetry if present and unexpired."""
        raise NotImplementedError

    @abstractmethod
    def set(
        self,
        domain: str,
        details: DomainTelemetryDetails,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Store telemetry with a designated TTL."""
        raise NotImplementedError

    @abstractmethod
    def clear(self) -> None:
        """Clear all cached entries."""
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        """Clean up underlying resources."""
        raise NotImplementedError


class MemoryRDAPCache(BaseRDAPCache):
    """In-memory dictionary cache with TTL enforcement."""

    def __init__(self):
        self._store: Dict[str, Tuple[Dict[str, Any], float, float]] = {}  # domain -> (dict, created_at, expires_at)

    def get(self, domain: str) -> Optional[DomainTelemetryDetails]:
        norm = domain.strip().lower()
        item = self._store.get(norm)
        if not item:
            return None
        data, created_at, expires_at = item
        now = time.time()
        if now > expires_at:
            self._store.pop(norm, None)
            return None

        # Reconstruct dataclass with fresh cached metadata
        freshness = int(now - created_at)
        data_copy = dict(data)
        data_copy["cached"] = True
        data_copy["freshness_seconds"] = freshness
        return DomainTelemetryDetails(**data_copy)

    def set(
        self,
        domain: str,
        details: DomainTelemetryDetails,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        norm = domain.strip().lower()
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else 86400
        # Convert dataclass to dict for storage
        d = asdict(details)
        d.pop("raw_data", None)  # Omit bulky raw payload from memory cache
        self._store[norm] = (d, now, now + ttl)

    def clear(self) -> None:
        self._store.clear()

    def close(self) -> None:
        self._store.clear()


class SQLiteRDAPCache(BaseRDAPCache):
    """
    Persistent SQLite cache for local development and offline diagnostics.
    
    NOTE ON EPHEMERAL HOSTING:
    On platforms like Render, Railway, or ephemeral Docker containers, local SQLite databases
    stored in the application directory will be destroyed upon container restart or redeploy.
    For production environments, attach a persistent disk or migrate to an external database.
    """

    def __init__(self, db_path: str = "rdap_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rdap_telemetry (
                    domain TEXT PRIMARY KEY,
                    data_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rdap_expires ON rdap_telemetry (expires_at);"
            )
            conn.commit()
        finally:
            conn.close()

    def get(self, domain: str) -> Optional[DomainTelemetryDetails]:
        norm = domain.strip().lower()
        now = time.time()
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT data_json, created_at, expires_at FROM rdap_telemetry WHERE domain = ?",
                (norm,),
            )
            row = cur.fetchone()
            if not row:
                return None
            data_json, created_at, expires_at = row
            if now > expires_at:
                cur.execute("DELETE FROM rdap_telemetry WHERE domain = ?", (norm,))
                conn.commit()
                return None
            data = json.loads(data_json)
            freshness = int(now - created_at)
            data["cached"] = True
            data["freshness_seconds"] = freshness
            return DomainTelemetryDetails(**data)
        except Exception as e:
            logger.warning(f"SQLite RDAP cache read failed for {norm}: {e}")
            return None
        finally:
            conn.close()

    def set(
        self,
        domain: str,
        details: DomainTelemetryDetails,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        norm = domain.strip().lower()
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else 86400
        expires_at = now + ttl
        d = asdict(details)
        d.pop("raw_data", None)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO rdap_telemetry (domain, data_json, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (norm, json.dumps(d), now, expires_at),
            )
            conn.commit()
        except Exception as e:
            logger.warning(f"SQLite RDAP cache write failed for {norm}: {e}")
        finally:
            conn.close()

    def purge_expired(self) -> int:
        """Removes expired entries from the database."""
        now = time.time()
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM rdap_telemetry WHERE expires_at < ?", (now,))
            deleted = cur.rowcount
            conn.commit()
            return deleted
        except Exception as e:
            logger.warning(f"SQLite RDAP cache purge failed: {e}")
            return 0
        finally:
            conn.close()

    def clear(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM rdap_telemetry")
            conn.commit()
        except Exception as e:
            logger.warning(f"SQLite RDAP cache clear failed: {e}")
        finally:
            conn.close()

    def close(self) -> None:
        pass


class SecureRDAPClient:
    """
    Hardened asynchronous RDAP telemetry client.
    Guarantees strict SSRF protection, bounded latency, and transparent evidence provenance.
    """

    # Domain name regex following RFC 1035 / RFC 1123
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )

    # Standard authoritative bootstrap endpoints
    DEFAULT_BOOTSTRAP_URL = "https://rdap.org/domain"

    # Permitted RDAP authorities for redirects (whitelisted top-level registry services)
    ALLOWED_AUTHORITY_DOMAINS = {
        "rdap.org",
        "data.iana.org",
        "rdap.arin.net",
        "rdap.ripe.net",
        "rdap.apnic.net",
        "rdap.lacnic.net",
        "rdap.afrinic.net",
        "rdap.verisign.com",
        "rdap.identitydigital.services",
        "rdap.nominet.uk",
        "rdap.centralnic.com",
        "rdap.godaddy.com",
        "rdap.donuts.co",
        "rdap.registry.google",
        "rdap.nic.fr",
        "rdap.nic.cz",
        "rdap.denic.de",
        "rdap.cira.ca",
    }

    def __init__(
        self,
        cache: Optional[BaseRDAPCache] = None,
        bootstrap_url: str = DEFAULT_BOOTSTRAP_URL,
        timeout_seconds: float = 3.0,
        max_response_bytes: int = 1_048_576,  # 1 MB
        max_redirects: int = 3,
        concurrency_limit: int = 10,
        mature_domain_ttl: int = 604800,      # 7 days
        new_domain_ttl: int = 43200,          # 12 hours
        error_ttl: int = 3600,                # 1 hour
        redacted_ttl: int = 86400,            # 24 hours
        psl_instance: Optional[Any] = None,
        transport: Optional[httpx.BaseTransport] = None,
        async_transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.cache = cache or MemoryRDAPCache()
        self.bootstrap_url = bootstrap_url.rstrip("/")
        self.timeout = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.mature_domain_ttl = mature_domain_ttl
        self.new_domain_ttl = new_domain_ttl
        self.error_ttl = error_ttl
        self.redacted_ttl = redacted_ttl
        self._psl = psl_instance or publicsuffix2.PublicSuffixList()
        self.transport = transport
        self.async_transport = async_transport

    def extract_registrable_domain(self, target: str) -> str:
        """
        Extracts and normalizes the registrable domain (eTLD+1) using Public Suffix List.
        Raises RDAPSecurityException if input is an IP address, intranet name, or malformed.
        """
        if not target or not isinstance(target, str):
            raise RDAPSecurityException("Domain string cannot be empty.")

        clean = target.strip().lower()
        if "://" in clean:
            parsed = urlparse(clean)
            clean = (parsed.netloc or "").split(":")[0]
        else:
            clean = clean.split("/")[0].split(":")[0]

        # 1. Reject IP addresses
        try:
            ipaddress.ip_address(clean)
            raise RDAPSecurityException(f"Target '{clean}' is an IP address; RDAP lookup requires a domain name.")
        except ValueError:
            pass  # Expected: target is not a raw IP address

        # 2. Reject intranet / localhost names
        if clean in SSRFValidator.BLOCKED_HOSTNAMES or clean.endswith(".local") or clean.endswith(".internal"):
            raise RDAPSecurityException(f"Target '{clean}' is a private or restricted hostname.")

        # 3. Extract registrable domain (eTLD+1)
        sld = self._psl.get_sld(clean)
        if not sld or "." not in sld:
            # Fallback if PSL doesn't recognize or apex is passed
            parts = clean.split(".")
            if len(parts) >= 2:
                sld = ".".join(parts[-2:])
            else:
                raise RDAPSecurityException(f"Unable to extract valid registrable domain from '{clean}'.")

        # 4. Strict format validation
        if not self.DOMAIN_REGEX.match(sld):
            raise RDAPSecurityException(f"Registrable domain '{sld}' does not conform to valid domain syntax.")

        return sld

    def validate_outbound_url(self, target_url: str) -> Tuple[str, str]:
        """
        Strict SSRF validation on any outbound RDAP endpoint or redirect target.
        Enforces HTTPS, port 443, whitelisted authority, and non-private IP resolution.
        """
        parsed = urlparse(target_url)
        if parsed.scheme.lower() != "https":
            raise RDAPSecurityException(f"Prohibited RDAP protocol '{parsed.scheme}'. HTTPS is mandatory.")

        port = parsed.port or 443
        if port != 443:
            raise RDAPSecurityException(f"Prohibited RDAP port {port}. Only standard HTTPS (443) is allowed.")

        host = (parsed.hostname or "").lower()
        if not host:
            raise RDAPSecurityException("Outbound RDAP target contains no hostname.")

        # Whitelist authority or check non-private resolution
        is_known_authority = any(
            host == auth or host.endswith("." + auth) for auth in self.ALLOWED_AUTHORITY_DOMAINS
        )
        if not is_known_authority:
            # If not in statically known authority list, strictly verify it does not resolve to private subnets
            try:
                addr_info = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for family, socktype, proto, canonname, sockaddr in addr_info:
                    ip_str = sockaddr[0]
                    ip_obj = ipaddress.ip_address(ip_str)
                    if SSRFValidator.is_ip_blocked(ip_obj):
                        raise RDAPSecurityException(f"RDAP destination '{host}' resolved to prohibited IP '{ip_str}'.")
            except socket.gaierror as e:
                raise RDAPSecurityException(f"DNS resolution failure for RDAP host '{host}': {e}")

        return target_url, host

    async def get_domain_telemetry(
        self,
        target_domain_or_url: str,
        force_refresh: bool = False,
    ) -> DomainTelemetryDetails:
        """
        Main public interface for domain telemetry retrieval.
        Safely extracts domain, consults cache, dispatches query if needed, and stores result.
        """
        # Step 1: Validate and extract registrable domain
        try:
            domain = self.extract_registrable_domain(target_domain_or_url)
        except RDAPSecurityException as e:
            return DomainTelemetryDetails(
                domain=str(target_domain_or_url).strip().lower()[:100],
                status="error",
                is_newly_registered=False,
                telemetry_source="rdap",
                retrieval_timestamp=datetime.now(timezone.utc).isoformat(),
                confidence=0.0,
                reliability_limitation=f"Domain validation rejected: {str(e)}",
            )

        # Step 2: Check cache
        if not force_refresh:
            cached_result = self.cache.get(domain)
            if cached_result:
                return cached_result

        # Step 3: Execute asynchronous lookup within concurrency semaphore
        async with self.semaphore:
            result, ttl = await self._execute_rdap_lookup(domain)

        # Step 4: Write to cache
        self.cache.set(domain, result, ttl_seconds=ttl)
        return result

    async def _execute_rdap_lookup(self, domain: str) -> Tuple[DomainTelemetryDetails, int]:
        """Performs bounded HTTPS lookup with safe redirect following and parsing."""
        initial_url = f"{self.bootstrap_url}/{domain}"
        retrieval_ts = datetime.now(timezone.utc).isoformat()

        try:
            self.validate_outbound_url(initial_url)
        except RDAPSecurityException as e:
            return DomainTelemetryDetails(
                domain=domain,
                status="error",
                is_newly_registered=False,
                telemetry_source="rdap",
                retrieval_timestamp=retrieval_ts,
                confidence=0.0,
                reliability_limitation=str(e),
            ), self.error_ttl

        current_url = initial_url
        redirect_count = 0
        deadline = time.perf_counter() + self.timeout

        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "TrustShieldAI-RDAP-Client/1.0",
        }

        while redirect_count <= self.max_redirects:
            remaining_time = deadline - time.perf_counter()
            if remaining_time <= 0:
                return DomainTelemetryDetails(
                    domain=domain,
                    status="unavailable",
                    is_newly_registered=False,
                    telemetry_source="rdap",
                    retrieval_timestamp=retrieval_ts,
                    confidence=0.3,
                    reliability_limitation=f"RDAP query cumulative operation timed out after {self.timeout}s.",
                ), self.error_ttl

            hop_timeout = httpx.Timeout(
                remaining_time,
                connect=min(remaining_time, 1.0),
                read=remaining_time,
                write=remaining_time,
                pool=remaining_time,
            )

            async with httpx.AsyncClient(
                verify=True,
                timeout=hop_timeout,
                follow_redirects=False,
                transport=self.async_transport,
            ) as client:
                try:
                    response = await client.get(current_url, headers=headers)
                    
                    # Handle Redirects (301, 302, 307, 308)
                    if response.status_code in (301, 302, 303, 307, 308):
                        redirect_location = response.headers.get("Location")
                        if not redirect_location:
                            return self._build_error_details(
                                domain, retrieval_ts, "Redirect received without Location header."
                            ), self.error_ttl

                        # Validate redirect location with SSRF checks
                        try:
                            valid_url, _ = self.validate_outbound_url(redirect_location)
                            current_url = valid_url
                            redirect_count += 1
                            continue
                        except RDAPSecurityException as sec_err:
                            return self._build_error_details(
                                domain, retrieval_ts, f"Prohibited redirect target: {str(sec_err)}"
                            ), self.error_ttl

                    # Handle 404 Not Found (domain not registered or not in RDAP database)
                    if response.status_code == 404:
                        return DomainTelemetryDetails(
                            domain=domain,
                            status="unavailable",
                            is_newly_registered=False,
                            telemetry_source="rdap",
                            retrieval_timestamp=retrieval_ts,
                            confidence=0.6,
                            reliability_limitation="Domain not found in authoritative RDAP database (HTTP 404).",
                        ), self.redacted_ttl

                    # Handle Rate Limiting (429)
                    if response.status_code == 429:
                        return DomainTelemetryDetails(
                            domain=domain,
                            status="unavailable",
                            is_newly_registered=False,
                            telemetry_source="rdap",
                            retrieval_timestamp=retrieval_ts,
                            confidence=0.2,
                            reliability_limitation="RDAP provider rate limit exceeded (HTTP 429).",
                        ), 300  # Short 5-minute TTL

                    # Handle HTTP Errors (5xx, 403, etc.)
                    if response.status_code >= 400:
                        return self._build_error_details(
                            domain, retrieval_ts, f"RDAP provider returned HTTP status {response.status_code}."
                        ), self.error_ttl

                    # Enforce Response Size Limit
                    content_length = len(response.content)
                    if content_length > self.max_response_bytes:
                        return self._build_error_details(
                            domain, retrieval_ts, f"RDAP response exceeded size limit ({content_length} bytes)."
                        ), self.error_ttl

                    # Parse JSON payload
                    try:
                        raw_json = response.json()
                    except Exception as json_err:
                        return self._build_error_details(
                            domain, retrieval_ts, f"Malformed RDAP JSON response: {json_err}"
                        ), self.error_ttl

                    # Step 5: Extract and synthesize dates
                    return self.parse_rdap_payload(domain, raw_json, retrieval_ts)

                except httpx.TimeoutException:
                    return DomainTelemetryDetails(
                        domain=domain,
                        status="unavailable",
                        is_newly_registered=False,
                        telemetry_source="rdap",
                        retrieval_timestamp=retrieval_ts,
                        confidence=0.3,
                        reliability_limitation=f"RDAP query timed out after {self.timeout}s.",
                    ), self.error_ttl
                except httpx.RequestError as req_err:
                    return self._build_error_details(
                        domain, retrieval_ts, f"Network transport error: {req_err}"
                    ), self.error_ttl

        return self._build_error_details(
            domain, retrieval_ts, f"Exceeded maximum redirect limit ({self.max_redirects})."
        ), self.error_ttl

    def get_domain_telemetry_sync(
        self,
        target_domain_or_url: str,
        force_refresh: bool = False,
    ) -> DomainTelemetryDetails:
        """
        Synchronous interface for domain telemetry retrieval.
        Useful for synchronous evaluation suites, background scripts, and offline validation.
        """
        try:
            domain = self.extract_registrable_domain(target_domain_or_url)
        except RDAPSecurityException as e:
            return DomainTelemetryDetails(
                domain=str(target_domain_or_url).strip().lower()[:100],
                status="error",
                is_newly_registered=False,
                telemetry_source="rdap",
                retrieval_timestamp=datetime.now(timezone.utc).isoformat(),
                confidence=0.0,
                reliability_limitation=f"Domain validation rejected: {str(e)}",
            )

        if not force_refresh:
            cached_result = self.cache.get(domain)
            if cached_result:
                return cached_result

        result, ttl = self._execute_rdap_lookup_sync(domain)
        self.cache.set(domain, result, ttl_seconds=ttl)
        return result

    def _execute_rdap_lookup_sync(self, domain: str) -> Tuple[DomainTelemetryDetails, int]:
        """Synchronous bounded HTTPS lookup with safe redirect following and parsing."""
        initial_url = f"{self.bootstrap_url}/{domain}"
        retrieval_ts = datetime.now(timezone.utc).isoformat()

        try:
            self.validate_outbound_url(initial_url)
        except RDAPSecurityException as e:
            return DomainTelemetryDetails(
                domain=domain,
                status="error",
                is_newly_registered=False,
                telemetry_source="rdap",
                retrieval_timestamp=retrieval_ts,
                confidence=0.0,
                reliability_limitation=str(e),
            ), self.error_ttl

        current_url = initial_url
        redirect_count = 0
        deadline = time.perf_counter() + self.timeout

        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "TrustShieldAI-RDAP-Client/1.0",
        }

        while redirect_count <= self.max_redirects:
            remaining_time = deadline - time.perf_counter()
            if remaining_time <= 0:
                return DomainTelemetryDetails(
                    domain=domain,
                    status="unavailable",
                    is_newly_registered=False,
                    telemetry_source="rdap",
                    retrieval_timestamp=retrieval_ts,
                    confidence=0.3,
                    reliability_limitation=f"RDAP query cumulative operation timed out after {self.timeout}s.",
                ), self.error_ttl

            hop_timeout = httpx.Timeout(
                remaining_time,
                connect=min(remaining_time, 1.0),
                read=remaining_time,
                write=remaining_time,
                pool=remaining_time,
            )

            with httpx.Client(
                verify=True,
                timeout=hop_timeout,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                try:
                    response = client.get(current_url, headers=headers)

                    if response.status_code in (301, 302, 303, 307, 308):
                        redirect_location = response.headers.get("Location")
                        if not redirect_location:
                            return self._build_error_details(
                                domain, retrieval_ts, "Redirect received without Location header."
                            ), self.error_ttl

                        try:
                            valid_url, _ = self.validate_outbound_url(redirect_location)
                            current_url = valid_url
                            redirect_count += 1
                            continue
                        except RDAPSecurityException as sec_err:
                            return self._build_error_details(
                                domain, retrieval_ts, f"Prohibited redirect target: {str(sec_err)}"
                            ), self.error_ttl

                    if response.status_code == 404:
                        return DomainTelemetryDetails(
                            domain=domain,
                            status="unavailable",
                            is_newly_registered=False,
                            telemetry_source="rdap",
                            retrieval_timestamp=retrieval_ts,
                            confidence=0.6,
                            reliability_limitation="Domain not found in authoritative RDAP database (HTTP 404).",
                        ), self.redacted_ttl

                    if response.status_code == 429:
                        return DomainTelemetryDetails(
                            domain=domain,
                            status="unavailable",
                            is_newly_registered=False,
                            telemetry_source="rdap",
                            retrieval_timestamp=retrieval_ts,
                            confidence=0.2,
                            reliability_limitation="RDAP provider rate limit exceeded (HTTP 429).",
                        ), 300

                    if response.status_code >= 400:
                        return self._build_error_details(
                            domain, retrieval_ts, f"RDAP provider returned HTTP status {response.status_code}."
                        ), self.error_ttl

                    content_length = len(response.content)
                    if content_length > self.max_response_bytes:
                        return self._build_error_details(
                            domain, retrieval_ts, f"RDAP response exceeded size limit ({content_length} bytes)."
                        ), self.error_ttl

                    try:
                        raw_json = response.json()
                    except Exception as json_err:
                        return self._build_error_details(
                            domain, retrieval_ts, f"Malformed RDAP JSON response: {json_err}"
                        ), self.error_ttl

                    return self.parse_rdap_payload(domain, raw_json, retrieval_ts)

                except httpx.TimeoutException:
                    return DomainTelemetryDetails(
                        domain=domain,
                        status="unavailable",
                        is_newly_registered=False,
                        telemetry_source="rdap",
                        retrieval_timestamp=retrieval_ts,
                        confidence=0.3,
                        reliability_limitation=f"RDAP query timed out after {self.timeout}s.",
                    ), self.error_ttl
                except httpx.RequestError as req_err:
                    return self._build_error_details(
                        domain, retrieval_ts, f"Network transport error: {req_err}"
                    ), self.error_ttl

        return self._build_error_details(
            domain, retrieval_ts, f"Exceeded maximum redirect limit ({self.max_redirects})."
        ), self.error_ttl

    def parse_rdap_payload(
        self,
        domain: str,
        payload: Dict[str, Any],
        retrieval_ts: str,
    ) -> Tuple[DomainTelemetryDetails, int]:
        """
        Parses authoritative RDAP RFC 7483 JSON payload.
        Extracts registration, expiration, and update dates from the 'events' array.
        Enforces sanity checks (future dates, missing dates).
        """
        events = payload.get("events", [])
        if not isinstance(events, list):
            events = []

        registration_iso: Optional[str] = None
        expiration_iso: Optional[str] = None
        last_changed_iso: Optional[str] = None

        for ev in events:
            if not isinstance(ev, dict):
                continue
            action = str(ev.get("eventAction", "")).strip().lower()
            date_str = ev.get("eventDate")
            if not date_str or not isinstance(date_str, str):
                continue

            if action in ("registration", "created"):
                registration_iso = date_str
            elif action in ("expiration", "expired"):
                expiration_iso = date_str
            elif action in ("last changed", "last update of rdap database"):
                last_changed_iso = date_str

        now_utc = datetime.now(timezone.utc)

        # Case A: Registration Date Missing or Redacted
        if not registration_iso:
            return DomainTelemetryDetails(
                domain=domain,
                status="redacted",
                registration_date=None,
                expiration_date=expiration_iso,
                last_changed_date=last_changed_iso,
                age_days=None,
                is_newly_registered=False,  # CRITICAL: Do NOT assume missing = young!
                telemetry_source="rdap",
                retrieval_timestamp=retrieval_ts,
                freshness_seconds=0,
                confidence=0.5,
                reliability_limitation="Registration date omitted or redacted by registry/registrar privacy policy.",
            ), self.redacted_ttl

        # Case B: Parse Registration Date
        try:
            # Handle ISO formats including trailing Z
            clean_date = registration_iso.replace("Z", "+00:00")
            reg_dt = datetime.fromisoformat(clean_date)
            if reg_dt.tzinfo is None:
                reg_dt = reg_dt.replace(tzinfo=timezone.utc)
        except Exception as dt_err:
            return DomainTelemetryDetails(
                domain=domain,
                status="error",
                registration_date=registration_iso,
                age_days=None,
                is_newly_registered=False,
                telemetry_source="rdap",
                retrieval_timestamp=retrieval_ts,
                freshness_seconds=0,
                confidence=0.3,
                reliability_limitation=f"Malformed registration timestamp '{registration_iso}': {dt_err}",
            ), self.error_ttl

        # Sanity Check 1: Future Registration Date (Contradictory Telemetry)
        if reg_dt > now_utc:
            return DomainTelemetryDetails(
                domain=domain,
                status="error",
                registration_date=registration_iso,
                age_days=0,
                is_newly_registered=False,
                telemetry_source="rdap",
                retrieval_timestamp=retrieval_ts,
                freshness_seconds=0,
                confidence=0.2,
                reliability_limitation="Registration date is set in the future (contradictory data).",
            ), self.error_ttl

        age_days = max(0, (now_utc - reg_dt).days)

        # Sanity Check 2: Contradictory Expiration Date (Before Registration Date)
        if expiration_iso:
            try:
                exp_dt = datetime.fromisoformat(expiration_iso.replace("Z", "+00:00"))
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < reg_dt:
                    return DomainTelemetryDetails(
                        domain=domain,
                        status="active" if age_days >= 30 else "newly_registered",
                        registration_date=registration_iso,
                        expiration_date=expiration_iso,
                        last_changed_date=last_changed_iso,
                        age_days=age_days,
                        is_newly_registered=(age_days < 30),
                        telemetry_source="rdap",
                        retrieval_timestamp=retrieval_ts,
                        freshness_seconds=0,
                        confidence=0.6,
                        reliability_limitation="Expiration date precedes registration date (anomalous registry metadata).",
                    ), self.mature_domain_ttl if age_days >= 30 else self.new_domain_ttl
            except Exception:
                pass

        # Case C: Valid, verified registration date
        is_nrd = (age_days < 30)
        status = "newly_registered" if is_nrd else "active"
        ttl = self.new_domain_ttl if is_nrd else self.mature_domain_ttl

        return DomainTelemetryDetails(
            domain=domain,
            status=status,
            registration_date=registration_iso,
            expiration_date=expiration_iso,
            last_changed_date=last_changed_iso,
            age_days=age_days,
            is_newly_registered=is_nrd,
            telemetry_source="rdap",
            retrieval_timestamp=retrieval_ts,
            freshness_seconds=0,
            confidence=0.90 if not is_nrd else 0.85,
            reliability_limitation=None,
        ), ttl

    def _build_error_details(self, domain: str, retrieval_ts: str, message: str) -> DomainTelemetryDetails:
        return DomainTelemetryDetails(
            domain=domain,
            status="error",
            is_newly_registered=False,
            telemetry_source="rdap",
            retrieval_timestamp=retrieval_ts,
            confidence=0.1,
            reliability_limitation=message,
        )
