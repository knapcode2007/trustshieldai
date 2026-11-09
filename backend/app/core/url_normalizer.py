import hashlib
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from typing import Dict, Any, Tuple

class URLNormalizer:
    """Enterprise URL canonicalizer and domain extractor for deduplication and consistent telemetry."""

    @classmethod
    def canonicalize(cls, raw_url: str) -> Tuple[str, str, Dict[str, Any]]:
        """
        Normalizes and canonicalizes a URL into standard RFC 3986 form.
        Returns (canonical_url, sha256_hash, metadata_dict).
        """
        if not raw_url or not isinstance(raw_url, str):
            raise ValueError("URL must be a non-empty string")

        url_str = raw_url.strip()
        if "://" not in url_str:
            url_str = f"https://{url_str}"

        parsed = urlparse(url_str)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme: {scheme}")

        hostname = (parsed.hostname or "").lower().strip()
        # Handle Punycode/IDNA
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except Exception:
            pass

        # Strip standard port redundancy
        port = parsed.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

        netloc = f"{hostname}:{port}" if port else hostname

        # Normalize path: empty path becomes "/"
        path = parsed.path or "/"
        if "//" in path:
            import re
            path = re.sub(r"/+", "/", path)

        # Sort query parameters for consistent hash deduplication
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_params))

        # Omit fragment (#...) from canonical representation
        canonical = urlunparse((scheme, netloc, path, "", sorted_query, ""))
        canonical_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        # Domain extraction
        domain_parts = hostname.split(".")
        if len(domain_parts) >= 2:
            root_domain = f"{domain_parts[-2]}.{domain_parts[-1]}"
            subdomains = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""
        else:
            root_domain = hostname
            subdomains = ""

        metadata = {
            "canonical_url": canonical,
            "canonical_hash": canonical_hash,
            "domain": hostname,
            "root_domain": root_domain,
            "subdomains": subdomains,
            "subdomain_count": len(domain_parts) - 2 if len(domain_parts) > 2 else 0,
            "scheme": scheme,
            "port": port or (443 if scheme == "https" else 80),
            "path": path,
            "query_param_count": len(query_params)
        }

        return canonical, canonical_hash, metadata
