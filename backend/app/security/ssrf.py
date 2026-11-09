import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, List, Optional

class SSRFSecurityException(Exception):
    """Raised when an SSRF violation or prohibited network destination is detected."""
    def __init__(self, message: str, code: str = "SSRF_BLOCKED"):
        self.message = message
        self.code = code
        super().__init__(self.message)

class SSRFValidator:
    """Enterprise-grade SSRF and outbound network restriction engine."""

    ALLOWED_SCHEMES = {"http", "https"}
    ALLOWED_PORTS = {80, 443}

    # Prohibited IPv4 networks
    BLOCKED_IPV4_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),          # Current network
        ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private
        ipaddress.ip_network("100.64.0.0/10"),       # Carrier Grade NAT
        ipaddress.ip_network("127.0.0.0/8"),        # Loopback
        ipaddress.ip_network("169.254.0.0/16"),      # Link-Local / Cloud Metadata
        ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private
        ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
        ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
        ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private
        ipaddress.ip_network("198.18.0.0/15"),       # Network Interconnect Device Benchmark
        ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
        ipaddress.ip_network("224.0.0.0/4"),         # Multicast
        ipaddress.ip_network("240.0.0.0/4"),         # Reserved for future use
        ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    ]

    # Prohibited IPv6 networks
    BLOCKED_IPV6_NETWORKS = [
        ipaddress.ip_network("::1/128"),             # Loopback
        ipaddress.ip_network("::/128"),              # Unspecified
        ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped IPv6
        ipaddress.ip_network("64:ff9b::/96"),        # IPv4/IPv6 translation
        ipaddress.ip_network("100::/64"),            # Discard prefix
        ipaddress.ip_network("2001:db8::/32"),       # Documentation
        ipaddress.ip_network("2002::/16"),           # 6to4
        ipaddress.ip_network("fc00::/7"),            # Unique Local Address (ULA)
        ipaddress.ip_network("fe80::/10"),           # Link-Local Unicast
        ipaddress.ip_network("ff00::/8"),            # Multicast
    ]

    BLOCKED_HOSTNAMES = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.internal",
        "169.254.169.254",
        "instance-data",
    }

    @classmethod
    def is_ip_blocked(cls, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Determines if an IP address belongs to a prohibited/internal subnet."""
        # Unpack IPv4-mapped IPv6
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True

        if isinstance(ip, ipaddress.IPv4Address):
            for net in cls.BLOCKED_IPV4_NETWORKS:
                if ip in net:
                    return True
        elif isinstance(ip, ipaddress.IPv6Address):
            for net in cls.BLOCKED_IPV6_NETWORKS:
                if ip in net:
                    return True

        return False

    @classmethod
    def validate_url(cls, url: str) -> Tuple[str, str, int, str]:
        """
        Strictly validates target URL against SSRF vulnerabilities.
        Returns tuple of (canonical_url, hostname, port, pinned_ip).
        Raises SSRFSecurityException on any violation.
        """
        if not url or not isinstance(url, str) or not url.strip():
            raise SSRFSecurityException("URL cannot be empty", code="EMPTY_URL")

        clean_url = url.strip()
        parsed = urlparse(clean_url)

        # 1. Scheme check
        if not parsed.scheme or parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise SSRFSecurityException(
                f"Prohibited URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.",
                code="INVALID_SCHEME"
            )

        # 2. Reject embedded user credentials
        if parsed.username or parsed.password:
            raise SSRFSecurityException(
                "URLs containing embedded authentication credentials (user:pass@) are prohibited.",
                code="CREDENTIALS_DISALLOWED"
            )

        # 3. Hostname check
        hostname = parsed.hostname
        if not hostname:
            raise SSRFSecurityException("URL is missing a valid hostname.", code="MISSING_HOSTNAME")

        hostname_lower = hostname.lower().strip()
        if hostname_lower in cls.BLOCKED_HOSTNAMES or hostname_lower.endswith(".localhost"):
            raise SSRFSecurityException(
                f"Access to private/metadata hostname '{hostname}' is prohibited.",
                code="FORBIDDEN_HOST"
            )

        # 4. Port check
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port not in cls.ALLOWED_PORTS:
            raise SSRFSecurityException(
                f"Access to port {port} is prohibited. Only standard web ports (80, 443) are allowed.",
                code="FORBIDDEN_PORT"
            )

        # 5. Direct IP check or DNS resolution
        pinned_ip = cls.resolve_and_verify_host(hostname_lower)

        return clean_url, hostname_lower, port, pinned_ip

    @classmethod
    def resolve_and_verify_host(cls, hostname: str) -> str:
        """Resolves DNS and verifies all returned IPs against blacklist to prevent DNS rebinding."""
        # Check if hostname is already a raw IP literal
        try:
            raw_ip = ipaddress.ip_address(hostname.strip("[]"))
            if cls.is_ip_blocked(raw_ip):
                raise SSRFSecurityException(
                    f"Destination IP '{raw_ip}' is a reserved, private, or loopback address.",
                    code="PRIVATE_IP_BLOCKED"
                )
            return str(raw_ip)
        except ValueError:
            pass  # Not an IP literal, proceed to DNS resolution

        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise SSRFSecurityException(
                f"DNS resolution failed for hostname '{hostname}': {str(e)}",
                code="DNS_RESOLUTION_FAILED"
            )

        if not addr_info:
            raise SSRFSecurityException(f"No IP addresses resolved for hostname '{hostname}'.", code="DNS_NO_RECORDS")

        validated_ips: List[str] = []
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if cls.is_ip_blocked(ip_obj):
                    raise SSRFSecurityException(
                        f"Resolved IP '{ip_str}' for hostname '{hostname}' belongs to a blocked internal or private range.",
                        code="DNS_REBINDING_BLOCKED"
                    )
                validated_ips.append(ip_str)
            except ValueError:
                continue

        if not validated_ips:
            raise SSRFSecurityException(
                f"All resolved IP addresses for '{hostname}' were blocked by security policy.",
                code="ALL_IPS_BLOCKED"
            )

        # Pin the first verified IP
        return validated_ips[0]
