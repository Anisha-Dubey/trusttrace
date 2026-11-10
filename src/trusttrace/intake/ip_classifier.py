"""IP Destination Classification & SSRF Defense.

Implements requirements:
- SSRF-001: Loopback blocking (127.0.0.1, ::1)
- SSRF-002: RFC 1918 IPv4 and IPv6 ULA blocking
- SSRF-003: Link-local and Cloud Metadata range blocking
"""

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Union, Optional, Tuple


class IPStatus(str, Enum):
    PUBLIC_SAFE = "public_safe"
    LOOPBACK = "loopback"
    PRIVATE_RFC1918 = "private_rfc1918"
    IPV6_ULA = "ipv6_ula"
    LINK_LOCAL = "link_local"
    CLOUD_METADATA = "cloud_metadata"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"
    UNSPECIFIED = "unspecified"
    CARRIER_GRADE_NAT = "carrier_grade_nat"
    DOCUMENTATION = "documentation"
    RESERVED = "reserved"
    INVALID = "invalid"


@dataclass(frozen=True)
class IPClassificationResult:
    ip_str: str
    status: IPStatus
    is_safe: bool
    rejection_reason: Optional[str] = None
    ip_obj: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None


# Prohibited Cloud Metadata Specific Addresses / Subnets
CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),          # AWS, GCP, Azure, OpenStack
    ipaddress.ip_address("100.100.100.200"),          # Alibaba Cloud metadata
}

CLOUD_METADATA_IPV6_NETWORKS = [
    ipaddress.ip_network("fd00:ec2::/32"),           # AWS IMDSv2 IPv6
]

# Carrier-Grade NAT (RFC 6598)
CARRIER_NAT_NET = ipaddress.ip_network("100.64.0.0/10")

# Documentation networks
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),             # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),         # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),          # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),           # IPv6 documentation
]


def classify_ip(ip_val: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> IPClassificationResult:
    """Classify an IP address as safe for outbound connection or prohibited under SSRF policy."""
    if isinstance(ip_val, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = ip_val
        ip_str = str(ip)
    else:
        ip_str = str(ip_val).strip()
        ip = None
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            # Check integer or hexadecimal numeric IP representations
            if ip_str.isdigit():
                try:
                    num_val = int(ip_str)
                    if 0 <= num_val <= 0xFFFFFFFF:
                        ip = ipaddress.IPv4Address(num_val)
                except Exception:
                    pass
            elif ip_str.lower().startswith("0x") and len(ip_str) <= 10:
                try:
                    num_val = int(ip_str, 16)
                    if 0 <= num_val <= 0xFFFFFFFF:
                        ip = ipaddress.IPv4Address(num_val)
                except Exception:
                    pass

        if ip is None:
            return IPClassificationResult(
                ip_str=ip_str,
                status=IPStatus.INVALID,
                is_safe=False,
                rejection_reason="invalid_ip_format"
            )

    # Check for IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if ip.version == 6 and ip.ipv4_mapped:
        mapped_ipv4 = ip.ipv4_mapped
        mapped_res = classify_ip(mapped_ipv4)
        if not mapped_res.is_safe:
            return IPClassificationResult(
                ip_str=ip_str,
                status=mapped_res.status,
                is_safe=False,
                rejection_reason=f"ipv4_mapped_{mapped_res.rejection_reason}",
                ip_obj=ip
            )

    # 1. Cloud Metadata checks (SSRF-003)
    if ip in CLOUD_METADATA_IPS:
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.CLOUD_METADATA,
            is_safe=False,
            rejection_reason="cloud_metadata_target",
            ip_obj=ip
        )
    if ip.version == 6:
        for net in CLOUD_METADATA_IPV6_NETWORKS:
            if ip in net:
                return IPClassificationResult(
                    ip_str=ip_str,
                    status=IPStatus.CLOUD_METADATA,
                    is_safe=False,
                    rejection_reason="cloud_metadata_target",
                    ip_obj=ip
                )

    # 2. Loopback checks (SSRF-001)
    if ip.is_loopback:
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.LOOPBACK,
            is_safe=False,
            rejection_reason="loopback_target",
            ip_obj=ip
        )

    # 3. Link-Local checks (SSRF-003)
    if ip.is_link_local:
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.LINK_LOCAL,
            is_safe=False,
            rejection_reason="link_local_target",
            ip_obj=ip
        )

    # 4. Private RFC1918 / IPv6 ULA checks (SSRF-002)
    if ip.version == 4 and ip.is_private:
        # Carrier grade NAT check
        if ip in CARRIER_NAT_NET:
            return IPClassificationResult(
                ip_str=ip_str,
                status=IPStatus.CARRIER_GRADE_NAT,
                is_safe=False,
                rejection_reason="carrier_grade_nat_target",
                ip_obj=ip
            )
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.PRIVATE_RFC1918,
            is_safe=False,
            rejection_reason="private_network_target",
            ip_obj=ip
        )
    elif ip.version == 6:
        # IPv6 Unique Local Address (ULA) fc00::/7
        if ip.is_private:
            return IPClassificationResult(
                ip_str=ip_str,
                status=IPStatus.IPV6_ULA,
                is_safe=False,
                rejection_reason="ipv6_ula_target",
                ip_obj=ip
            )

    # 5. Multicast (RFC 5771 / RFC 4291)
    if ip.is_multicast:
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.MULTICAST,
            is_safe=False,
            rejection_reason="multicast_target",
            ip_obj=ip
        )

    # 6. Unspecified (0.0.0.0 / ::)
    if ip.is_unspecified:
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.UNSPECIFIED,
            is_safe=False,
            rejection_reason="unspecified_target",
            ip_obj=ip
        )

    # 7. Reserved
    if ip.is_reserved:
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.RESERVED,
            is_safe=False,
            rejection_reason="reserved_ip_target",
            ip_obj=ip
        )

    # 8. Documentation networks
    for net in DOCUMENTATION_NETWORKS:
        if ip in net:
            return IPClassificationResult(
                ip_str=ip_str,
                status=IPStatus.DOCUMENTATION,
                is_safe=False,
                rejection_reason="documentation_network_target",
                ip_obj=ip
            )

    # 9. Broadcast
    if ip.version == 4 and ip_str == "255.255.255.255":
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.BROADCAST,
            is_safe=False,
            rejection_reason="broadcast_target",
            ip_obj=ip
        )

    # If it is global public
    if ip.is_global:
        return IPClassificationResult(
            ip_str=ip_str,
            status=IPStatus.PUBLIC_SAFE,
            is_safe=True,
            ip_obj=ip
        )

    # Default conservative denial
    return IPClassificationResult(
        ip_str=ip_str,
        status=IPStatus.RESERVED,
        is_safe=False,
        rejection_reason="non_global_ip_target",
        ip_obj=ip
    )

