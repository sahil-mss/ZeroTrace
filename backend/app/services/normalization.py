"""
Normalization utilities for ZeroTrace / AegisPT.

Provides deterministic, RFC-compliant normalization functions for:
- DNS hostnames (lowercase, IDN/punycode, trailing dot handling).
- IPv4 and IPv6 addresses (brackets, canonical compression).
- HTTP and HTTPS URLs (scheme validation, credential rejection, effective ports, path normalization).
- Structured representations and whitespace trimming.
- Canonical JSON serialization and deterministic content hashing.
"""

import hashlib
import ipaddress
import json
import posixpath
import re
from datetime import date, datetime
from enum import Enum
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from aegis_common.enums import AssetType


def clean_whitespace(text: str) -> str:
    """Strips leading/trailing whitespace and collapses repeated internal spaces."""
    if not isinstance(text, str):
        return str(text)
    # Collapse multiple spaces/tabs into a single space, but preserve newlines if needed
    cleaned = re.sub(r"[ \t]+", " ", text.strip())
    return cleaned


def normalize_hostname(hostname: str) -> str:
    """
    Normalizes a DNS hostname:
    - Strips whitespace
    - Lowercases
    - Strips trailing DNS dot
    - Converts Internationalized Domain Names (IDN) via Punycode
    - Validates character constraints (no spaces, valid labels)
    """
    if not hostname or not isinstance(hostname, str):
        raise ValueError("Hostname must be a non-empty string.")

    cleaned = hostname.strip().lower()
    # Strip single or multiple trailing dots
    cleaned = cleaned.rstrip(".")

    if not cleaned:
        raise ValueError("Hostname cannot be empty after stripping trailing dots.")

    if any(char in cleaned for char in (" ", "\t", "\r", "\n", "/", "\\", "@", ":")):
        raise ValueError(f"Invalid character in hostname: '{hostname}'")

    # Punycode / IDN normalization
    try:
        punycode = cleaned.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Failed to encode internationalized domain '{hostname}': {exc}") from exc

    # Validate label lengths
    labels = punycode.split(".")
    for label in labels:
        if not label:
            raise ValueError(f"Hostname contains empty label: '{hostname}'")
        if len(label) > 63:
            raise ValueError(f"Hostname label exceeds 63 characters: '{label}' in '{hostname}'")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(f"Hostname label cannot start or end with hyphen: '{label}' in '{hostname}'")

    if len(punycode) > 253:
        raise ValueError(f"Hostname total length exceeds 253 characters: '{punycode}'")

    return punycode


def normalize_ip_address(ip_str: str) -> str:
    """
    Safely parses and normalizes IPv4 and IPv6 addresses:
    - Strips whitespace and brackets (e.g. '[::1]' -> '::1')
    - Returns canonical compressed representation (e.g. '2001:db8::1')
    """
    if not ip_str or not isinstance(ip_str, str):
        raise ValueError("IP address must be a non-empty string.")

    cleaned = ip_str.strip()
    # Strip surrounding brackets if IPv6
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]

    try:
        ip_obj = ipaddress.ip_address(cleaned)
        # Returns standard canonical string representation (compressed for IPv6)
        return str(ip_obj)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 or IPv6 address: '{ip_str}'") from exc


def normalize_cidr(cidr_str: str) -> str:
    """
    Safely parses and normalizes IPv4 and IPv6 CIDR notations.
    Returns canonical network string representation (e.g. '192.168.1.0/24').
    """
    if not cidr_str or not isinstance(cidr_str, str):
        raise ValueError("CIDR must be a non-empty string.")

    cleaned = cidr_str.strip()
    try:
        net = ipaddress.ip_network(cleaned, strict=False)
        return str(net)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR network representation: '{cidr_str}'") from exc


def normalize_url(url: str) -> str:
    """
    Normalizes an HTTP or HTTPS URL:
    - Strips whitespace
    - Validates scheme (strictly http or https)
    - Rejects embedded user credentials (user:pass@host)
    - Normalizes hostname (IDN/Punycode, lowercase, trailing dot) or IP
    - Normalizes port: preserves non-default ports; standardizes default ports (80 for http, 443 for https)
    - Normalizes path using posixpath.normpath, preserving trailing slash if present
    - Canonicalizes query parameters in sorted order
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string.")

    cleaned = url.strip()

    # Reject leading or embedded credentials pattern before urlsplit
    if "@" in cleaned.split("?", 1)[0].split("#", 1)[0]:
        raise ValueError(f"URL contains embedded credentials, which are prohibited: '{url}'")

    try:
        parsed = urlsplit(cleaned)
    except Exception as exc:
        raise ValueError(f"Malformed URL structure: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'. Only 'http' and 'https' are permitted.")

    if parsed.username or parsed.password:
        raise ValueError(f"URL contains embedded user credentials, which are prohibited: '{url}'")

    if not parsed.hostname:
        raise ValueError(f"URL missing valid hostname: '{url}'")

    # Hostname / IP normalization
    raw_host = parsed.hostname
    try:
        normalized_host = normalize_ip_address(raw_host)
        # If IPv6, format in brackets for URL netloc
        if ":" in normalized_host:
            host_for_netloc = f"[{normalized_host}]"
        else:
            host_for_netloc = normalized_host
    except ValueError:
        normalized_host = normalize_hostname(raw_host)
        host_for_netloc = normalized_host

    # Port normalization
    port = parsed.port
    if port is not None:
        if not (1 <= port <= 65535):
            raise ValueError(f"Port {port} is out of valid range 1-65535.")

        # Default ports are normalized out to avoid redundant records for the same endpoint
        is_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        if is_default_port:
            netloc = host_for_netloc
        else:
            netloc = f"{host_for_netloc}:{port}"
    else:
        netloc = host_for_netloc

    # Path normalization
    raw_path = parsed.path or "/"
    had_trailing_slash = raw_path.endswith("/") and raw_path != "/"
    norm_path = posixpath.normpath(raw_path)
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path

    if had_trailing_slash and not norm_path.endswith("/"):
        norm_path += "/"

    # Query normalization (sorted keys for deterministic URL identity)
    query_str = ""
    if parsed.query:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        sorted_pairs = sorted(query_pairs, key=lambda kv: (kv[0], kv[1]))
        query_str = f"?{urlencode(sorted_pairs)}"

    return f"{scheme}://{netloc}{norm_path}{query_str}"


def normalize_structured_data(data: Any) -> Any:
    """
    Recursively cleans whitespace and normalizes dictionary keys/values
    for stable canonical structured representation.
    """
    if isinstance(data, dict):
        cleaned_dict = {}
        for k, v in data.items():
            clean_k = str(k).strip()
            cleaned_dict[clean_k] = normalize_structured_data(v)
        return cleaned_dict
    elif isinstance(data, (list, tuple, set)):
        return [normalize_structured_data(item) for item in data]
    elif isinstance(data, str):
        return clean_whitespace(data)
    elif isinstance(data, Enum):
        return data.value
    elif isinstance(data, (datetime, date)):
        return data.isoformat()
    return data


def canonical_json_dumps(data: Any) -> str:
    """
    Returns a deterministic, canonical JSON string for stable hashing:
    - Keys sorted recursively
    - Compact separators (no extra whitespace)
    - ASCII-safe escaping
    - Deterministic date/enum serialization
    """
    structured = normalize_structured_data(data)
    return json.dumps(
        structured,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def calculate_content_hash(data: Any) -> str:
    """Computes a deterministic SHA-256 hex digest of canonicalized JSON data."""
    canonical_str = canonical_json_dumps(data)
    hasher = hashlib.sha256()
    hasher.update(canonical_str.encode("utf-8"))
    return hasher.hexdigest()


def infer_and_normalize_asset_target(raw_target: str, explicit_type: AssetType | None = None) -> tuple[str, AssetType]:
    """
    Inspects a target string, infers its AssetType (if not provided), and returns
    (normalized_value, asset_type).
    """
    if not raw_target or not isinstance(raw_target, str):
        raise ValueError("Target must be a non-empty string.")

    cleaned = raw_target.strip()

    # 1. Check if URL
    if cleaned.lower().startswith(("http://", "https://")):
        normalized = normalize_url(cleaned)
        return normalized, AssetType.URL

    # 2. Check if CIDR
    if "/" in cleaned and not cleaned.startswith("/"):
        try:
            normalized = normalize_cidr(cleaned)
            return normalized, AssetType.CIDR_RANGE
        except ValueError:
            pass

    # 3. Check if IP (with optional port)
    ip_candidate = cleaned
    port_candidate = None
    if ":" in cleaned and not cleaned.startswith("[") and cleaned.count(":") == 1:
        # IPv4 with port: e.g. 192.168.1.1:8080
        parts = cleaned.split(":")
        ip_candidate = parts[0]
        port_candidate = parts[1]
    elif cleaned.startswith("[") and "]:" in cleaned:
        # IPv6 with port: e.g. [::1]:8080
        parts = cleaned.split("]:")
        ip_candidate = parts[0] + "]"
        port_candidate = parts[1]

    try:
        norm_ip = normalize_ip_address(ip_candidate)
        if port_candidate:
            port_int = int(port_candidate)
            if not (1 <= port_int <= 65535):
                raise ValueError(f"Port {port_int} out of range.")
            if explicit_type == AssetType.SERVICE or explicit_type == AssetType.NETWORK_SERVICE:
                return f"{norm_ip}:{port_int}", explicit_type
            return f"{norm_ip}:{port_int}", AssetType.SERVICE
        return norm_ip, AssetType.IP_ADDRESS
    except ValueError:
        pass

    # 4. Check hostname (with optional port)
    host_candidate = cleaned
    port_candidate = None
    if ":" in cleaned and cleaned.count(":") == 1:
        parts = cleaned.split(":")
        host_candidate = parts[0]
        port_candidate = parts[1]

    norm_host = normalize_hostname(host_candidate)
    if port_candidate:
        port_int = int(port_candidate)
        if not (1 <= port_int <= 65535):
            raise ValueError(f"Port {port_int} out of range.")
        return f"{norm_host}:{port_int}", AssetType.SERVICE

    # Infer DOMAIN vs SUBDOMAIN
    # Simple heuristic: more than 2 labels or sub-label is SUBDOMAIN
    if explicit_type:
        return norm_host, explicit_type

    dot_count = norm_host.count(".")
    if dot_count > 1:
        return norm_host, AssetType.SUBDOMAIN
    return norm_host, AssetType.DOMAIN
