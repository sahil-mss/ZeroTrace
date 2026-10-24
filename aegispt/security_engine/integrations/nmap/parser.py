"""Safe Nmap XML output parser.

TASK 3 & 4: Uses defusedxml to safely parse Nmap XML reports, protecting against
XXE (XML External Entity) and entity expansion attacks. Converts raw host/port
XML elements into standardized ServiceObservation objects.
"""

from pathlib import Path
from typing import Any
import defusedxml.ElementTree as ET

from aegispt.security_engine.schemas.observation import ServiceObservation


class NmapParserError(Exception):
    """Raised when an Nmap XML report is malformed, truncated, or unreadable."""


class NmapXMLParser:
    """Parses structured Nmap XML documents into normalized telemetry models."""

    @classmethod
    def parse_file(cls, file_path: str | Path, strict: bool = True) -> list[ServiceObservation]:
        """Parse Nmap XML output from a file path."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Nmap XML file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            return cls.parse_string(content, strict=strict)
        except Exception as exc:
            if isinstance(exc, (FileNotFoundError, NmapParserError)):
                raise
            raise NmapParserError(f"Failed to read Nmap output file '{path}': {exc}") from exc

    @classmethod
    def parse_string(cls, xml_text: str, strict: bool = True) -> list[ServiceObservation]:
        """Parse Nmap XML output from a string.

        Extracts:
        - Host address (IPv4 / IPv6)
        - Hostname (if present)
        - Port number (1-65535)
        - Protocol ('tcp', 'udp')
        - Port state ('open', 'closed', 'filtered', etc.)
        - Service name ('http', 'ssh', etc.)
        - Service version and product details (if probed)
        """
        if not xml_text or not xml_text.strip():
            if strict:
                raise NmapParserError("Nmap XML document is empty.")
            return []

        try:
            root = ET.fromstring(xml_text.strip())
        except Exception as exc:
            if strict:
                raise NmapParserError(f"Malformed or invalid Nmap XML: {exc}") from exc
            return []

        if root.tag != "nmaprun":
            if strict:
                raise NmapParserError(f"Expected root tag '<nmaprun>', found '<{root.tag}>'.")
            return []

        observations: list[ServiceObservation] = []

        # Iterate over all <host> elements
        for host in root.findall("host"):
            host_address = cls._extract_host_address(host)
            if not host_address:
                # If host has no address element, skip
                continue

            hostname = cls._extract_hostname(host)

            # Ports container may be absent if host was down or no ports scanned
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                obs = cls._extract_port_observation(
                    port_elem=port_elem,
                    host_address=host_address,
                    hostname=hostname,
                )
                if obs is not None:
                    observations.append(obs)

        return observations

    @classmethod
    def _extract_host_address(cls, host_elem: Any) -> str | None:
        """Extract primary IPv4 or IPv6 address from <host> element."""
        addresses = host_elem.findall("address")
        if not addresses:
            return None

        # Prioritize IPv4, then IPv6, then any address
        for addr in addresses:
            addr_type = addr.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6"):
                return addr.get("addr")

        return addresses[0].get("addr")

    @classmethod
    def _extract_hostname(cls, host_elem: Any) -> str | None:
        """Extract primary hostname from <hostnames> container if present."""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is None:
            return None

        hostname_node = hostnames_elem.find("hostname")
        if hostname_node is not None:
            name = hostname_node.get("name")
            if name:
                return name.strip()

        return None

    @classmethod
    def _extract_port_observation(
        cls,
        port_elem: Any,
        host_address: str,
        hostname: str | None,
    ) -> ServiceObservation | None:
        """Extract a single ServiceObservation from a <port> element."""
        port_str = port_elem.get("portid")
        if not port_str:
            return None

        try:
            port_num = int(port_str)
        except ValueError:
            return None

        if not (1 <= port_num <= 65535):
            return None

        protocol = port_elem.get("protocol", "tcp").lower()

        # State element
        state_elem = port_elem.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

        # Service element (may be omitted)
        service_elem = port_elem.find("service")
        service_name: str | None = None
        service_version: str | None = None
        product: str | None = None
        extra_info: str | None = None

        if service_elem is not None:
            service_name = service_elem.get("name")
            product = service_elem.get("product")
            service_version = service_elem.get("version")
            extra_info = service_elem.get("extrainfo")

        return ServiceObservation(
            host_address=host_address,
            hostname=hostname,
            port=port_num,
            protocol=protocol,
            state=state,
            service_name=service_name,
            service_version=service_version,
            product=product,
            extra_info=extra_info,
        )
