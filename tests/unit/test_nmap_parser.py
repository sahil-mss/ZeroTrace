"""Unit tests for NmapXMLParser using static XML fixtures."""

from pathlib import Path
import pytest

from aegispt.security_engine.integrations.nmap.parser import (
    NmapParserError,
    NmapXMLParser,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "nmap"


class TestNmapXMLParser:
    """Verifies XML parsing extraction, field mappings, and error handling."""

    def test_parse_open_ports(self) -> None:
        """Verify extraction of open ports, services, versions, and product names."""
        fixture_path = FIXTURES_DIR / "sample_open_ports.xml"
        obs = NmapXMLParser.parse_file(fixture_path)

        assert len(obs) == 2

        # Port 3000 (Juice Shop / Node.js)
        juice_port = next(o for o in obs if o.port == 3000)
        assert juice_port.host_address == "127.0.0.1"
        assert juice_port.hostname == "localhost"
        assert juice_port.protocol == "tcp"
        assert juice_port.state == "open"
        assert juice_port.service_name == "http"
        assert juice_port.service_version == "17.1.1"
        assert "Node.js" in (juice_port.product or "")

        # Port 80 (Apache)
        apache_port = next(o for o in obs if o.port == 80)
        assert apache_port.host_address == "127.0.0.1"
        assert apache_port.state == "open"
        assert apache_port.service_name == "http"
        assert apache_port.service_version == "2.4.52"

    def test_parse_closed_and_filtered_ports(self) -> None:
        """Verify extraction of closed and filtered ports."""
        fixture_path = FIXTURES_DIR / "sample_closed_filtered.xml"
        obs = NmapXMLParser.parse_file(fixture_path)

        assert len(obs) == 2

        port_22 = next(o for o in obs if o.port == 22)
        assert port_22.state == "closed"
        assert port_22.protocol == "tcp"

        port_8080 = next(o for o in obs if o.port == 8080)
        assert port_8080.state == "filtered"
        assert port_8080.protocol == "tcp"

    def test_parse_missing_service_information(self) -> None:
        """Verify robust parsing when <service> tags are omitted."""
        fixture_path = FIXTURES_DIR / "sample_missing_service_info.xml"
        obs = NmapXMLParser.parse_file(fixture_path)

        assert len(obs) == 1
        port_5000 = obs[0]
        assert port_5000.port == 5000
        assert port_5000.state == "open"
        assert port_5000.service_name is None
        assert port_5000.service_version is None
        assert port_5000.product is None

    def test_parse_multiple_hosts(self) -> None:
        """Verify parsing XML reports containing multiple host elements."""
        fixture_path = FIXTURES_DIR / "sample_multiple_hosts.xml"
        obs = NmapXMLParser.parse_file(fixture_path)

        assert len(obs) == 2
        host_addrs = {o.host_address for o in obs}
        assert "127.0.0.1" in host_addrs
        assert "172.18.0.2" in host_addrs

        host1 = next(o for o in obs if o.host_address == "127.0.0.1")
        assert host1.hostname == "localhost"
        assert host1.port == 3000

        host2 = next(o for o in obs if o.host_address == "172.18.0.2")
        assert host2.hostname == "lab-juice-shop.internal"
        assert host2.port == 80
        assert host2.product == "nginx"

    def test_parse_malformed_xml_strict_raises_error(self) -> None:
        """Malformed XML raises NmapParserError when strict=True."""
        fixture_path = FIXTURES_DIR / "sample_malformed.xml"
        with pytest.raises(NmapParserError) as exc_info:
            NmapXMLParser.parse_file(fixture_path, strict=True)
        assert "Malformed or invalid Nmap XML" in str(exc_info.value)

    def test_parse_malformed_xml_non_strict_returns_empty(self) -> None:
        """Malformed XML returns empty list when strict=False."""
        fixture_path = FIXTURES_DIR / "sample_malformed.xml"
        obs = NmapXMLParser.parse_file(fixture_path, strict=False)
        assert obs == []

    def test_parse_empty_string_handling(self) -> None:
        """Empty string handled cleanly."""
        with pytest.raises(NmapParserError):
            NmapXMLParser.parse_string("", strict=True)

        assert NmapXMLParser.parse_string("", strict=False) == []
