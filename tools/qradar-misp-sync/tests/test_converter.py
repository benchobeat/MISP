"""Tests for offense-to-MISP event conversion."""

import pytest
from unittest.mock import MagicMock

from qradar_misp_sync.converter import OffenseConverter, is_public_ip, magnitude_to_threat_level
from qradar_misp_sync.enrichment import EnrichedIOCs


class TestIPClassification:
    def test_public_ip(self):
        assert is_public_ip("8.8.8.8") is True
        assert is_public_ip("185.220.101.1") is True
        assert is_public_ip("1.1.1.1") is True

    def test_private_ip(self):
        assert is_public_ip("10.0.0.1") is False
        assert is_public_ip("192.168.1.1") is False
        assert is_public_ip("172.16.0.1") is False

    def test_reserved_ip(self):
        assert is_public_ip("127.0.0.1") is False
        assert is_public_ip("169.254.1.1") is False
        assert is_public_ip("224.0.0.1") is False

    def test_invalid_ip(self):
        assert is_public_ip("not-an-ip") is False
        assert is_public_ip("") is False


class TestMagnitudeMapping:
    def test_high(self):
        assert magnitude_to_threat_level(8) == 1
        assert magnitude_to_threat_level(10) == 1

    def test_medium(self):
        assert magnitude_to_threat_level(5) == 2
        assert magnitude_to_threat_level(7) == 2

    def test_low(self):
        assert magnitude_to_threat_level(3) == 3
        assert magnitude_to_threat_level(4) == 3

    def test_undefined(self):
        assert magnitude_to_threat_level(0) == 4
        assert magnitude_to_threat_level(2) == 4


class TestOffenseConverter:
    def _make_converter(self):
        misp = MagicMock()
        # Mock build_event to return a real-ish MISPEvent-like mock
        from pymisp import MISPEvent
        def build_event_side_effect(**kwargs):
            event = MISPEvent()
            event.info = kwargs.get("info", "test")
            event.distribution = kwargs.get("distribution", 0)
            event.threat_level_id = kwargs.get("threat_level_id", 2)
            event.analysis = kwargs.get("analysis", 0)
            for tag in kwargs.get("tags", []):
                event.add_tag(tag)
            if kwargs.get("date"):
                event.date = kwargs["date"]
            return event

        misp.build_event = MagicMock(side_effect=build_event_side_effect)
        return OffenseConverter(misp=misp)

    def test_basic_offense_conversion(self):
        converter = self._make_converter()
        offense = {
            "id": 42,
            "description": "Malware C2 detected",
            "magnitude": 8,
            "categories": ["Malware"],
            "category_count": 1,
            "offense_type_str": "Source IP",
            "status": "OPEN",
            "start_time": 1700000000000,
            "source_address_ids": [],
            "local_destination_address_ids": [],
            "_resolved_source_ips": ["185.220.101.1"],
            "_resolved_dest_ips": ["10.0.0.5"],
        }

        event = converter.convert(offense)

        assert "[QRadar #42]" in event.info
        assert "Malware C2 detected" in event.info
        # Should have at least the metadata comment + 2 IP attributes
        assert len(event.Attribute) >= 3

    def test_public_ip_gets_to_ids(self):
        converter = self._make_converter()
        offense = {
            "id": 1,
            "description": "Test",
            "magnitude": 5,
            "categories": [],
            "category_count": 0,
            "offense_type_str": "Source IP",
            "status": "OPEN",
            "start_time": 0,
            "_resolved_source_ips": ["185.220.101.1"],
            "_resolved_dest_ips": [],
        }

        event = converter.convert(offense)

        # Find the ip-src attribute
        ip_attrs = [a for a in event.Attribute if a.type == "ip-src"]
        assert len(ip_attrs) == 1
        assert ip_attrs[0].to_ids is True

    def test_private_ip_no_to_ids(self):
        converter = self._make_converter()
        offense = {
            "id": 1,
            "description": "Test",
            "magnitude": 5,
            "categories": [],
            "category_count": 0,
            "offense_type_str": "Dest IP",
            "status": "OPEN",
            "start_time": 0,
            "_resolved_source_ips": [],
            "_resolved_dest_ips": ["192.168.1.100"],
        }

        event = converter.convert(offense)

        ip_attrs = [a for a in event.Attribute if a.type == "ip-dst"]
        assert len(ip_attrs) == 1
        assert ip_attrs[0].to_ids is False

    def test_enriched_iocs_added(self):
        converter = self._make_converter()
        offense = {
            "id": 99,
            "description": "Enrichment test",
            "magnitude": 7,
            "categories": ["Suspicious Activity"],
            "category_count": 1,
            "offense_type_str": "Source IP",
            "status": "OPEN",
            "start_time": 0,
            "_resolved_source_ips": [],
            "_resolved_dest_ips": [],
        }

        enriched = EnrichedIOCs(
            source_ips=["8.8.8.8"],
            dest_ips=[],
            urls=["https://evil.example.com/payload.exe"],
            domains=["evil.example.com"],
            file_hashes_sha256=["a" * 64],
            usernames=["compromised_user"],
        )

        event = converter.convert(offense, enriched)

        types_present = {a.type for a in event.Attribute}
        assert "url" in types_present
        assert "domain" in types_present
        assert "sha256" in types_present
        assert "target-user" in types_present
        assert "ip-src" in types_present
