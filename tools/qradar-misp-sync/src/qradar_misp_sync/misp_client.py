"""MISP client wrapper with event creation and sighting feedback support.

Wraps PyMISP to provide offense-oriented operations: creating events from
offense data, searching for existing imports, and reporting sightings.
"""

import logging
from typing import Any

from pymisp import MISPAttribute, MISPEvent, MISPSighting, PyMISP

log = logging.getLogger(__name__)


class MISPClientError(Exception):
    """Raised when a MISP operation fails."""


class MISPClient:
    """High-level MISP client for QRadar integration.

    Args:
        base_url: MISP instance URL (e.g., https://misp.example.com).
        api_key: MISP authentication key.
        verify_ssl: Whether to verify TLS certificates.
        distribution: Default distribution level for new events.
        auto_publish: Whether to auto-publish created events.
        tags: Default tags to apply to created events.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify_ssl: bool = True,
        distribution: int = 0,
        auto_publish: bool = False,
        tags: list[str] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.distribution = distribution
        self.auto_publish = auto_publish
        self.default_tags = tags or ["qradar", "automated-import", "tlp:amber"]

        self._misp = PyMISP(base_url, api_key, ssl=verify_ssl)

    # ------------------------------------------------------------------
    # Event Operations
    # ------------------------------------------------------------------

    def event_exists(self, offense_id: int) -> int | None:
        """Check if a MISP event for this QRadar offense already exists.

        Searches by event info containing the offense ID marker.

        Returns:
            MISP event ID if found, None otherwise.
        """
        search_tag = f"qradar:offense-id={offense_id}"
        try:
            results = self._misp.search(
                controller="events",
                tags=[search_tag],
                limit=1,
                pythonify=True,
            )
            if results and hasattr(results[0], "id"):
                return int(results[0].id)
        except Exception as exc:
            log.debug("Search by tag failed for offense %d, trying info search: %s", offense_id, exc)

        # Fallback: search by event info text
        try:
            results = self._misp.search(
                controller="events",
                eventinfo=f"[QRadar #{offense_id}]",
                limit=1,
                pythonify=True,
            )
            if results and hasattr(results[0], "id"):
                return int(results[0].id)
        except Exception as exc:
            log.debug("Search by info failed for offense %d: %s", offense_id, exc)

        return None

    def create_event(self, event: MISPEvent) -> MISPEvent:
        """Create an event in MISP and optionally publish it.

        Args:
            event: Prepared MISPEvent object.

        Returns:
            The created MISPEvent (with id, uuid populated).

        Raises:
            MISPClientError if creation fails.
        """
        result = self._misp.add_event(event, pythonify=True)

        if isinstance(result, dict) and "errors" in result:
            raise MISPClientError(f"Failed to create event: {result['errors']}")

        if not hasattr(result, "id") or not result.id:
            raise MISPClientError(f"Unexpected response creating event: {result}")

        log.info("Created MISP event #%s: %s", result.id, result.info[:80])

        if self.auto_publish:
            self._misp.publish(result.id)
            log.info("Published MISP event #%s", result.id)

        return result

    def add_attribute(self, event_id: int, attribute: MISPAttribute) -> MISPAttribute:
        """Add a single attribute to an existing MISP event.

        Returns:
            The created attribute.
        """
        result = self._misp.add_attribute(event_id, attribute, pythonify=True)
        if isinstance(result, dict) and "errors" in result:
            raise MISPClientError(f"Failed to add attribute to event {event_id}: {result['errors']}")
        return result

    def update_event(self, event: MISPEvent) -> MISPEvent:
        """Update an existing MISP event.

        Returns:
            The updated event.
        """
        result = self._misp.update_event(event, pythonify=True)
        if isinstance(result, dict) and "errors" in result:
            raise MISPClientError(f"Failed to update event {event.id}: {result['errors']}")
        return result

    # ------------------------------------------------------------------
    # Sighting Operations
    # ------------------------------------------------------------------

    def add_sighting(self, value: str, source: str = "QRadar", sighting_type: int = 0) -> bool:
        """Report a sighting for a given IoC value.

        This tells MISP that QRadar has observed this indicator in live traffic.

        Args:
            value: The IoC value (IP, domain, hash, etc.).
            source: Source identifier (default: "QRadar").
            sighting_type: 0=sighting, 1=false-positive, 2=expiration.

        Returns:
            True if the sighting was successfully recorded.
        """
        try:
            sighting = MISPSighting()
            sighting.value = value
            sighting.source = source
            sighting.type = sighting_type

            result = self._misp.add_sighting(sighting, pythonify=True)

            if isinstance(result, dict) and "message" in result:
                if "No matches" in str(result.get("message", "")):
                    log.debug("Sighting for '%s' - no matching attribute in MISP", value)
                    return False

            log.debug("Recorded sighting for '%s' from %s", value, source)
            return True

        except Exception as exc:
            log.warning("Failed to add sighting for '%s': %s", value, exc)
            return False

    def bulk_add_sightings(self, values: list[str], source: str = "QRadar") -> dict[str, bool]:
        """Report sightings for multiple IoC values.

        Args:
            values: List of IoC values.
            source: Source identifier.

        Returns:
            Dict mapping each value to success (True/False).
        """
        results = {}
        for value in values:
            results[value] = self.add_sighting(value, source=source)
        return results

    # ------------------------------------------------------------------
    # Search (for sighting feedback loop)
    # ------------------------------------------------------------------

    def search_attributes(
        self,
        attr_type: str | list[str] | None = None,
        to_ids: bool = True,
        last: str | None = None,
        tags: list[str] | None = None,
        published: bool = True,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Search MISP attributes (IoCs).

        Args:
            attr_type: Attribute type(s) to search for.
            to_ids: Only return IDS-flagged attributes.
            last: Time window (e.g., "1d", "6h").
            tags: Tag filter.
            published: Only return attributes from published events.
            limit: Maximum results.

        Returns:
            List of attribute dicts.
        """
        kwargs: dict[str, Any] = {
            "controller": "attributes",
            "to_ids": to_ids,
            "published": published,
            "limit": limit,
            "enforceWarninglist": True,
        }
        if attr_type:
            kwargs["type_attribute"] = attr_type
        if last:
            kwargs["last"] = last
        if tags:
            kwargs["tags"] = tags

        try:
            result = self._misp.search(**kwargs)
            if isinstance(result, dict) and "Attribute" in result:
                return result["Attribute"]
            if isinstance(result, dict) and "response" in result:
                attrs = []
                for item in result["response"].get("Attribute", []):
                    attrs.append(item)
                return attrs
            return []
        except Exception as exc:
            log.error("MISP attribute search failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def build_event(
        self,
        info: str,
        threat_level_id: int = 2,
        analysis: int = 0,
        tags: list[str] | None = None,
        date: str | None = None,
    ) -> MISPEvent:
        """Build a MISPEvent with default settings.

        Args:
            info: Event description.
            threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined.
            analysis: 0=Initial, 1=Ongoing, 2=Completed.
            tags: Additional tags (appended to default tags).
            date: Event date (YYYY-MM-DD). Defaults to today.

        Returns:
            Prepared MISPEvent (not yet submitted).
        """
        event = MISPEvent()
        event.info = info[:500]
        event.distribution = self.distribution
        event.threat_level_id = threat_level_id
        event.analysis = analysis

        if date:
            event.date = date

        all_tags = list(self.default_tags)
        if tags:
            all_tags.extend(tags)
        for tag in all_tags:
            event.add_tag(tag.strip())

        return event

    def test_connection(self) -> dict:
        """Test the connection to MISP.

        Returns:
            MISP version info dict.

        Raises:
            MISPClientError if connection fails.
        """
        try:
            result = self._misp.get_version()
            if isinstance(result, dict) and "version" in result:
                log.info("Connected to MISP %s", result["version"])
                return result
            raise MISPClientError(f"Unexpected response: {result}")
        except Exception as exc:
            raise MISPClientError(f"Connection test failed: {exc}") from exc
