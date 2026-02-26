"""Sighting feedback loop: QRadar detections -> MISP sightings.

This module implements the reverse feedback path: when QRadar detects traffic
matching known IoCs (from MISP reference sets), we report those detections
back to MISP as sightings. This keeps MISP's sighting counts current and
helps analysts gauge which IoCs are actively being observed.

Flow:
1. Pull recent IoCs from MISP (type: ip-src, ip-dst, domain, md5, sha256, url)
2. Query QRadar AQL to check if any of those IoCs appeared in recent events
3. For IoCs found in QRadar events, report a sighting back to MISP
"""

import logging
import time

from .misp_client import MISPClient
from .qradar_client import QRadarClient, QRadarAPIError
from .state import StateManager

log = logging.getLogger(__name__)

# MISP attribute types grouped by how we query them in QRadar
SIGHTING_QUERIES = {
    "ip": {
        "misp_types": ["ip-src", "ip-dst"],
        "aql_template": (
            "SELECT sourceip, destinationip, COUNT(*) as hit_count "
            "FROM events WHERE (sourceip IN ({values}) OR destinationip IN ({values})) "
            "GROUP BY sourceip, destinationip "
            "LAST {time_window}"
        ),
        "extract_fields": ["sourceip", "destinationip"],
    },
    "domain": {
        "misp_types": ["domain", "hostname"],
        "aql_template": (
            "SELECT \"DNS Request Name\" as dns_name, COUNT(*) as hit_count "
            "FROM events WHERE \"DNS Request Name\" IN ({values}) "
            "GROUP BY \"DNS Request Name\" "
            "LAST {time_window}"
        ),
        "extract_fields": ["dns_name"],
    },
    "url": {
        "misp_types": ["url"],
        "aql_template": (
            "SELECT url, COUNT(*) as hit_count "
            "FROM events WHERE url IN ({values}) "
            "GROUP BY url "
            "LAST {time_window}"
        ),
        "extract_fields": ["url"],
    },
}

# Maximum IoCs to query per AQL batch (QRadar IN clause limit)
MAX_BATCH_SIZE = 200


class SightingFeedback:
    """Reports QRadar detections back to MISP as sightings.

    Args:
        qradar: QRadar API client.
        misp: MISP client.
        state: State manager for cursor tracking.
        misp_lookback: How far back to pull IoCs from MISP (e.g., "30d").
        qradar_lookback: How far back to search in QRadar events (e.g., "24 HOURS").
        source_name: Source name to use in MISP sightings.
    """

    def __init__(
        self,
        qradar: QRadarClient,
        misp: MISPClient,
        state: StateManager,
        misp_lookback: str = "30d",
        qradar_lookback: str = "24 HOURS",
        source_name: str = "QRadar",
    ):
        self._qradar = qradar
        self._misp = misp
        self._state = state
        self._misp_lookback = misp_lookback
        self._qradar_lookback = qradar_lookback
        self._source_name = source_name

    def run(self) -> int:
        """Execute one sighting feedback cycle.

        Returns:
            Number of sightings successfully reported.
        """
        total_sightings = 0

        for category, config in SIGHTING_QUERIES.items():
            try:
                count = self._process_category(category, config)
                total_sightings += count
            except Exception as exc:
                log.warning("Sighting feedback for '%s' failed: %s", category, exc)

        # Update cursor
        self._state.sighting_cursor = int(time.time())
        self._state.increment_stat("total_sightings_reported", total_sightings)
        self._state.save()

        if total_sightings > 0:
            log.info("Sighting feedback: reported %d sightings to MISP", total_sightings)
        else:
            log.debug("Sighting feedback: no new sightings to report")

        return total_sightings

    def _process_category(self, category: str, config: dict) -> int:
        """Process a single IoC category (IPs, domains, URLs).

        1. Pull IoC values from MISP
        2. Batch-query QRadar
        3. Report sightings for matches

        Returns:
            Number of sightings reported for this category.
        """
        # Step 1: Get IoC values from MISP
        misp_iocs = self._misp.search_attributes(
            attr_type=config["misp_types"],
            to_ids=True,
            last=self._misp_lookback,
            limit=2000,
        )

        if not misp_iocs:
            log.debug("No %s IoCs found in MISP for sighting feedback", category)
            return 0

        # Deduplicate values
        values = list({attr.get("value", "") for attr in misp_iocs if attr.get("value")})
        log.debug("Sighting feedback: %d unique %s values from MISP", len(values), category)

        if not values:
            return 0

        # Step 2: Query QRadar in batches
        detected_values = set()
        for batch_start in range(0, len(values), MAX_BATCH_SIZE):
            batch = values[batch_start : batch_start + MAX_BATCH_SIZE]
            try:
                detected = self._query_qradar_batch(config, batch)
                detected_values.update(detected)
            except QRadarAPIError as exc:
                log.warning("AQL sighting query for %s batch failed: %s", category, exc)

        if not detected_values:
            log.debug("No %s sightings detected in QRadar", category)
            return 0

        # Step 3: Report sightings to MISP
        sighting_count = 0
        for value in detected_values:
            success = self._misp.add_sighting(value, source=self._source_name)
            if success:
                sighting_count += 1

        log.info("Sighting feedback [%s]: %d/%d IoCs observed in QRadar, %d sightings reported",
                 category, len(detected_values), len(values), sighting_count)

        return sighting_count

    def _query_qradar_batch(self, config: dict, values: list[str]) -> set[str]:
        """Query QRadar for a batch of IoC values.

        Returns:
            Set of values that were found in QRadar events.
        """
        # Build AQL IN clause: ('val1','val2','val3')
        quoted = ", ".join(f"'{v}'" for v in values)
        aql = config["aql_template"].format(
            values=quoted,
            time_window=self._qradar_lookback,
        )

        rows = self._qradar.aql_search(aql, timeout_seconds=120)

        # Extract detected values from results
        detected = set()
        value_set = set(values)  # For O(1) lookup

        for row in rows:
            for field in config["extract_fields"]:
                val = row.get(field, "")
                if val and val in value_set:
                    detected.add(val)

        return detected
