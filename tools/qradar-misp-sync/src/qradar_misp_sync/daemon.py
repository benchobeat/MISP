"""Main daemon orchestrator.

Coordinates the offense polling loop, AQL enrichment, event creation,
and sighting feedback into a single long-running process.
"""

import logging
import signal
import time

from .config import AppConfig
from .converter import OffenseConverter
from .enrichment import AQLEnrichmentEngine
from .misp_client import MISPClient, MISPClientError
from .qradar_client import QRadarClient, QRadarAPIError
from .sighting_feedback import SightingFeedback
from .state import StateManager

log = logging.getLogger(__name__)


class SyncDaemon:
    """Main daemon that orchestrates QRadar -> MISP sync.

    Runs two alternating loops:
    1. **Offense poll**: Every `poller.interval_seconds`, fetch new offenses,
       enrich them via AQL, and create MISP events.
    2. **Sighting feedback**: Every `sighting.interval_seconds`, pull MISP IoCs,
       check QRadar for matches, and report sightings.

    Args:
        config: Validated application configuration.
    """

    def __init__(self, config: AppConfig):
        self._config = config
        self._running = False

        # Initialize components
        self._qradar = QRadarClient(
            base_url=config.qradar.url,
            api_token=config.qradar.api_token,
            verify_ssl=config.qradar.verify_ssl,
            timeout=config.qradar.timeout,
        )
        self._misp = MISPClient(
            base_url=config.misp.url,
            api_key=config.misp.api_key,
            verify_ssl=config.misp.verify_ssl,
            distribution=config.misp.distribution,
            auto_publish=config.misp.auto_publish,
            tags=config.misp.tags,
        )
        self._state = StateManager(config.state_file)

        self._enricher = None
        if config.enrichment.enabled:
            self._enricher = AQLEnrichmentEngine(
                qradar=self._qradar,
                time_window=config.enrichment.time_window,
                max_results_per_query=config.enrichment.max_results_per_query,
                aql_timeout=config.enrichment.aql_timeout,
            )

        self._sighting = None
        if config.sighting.enabled:
            self._sighting = SightingFeedback(
                qradar=self._qradar,
                misp=self._misp,
                state=self._state,
                misp_lookback=config.sighting.misp_lookback,
                qradar_lookback=config.sighting.qradar_lookback,
                source_name=config.sighting.source_name,
            )

        self._converter = OffenseConverter(misp=self._misp)
        self._last_sighting_run = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def test_connections(self):
        """Test connectivity to both QRadar and MISP before starting.

        Raises on failure.
        """
        log.info("Testing QRadar connection at %s...", self._config.qradar.url)
        info = self._qradar.test_connection()
        log.info("QRadar OK: %s", info)

        log.info("Testing MISP connection at %s...", self._config.misp.url)
        self._misp.test_connection()

    def run(self, once: bool = False):
        """Start the daemon loop.

        Args:
            once: If True, run a single poll cycle and exit.
        """
        self._running = True

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        log.info("=== QRadar-MISP Sync Daemon started ===")
        log.info("Poll interval: %ds", self._config.poller.interval_seconds)
        log.info("Min magnitude: %d", self._config.poller.min_magnitude)
        log.info("Enrichment: %s", "enabled" if self._enricher else "disabled")
        log.info("Sighting feedback: %s (every %ds)",
                 "enabled" if self._sighting else "disabled",
                 self._config.sighting.interval_seconds)
        log.info("State file: %s", self._config.state_file)
        log.info("Last offense ID: %d", self._state.last_offense_id)

        if once:
            self._poll_cycle()
            if self._sighting:
                self._sighting.run()
            return

        while self._running:
            try:
                self._poll_cycle()
            except Exception as exc:
                log.error("Poll cycle failed: %s", exc, exc_info=True)
                self._state.set_last_error(str(exc))
                self._state.save()

            # Run sighting feedback if interval has elapsed
            if self._sighting:
                now = time.time()
                if now - self._last_sighting_run >= self._config.sighting.interval_seconds:
                    try:
                        self._sighting.run()
                    except Exception as exc:
                        log.error("Sighting feedback failed: %s", exc, exc_info=True)
                    self._last_sighting_run = now

            # Sleep until next poll (interruptible)
            self._interruptible_sleep(self._config.poller.interval_seconds)

        log.info("=== QRadar-MISP Sync Daemon stopped ===")

    def stop(self):
        """Signal the daemon to stop."""
        self._running = False
        log.info("Shutdown requested")

    def _handle_signal(self, signum, frame):
        """Handle SIGTERM/SIGINT for graceful shutdown."""
        sig_name = signal.Signals(signum).name
        log.info("Received %s, initiating shutdown...", sig_name)
        self.stop()

    def _interruptible_sleep(self, seconds: int):
        """Sleep in small increments so we can respond to shutdown signals."""
        end = time.time() + seconds
        while self._running and time.time() < end:
            time.sleep(min(1, end - time.time()))

    # ------------------------------------------------------------------
    # Core Poll Cycle
    # ------------------------------------------------------------------

    def _poll_cycle(self):
        """Execute one offense polling cycle.

        1. Fetch new offenses from QRadar
        2. For each offense: resolve IPs, enrich via AQL, create MISP event
        3. Update state
        """
        last_id = self._state.last_offense_id
        min_mag = self._config.poller.min_magnitude
        max_offenses = self._config.poller.max_offenses_per_cycle

        # Build filter
        filter_parts = [f"id > {last_id}", f"magnitude >= {min_mag}"]
        categories = self._config.poller.offense_filter_categories
        if categories:
            cat_filter = " or ".join(f"categories = '{c}'" for c in categories)
            filter_parts.append(f"({cat_filter})")
        filter_query = " and ".join(filter_parts)

        fields = (
            "id,description,magnitude,categories,category_count,"
            "offense_type_str,status,source_address_ids,"
            "local_destination_address_ids,start_time"
        )

        log.debug("Polling offenses: %s", filter_query)

        try:
            offenses = self._qradar.get_offenses(
                filter_query=filter_query,
                fields=fields,
                sort="+id",
                range_start=0,
                range_end=max_offenses - 1,
            )
        except QRadarAPIError as exc:
            log.error("Failed to fetch offenses: %s", exc)
            return

        if not offenses:
            log.debug("No new offenses found")
            return

        log.info("Found %d new offense(s) to process", len(offenses))

        for offense in offenses:
            if not self._running:
                break
            self._process_offense(offense)

    def _process_offense(self, offense: dict):
        """Process a single offense: resolve, enrich, convert, create."""
        offense_id = offense["id"]

        # Skip if already processed (dedup check)
        if self._state.is_offense_processed(offense_id):
            log.debug("Offense #%d already processed, skipping", offense_id)
            return

        log.info("Processing offense #%d: %s (magnitude: %s)",
                 offense_id,
                 offense.get("description", "")[:80],
                 offense.get("magnitude"))

        # Check if MISP event already exists
        existing = self._misp.event_exists(offense_id)
        if existing:
            log.info("MISP event already exists for offense #%d (event #%d), skipping", offense_id, existing)
            self._state.mark_offense_processed(offense_id)
            self._state.save()
            return

        # Resolve IP addresses from offense metadata
        source_ids = offense.get("source_address_ids", [])
        dest_ids = offense.get("local_destination_address_ids", [])

        offense["_resolved_source_ips"] = self._qradar.resolve_source_ips(source_ids) if source_ids else []
        offense["_resolved_dest_ips"] = self._qradar.resolve_destination_ips(dest_ids) if dest_ids else []

        # AQL enrichment
        enriched = None
        if self._enricher:
            enriched = self._enricher.enrich(offense_id)

        # Convert to MISP event
        event = self._converter.convert(offense, enriched)

        # Submit to MISP
        try:
            created = self._misp.create_event(event)
            attr_count = len(created.Attribute) if hasattr(created, "Attribute") else 0
            log.info("Created MISP event #%s for offense #%d (%d attributes)",
                     created.id, offense_id, attr_count)
            self._state.increment_stat("total_events_created")
        except MISPClientError as exc:
            log.error("Failed to create MISP event for offense #%d: %s", offense_id, exc)
            self._state.set_last_error(f"Offense #{offense_id}: {exc}")
            self._state.save()
            return

        # Mark as processed
        self._state.mark_offense_processed(offense_id)
        self._state.increment_stat("total_offenses_processed")
        self._state.set_last_error(None)
        self._state.save()
