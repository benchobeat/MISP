"""AQL-based enrichment engine for QRadar offenses.

Runs targeted AQL queries against offense events to extract additional IoCs
beyond what the offense metadata provides (IPs with ports, URLs, domains,
file hashes, usernames, DNS queries).
"""

import logging
from dataclasses import dataclass, field

from .qradar_client import QRadarClient, QRadarAPIError

log = logging.getLogger(__name__)


@dataclass
class EnrichedIOCs:
    """Container for all IoCs extracted from an offense via AQL enrichment."""

    # Network indicators
    source_ips: list[str] = field(default_factory=list)
    dest_ips: list[str] = field(default_factory=list)
    ip_port_pairs: list[tuple[str, int, str]] = field(default_factory=list)  # (ip, port, direction)
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)

    # File indicators
    file_hashes_md5: list[str] = field(default_factory=list)
    file_hashes_sha1: list[str] = field(default_factory=list)
    file_hashes_sha256: list[str] = field(default_factory=list)
    filenames: list[str] = field(default_factory=list)

    # Identity indicators
    usernames: list[str] = field(default_factory=list)

    # Email indicators
    email_senders: list[str] = field(default_factory=list)
    email_subjects: list[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        """Total number of enriched IoCs found."""
        return (
            len(self.source_ips) + len(self.dest_ips) + len(self.ip_port_pairs)
            + len(self.urls) + len(self.domains)
            + len(self.file_hashes_md5) + len(self.file_hashes_sha1) + len(self.file_hashes_sha256)
            + len(self.filenames) + len(self.usernames)
            + len(self.email_senders) + len(self.email_subjects)
        )


class AQLEnrichmentEngine:
    """Extracts additional IoCs from QRadar offense events via AQL queries.

    Args:
        qradar: QRadar API client.
        time_window: AQL time window (e.g., "24 HOURS", "7 DAYS").
        max_results_per_query: Maximum rows per AQL query.
        aql_timeout: Timeout for each AQL query in seconds.
    """

    def __init__(
        self,
        qradar: QRadarClient,
        time_window: str = "24 HOURS",
        max_results_per_query: int = 100,
        aql_timeout: int = 120,
    ):
        self._qradar = qradar
        self._time_window = time_window
        self._max_results = max_results_per_query
        self._aql_timeout = aql_timeout

    def enrich(self, offense_id: int) -> EnrichedIOCs:
        """Run all enrichment queries for an offense.

        Each query is independent and failures are non-fatal.

        Args:
            offense_id: QRadar offense ID to enrich.

        Returns:
            EnrichedIOCs with all extracted indicators.
        """
        result = EnrichedIOCs()

        enrichers = [
            ("network IPs", self._enrich_network_ips),
            ("URLs", self._enrich_urls),
            ("domains/DNS", self._enrich_domains),
            ("file hashes", self._enrich_file_hashes),
            ("usernames", self._enrich_usernames),
            ("email", self._enrich_email),
        ]

        for name, enricher_fn in enrichers:
            try:
                enricher_fn(offense_id, result)
            except QRadarAPIError as exc:
                log.warning("AQL enrichment '%s' failed for offense %d: %s", name, offense_id, exc)
            except Exception as exc:
                log.warning("Unexpected error in '%s' enrichment for offense %d: %s", name, offense_id, exc)

        log.info("Enrichment for offense %d: %d total IoCs extracted", offense_id, result.total_count)
        return result

    # ------------------------------------------------------------------
    # Individual Enrichment Queries
    # ------------------------------------------------------------------

    def _enrich_network_ips(self, offense_id: int, result: EnrichedIOCs):
        """Extract unique source/destination IP:port pairs from offense events."""
        aql = (
            f"SELECT sourceip, sourceport, destinationip, destinationport "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"GROUP BY sourceip, sourceport, destinationip, destinationport "
            f"ORDER BY destinationport ASC "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)

        seen_src = set()
        seen_dst = set()
        for row in rows:
            src_ip = row.get("sourceip")
            src_port = row.get("sourceport")
            dst_ip = row.get("destinationip")
            dst_port = row.get("destinationport")

            if src_ip and src_ip not in seen_src:
                seen_src.add(src_ip)
                result.source_ips.append(src_ip)
                if src_port and int(src_port) not in (0,):
                    result.ip_port_pairs.append((src_ip, int(src_port), "src"))

            if dst_ip and dst_ip not in seen_dst:
                seen_dst.add(dst_ip)
                result.dest_ips.append(dst_ip)
                if dst_port and int(dst_port) not in (0,):
                    result.ip_port_pairs.append((dst_ip, int(dst_port), "dst"))

    def _enrich_urls(self, offense_id: int, result: EnrichedIOCs):
        """Extract unique URLs from offense events."""
        aql = (
            f"SELECT DISTINCT url "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"AND url IS NOT NULL AND url != 'N/A' "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)

        seen = set()
        for row in rows:
            url = row.get("url", "")
            if url and url not in seen and url != "N/A":
                seen.add(url)
                result.urls.append(url)

    def _enrich_domains(self, offense_id: int, result: EnrichedIOCs):
        """Extract DNS query domains from offense events.

        Looks at both the 'DomainName' and DNS-specific log source fields.
        """
        # Try DNS query names first
        aql = (
            f"SELECT DISTINCT \"DNS Request Name\" as dns_name "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"AND \"DNS Request Name\" IS NOT NULL "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        try:
            rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)
            seen = set()
            for row in rows:
                domain = row.get("dns_name", "")
                if domain and domain not in seen:
                    seen.add(domain)
                    result.domains.append(domain)
        except QRadarAPIError:
            log.debug("DNS Request Name field not available, trying DomainName")

        # Fallback: try generic DomainName field
        if not result.domains:
            aql = (
                f"SELECT DISTINCT DomainName "
                f"FROM events WHERE INOFFENSE({offense_id}) "
                f"AND DomainName IS NOT NULL AND DomainName != 'N/A' "
                f"LIMIT {self._max_results} LAST {self._time_window}"
            )
            try:
                rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)
                seen = set()
                for row in rows:
                    domain = row.get("DomainName", row.get("domainname", ""))
                    if domain and domain not in seen and domain != "N/A":
                        seen.add(domain)
                        result.domains.append(domain)
            except QRadarAPIError:
                log.debug("DomainName field not available either")

    def _enrich_file_hashes(self, offense_id: int, result: EnrichedIOCs):
        """Extract file hashes from offense events.

        Looks at common QRadar DSM fields for file hashes:
        - File Hash (generic)
        - MD5 Hash
        - SHA1 Hash
        - SHA256 Hash
        - Filename
        """
        # SHA256
        aql = (
            f"SELECT DISTINCT \"SHA256 Hash\" as hash_val "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"AND \"SHA256 Hash\" IS NOT NULL "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        try:
            rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)
            for row in rows:
                h = row.get("hash_val", "")
                if h and len(h) == 64:
                    result.file_hashes_sha256.append(h.lower())
        except QRadarAPIError:
            log.debug("SHA256 Hash field not available")

        # MD5
        aql = (
            f"SELECT DISTINCT \"MD5 Hash\" as hash_val "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"AND \"MD5 Hash\" IS NOT NULL "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        try:
            rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)
            for row in rows:
                h = row.get("hash_val", "")
                if h and len(h) == 32:
                    result.file_hashes_md5.append(h.lower())
        except QRadarAPIError:
            log.debug("MD5 Hash field not available")

        # SHA1
        aql = (
            f"SELECT DISTINCT \"SHA1 Hash\" as hash_val "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"AND \"SHA1 Hash\" IS NOT NULL "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        try:
            rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)
            for row in rows:
                h = row.get("hash_val", "")
                if h and len(h) == 40:
                    result.file_hashes_sha1.append(h.lower())
        except QRadarAPIError:
            log.debug("SHA1 Hash field not available")

        # Filenames
        aql = (
            f"SELECT DISTINCT Filename "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"AND Filename IS NOT NULL AND Filename != 'N/A' "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        try:
            rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)
            for row in rows:
                fname = row.get("Filename", row.get("filename", ""))
                if fname and fname != "N/A":
                    result.filenames.append(fname)
        except QRadarAPIError:
            log.debug("Filename field not available")

    def _enrich_usernames(self, offense_id: int, result: EnrichedIOCs):
        """Extract usernames from offense events."""
        aql = (
            f"SELECT DISTINCT username "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"AND username IS NOT NULL AND username != 'N/A' AND username != '' "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)

        seen = set()
        for row in rows:
            user = row.get("username", "")
            if user and user not in seen and user not in ("N/A", "SYSTEM", "-"):
                seen.add(user)
                result.usernames.append(user)

    def _enrich_email(self, offense_id: int, result: EnrichedIOCs):
        """Extract email senders and subjects from offense events."""
        aql = (
            f"SELECT DISTINCT \"Sender\" as sender, \"Subject\" as subject "
            f"FROM events WHERE INOFFENSE({offense_id}) "
            f"AND (\"Sender\" IS NOT NULL OR \"Subject\" IS NOT NULL) "
            f"LIMIT {self._max_results} LAST {self._time_window}"
        )
        try:
            rows = self._qradar.aql_search(aql, timeout_seconds=self._aql_timeout)
            seen_senders = set()
            seen_subjects = set()
            for row in rows:
                sender = row.get("sender", "")
                subject = row.get("subject", "")
                if sender and sender not in seen_senders and "@" in sender:
                    seen_senders.add(sender)
                    result.email_senders.append(sender)
                if subject and subject not in seen_subjects:
                    seen_subjects.add(subject)
                    result.email_subjects.append(subject)
        except QRadarAPIError:
            log.debug("Email Sender/Subject fields not available")
