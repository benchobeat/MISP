"""QRadar REST API v15+ client for IBM QRadar 7.5.x.

Handles authentication, offense retrieval, address resolution, and AQL queries.
All methods include retry logic with exponential backoff for transient failures.
"""

import logging
import time
from typing import Any

import requests

log = logging.getLogger(__name__)

# QRadar API version for 7.5.x
API_VERSION = "15.0"

# Retry configuration
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds


class QRadarAPIError(Exception):
    """Raised when the QRadar API returns a non-success response."""

    def __init__(self, status_code: int, message: str, response_body: str = ""):
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(f"QRadar API error {status_code}: {message}")


class QRadarClient:
    """Client for IBM QRadar REST API v15+ (QRadar 7.5.x).

    Args:
        base_url: QRadar console URL (e.g., https://qradar.example.com).
        api_token: SEC token for authentication.
        verify_ssl: Whether to verify TLS certificates.
        timeout: Request timeout in seconds.
    """

    def __init__(self, base_url: str, api_token: str, verify_ssl: bool = True, timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.headers.update({
            "SEC": api_token,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Version": API_VERSION,
        })

    # ------------------------------------------------------------------
    # Low-level request with retry
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs) -> Any:
        """Execute an HTTP request against the QRadar API with retry logic.

        Returns the parsed JSON response body.
        Raises QRadarAPIError on non-2xx responses after all retries are exhausted.
        """
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)

        last_exception = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self._session.request(method, url, **kwargs)

                if resp.status_code == 429:
                    # Rate limited - wait and retry
                    retry_after = int(resp.headers.get("Retry-After", RETRY_BACKOFF_BASE ** (attempt + 1)))
                    log.warning("Rate limited by QRadar, waiting %ds (attempt %d/%d)", retry_after, attempt + 1, MAX_RETRIES + 1)
                    time.sleep(retry_after)
                    continue

                if resp.status_code >= 500:
                    # Server error - retry with backoff
                    wait = RETRY_BACKOFF_BASE ** (attempt + 1)
                    log.warning("QRadar server error %d, retrying in %ds (attempt %d/%d)", resp.status_code, wait, attempt + 1, MAX_RETRIES + 1)
                    time.sleep(wait)
                    continue

                if resp.status_code >= 400:
                    raise QRadarAPIError(resp.status_code, resp.reason, resp.text)

                # 2xx - success
                if resp.content:
                    return resp.json()
                return None

            except requests.exceptions.ConnectionError as exc:
                last_exception = exc
                wait = RETRY_BACKOFF_BASE ** (attempt + 1)
                log.warning("Connection error to QRadar, retrying in %ds (attempt %d/%d): %s", wait, attempt + 1, MAX_RETRIES + 1, exc)
                time.sleep(wait)

            except requests.exceptions.Timeout as exc:
                last_exception = exc
                wait = RETRY_BACKOFF_BASE ** (attempt + 1)
                log.warning("Timeout connecting to QRadar, retrying in %ds (attempt %d/%d): %s", wait, attempt + 1, MAX_RETRIES + 1, exc)
                time.sleep(wait)

        raise QRadarAPIError(0, f"All {MAX_RETRIES + 1} attempts failed", str(last_exception))

    # ------------------------------------------------------------------
    # Offense Endpoints
    # ------------------------------------------------------------------

    def get_offenses(
        self,
        filter_query: str | None = None,
        fields: str | None = None,
        sort: str | None = None,
        range_start: int = 0,
        range_end: int = 49,
    ) -> list[dict]:
        """Retrieve offenses from the SIEM.

        Args:
            filter_query: AQL-style filter (e.g., "id > 100 and magnitude >= 5").
            fields: Comma-separated field list to return.
            sort: Sort expression (e.g., "+id" for ascending by ID).
            range_start: Start index for pagination.
            range_end: End index for pagination.

        Returns:
            List of offense dicts.
        """
        params = {}
        if filter_query:
            params["filter"] = filter_query
        if fields:
            params["fields"] = fields
        if sort:
            params["sort"] = sort

        headers = {"Range": f"items={range_start}-{range_end}"}
        result = self._request("GET", "/api/siem/offenses", params=params, headers=headers)
        return result if result else []

    def get_offense(self, offense_id: int, fields: str | None = None) -> dict:
        """Retrieve a single offense by ID.

        Args:
            offense_id: The offense ID.
            fields: Comma-separated field list.

        Returns:
            Offense dict.
        """
        params = {}
        if fields:
            params["fields"] = fields
        return self._request("GET", f"/api/siem/offenses/{offense_id}", params=params)

    def get_offense_notes(self, offense_id: int) -> list[dict]:
        """Retrieve notes/annotations for an offense.

        Returns:
            List of note dicts with 'note_text', 'create_time', etc.
        """
        result = self._request("GET", f"/api/siem/offenses/{offense_id}/notes")
        return result if result else []

    # ------------------------------------------------------------------
    # Address Resolution
    # ------------------------------------------------------------------

    def get_source_address(self, source_address_id: int) -> dict:
        """Resolve a source address ID to its IP and metadata.

        Returns:
            Dict with 'source_ip', 'id', 'domain_id', etc.
        """
        return self._request("GET", f"/api/siem/source_addresses/{source_address_id}")

    def get_local_destination_address(self, dest_address_id: int) -> dict:
        """Resolve a local destination address ID to its IP and metadata.

        Returns:
            Dict with 'local_destination_ip', 'id', 'domain_id', etc.
        """
        return self._request("GET", f"/api/siem/local_destination_addresses/{dest_address_id}")

    def resolve_source_ips(self, address_ids: list[int]) -> list[str]:
        """Resolve a batch of source address IDs to IP strings.

        Skips IDs that fail to resolve (logs a warning).

        Returns:
            List of IP address strings.
        """
        ips = []
        for addr_id in address_ids:
            try:
                data = self.get_source_address(addr_id)
                ip = data.get("source_ip")
                if ip:
                    ips.append(ip)
            except QRadarAPIError as exc:
                log.warning("Failed to resolve source address ID %d: %s", addr_id, exc)
        return ips

    def resolve_destination_ips(self, address_ids: list[int]) -> list[str]:
        """Resolve a batch of local destination address IDs to IP strings.

        Returns:
            List of IP address strings.
        """
        ips = []
        for addr_id in address_ids:
            try:
                data = self.get_local_destination_address(addr_id)
                ip = data.get("local_destination_ip")
                if ip:
                    ips.append(ip)
            except QRadarAPIError as exc:
                log.warning("Failed to resolve dest address ID %d: %s", addr_id, exc)
        return ips

    # ------------------------------------------------------------------
    # AQL Search
    # ------------------------------------------------------------------

    def aql_search(self, query: str, timeout_seconds: int = 120) -> list[dict]:
        """Execute an AQL query and wait for results.

        This is a synchronous method: it submits the search, polls for completion,
        and returns the result rows.

        Args:
            query: The AQL query string.
            timeout_seconds: Maximum time to wait for query completion.

        Returns:
            List of result row dicts.

        Raises:
            QRadarAPIError: If the search fails or times out.
        """
        # Start the search
        log.debug("Executing AQL: %s", query[:200])
        search_data = self._request("POST", "/api/ariel/searches", params={"query_expression": query})
        search_id = search_data["search_id"]

        # Poll for completion
        deadline = time.time() + timeout_seconds
        poll_interval = 2

        while time.time() < deadline:
            status_data = self._request("GET", f"/api/ariel/searches/{search_id}")
            status = status_data.get("status")

            if status == "COMPLETED":
                break
            if status in ("FAILED", "CANCELED"):
                raise QRadarAPIError(0, f"AQL search {search_id} {status}: {status_data.get('error_messages', '')}")

            time.sleep(poll_interval)
            # Gradually increase poll interval (max 10s)
            poll_interval = min(poll_interval * 1.5, 10)
        else:
            # Timeout - attempt to cancel the search
            try:
                self._request("POST", f"/api/ariel/searches/{search_id}", params={"status": "CANCELED"})
            except QRadarAPIError:
                pass
            raise QRadarAPIError(0, f"AQL search {search_id} timed out after {timeout_seconds}s")

        # Fetch results
        results = self._request("GET", f"/api/ariel/searches/{search_id}/results")
        rows = results.get("events", results.get("flows", []))
        log.debug("AQL search %s returned %d rows", search_id, len(rows))
        return rows

    # ------------------------------------------------------------------
    # Reference Data (for sighting feedback)
    # ------------------------------------------------------------------

    def get_reference_sets(self) -> list[dict]:
        """List all reference sets.

        Returns:
            List of reference set metadata dicts.
        """
        result = self._request("GET", "/api/reference_data/sets")
        return result if result else []

    def create_reference_set(self, name: str, element_type: str = "ALN") -> dict:
        """Create a new reference set.

        Args:
            name: Reference set name.
            element_type: Type of elements (ALN=string, NUM=number, IP=IP, PORT=port).

        Returns:
            Created reference set metadata.
        """
        params = {"name": name, "element_type": element_type}
        return self._request("POST", "/api/reference_data/sets", params=params)

    def add_to_reference_set(self, name: str, value: str) -> dict:
        """Add a single value to a reference set.

        Args:
            name: Reference set name.
            value: Value to add.

        Returns:
            Updated reference set metadata.
        """
        params = {"name": name, "value": value}
        return self._request("POST", f"/api/reference_data/sets/{name}", params=params)

    def bulk_add_to_reference_set(self, name: str, values: list[str]) -> dict:
        """Bulk-add values to a reference set.

        Args:
            name: Reference set name.
            values: List of values to add.

        Returns:
            Updated reference set metadata.
        """
        return self._request("POST", f"/api/reference_data/sets/bulk_load/{name}", json=values)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def test_connection(self) -> dict:
        """Test the connection to QRadar by fetching the server version.

        Returns:
            Server info dict.

        Raises:
            QRadarAPIError if connection fails.
        """
        return self._request("GET", "/api/system/about")
