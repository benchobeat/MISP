#!/usr/bin/env python3
"""
QRadar Offense -> MISP Integration Script

Polls QRadar for new offenses and automatically creates MISP events
with the associated IoCs (IPs, domains, hashes, URLs, etc.).

Usage:
    # Run once (process new offenses since last run)
    python3 qradar_offense_to_misp.py

    # Run via cron every 5 minutes
    */5 * * * * /usr/bin/python3 /path/to/qradar_offense_to_misp.py

    # Run in continuous mode (daemon)
    python3 qradar_offense_to_misp.py --daemon --interval 300

Configuration:
    Set environment variables or edit the CONFIG section below.

Requirements:
    pip install pymisp requests
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import requests
from pymisp import PyMISP, MISPEvent, MISPAttribute

# ---------------------------------------------------------------------------
# Configuration - Override via environment variables or edit directly
# ---------------------------------------------------------------------------
CONFIG = {
    "QRADAR_URL": os.environ.get("QRADAR_URL", "https://qradar.example.com"),
    "QRADAR_TOKEN": os.environ.get("QRADAR_TOKEN", "your-qradar-api-token"),
    "QRADAR_VERIFY_SSL": os.environ.get("QRADAR_VERIFY_SSL", "true").lower() == "true",
    "MISP_URL": os.environ.get("MISP_URL", "https://misp.example.com"),
    "MISP_KEY": os.environ.get("MISP_KEY", "your-misp-api-key"),
    "MISP_VERIFY_SSL": os.environ.get("MISP_VERIFY_SSL", "true").lower() == "true",
    # State file to track the last processed offense ID
    "STATE_FILE": os.environ.get("STATE_FILE", "/var/tmp/qradar_misp_last_offense_id"),
    # MISP event distribution: 0=Org, 1=Community, 2=Connected, 3=All
    "MISP_DISTRIBUTION": int(os.environ.get("MISP_DISTRIBUTION", "0")),
    # Minimum QRadar offense magnitude to process (0-10)
    "MIN_MAGNITUDE": int(os.environ.get("MIN_MAGNITUDE", "3")),
    # Tags to apply to created MISP events
    "MISP_TAGS": os.environ.get("MISP_TAGS", "qradar,automated-import,tlp:amber").split(","),
    # Whether to auto-publish MISP events (false = manual review first)
    "AUTO_PUBLISH": os.environ.get("AUTO_PUBLISH", "false").lower() == "true",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("qradar-to-misp")


# ---------------------------------------------------------------------------
# QRadar API Client
# ---------------------------------------------------------------------------
class QRadarClient:
    """Minimal QRadar REST API client."""

    def __init__(self, url, token, verify_ssl=True):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "SEC": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl

    def get_offenses(self, filter_query=None, fields=None, sort=None, range_header=None):
        """Retrieve offenses from QRadar."""
        params = {}
        if filter_query:
            params["filter"] = filter_query
        if fields:
            params["fields"] = fields
        if sort:
            params["sort"] = sort

        headers = {}
        if range_header:
            headers["Range"] = range_header

        resp = self.session.get(
            f"{self.url}/api/siem/offenses",
            params=params,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    def get_offense_addresses(self, offense_id, address_type="source"):
        """Get source or destination IPs for an offense.

        Args:
            offense_id: The offense ID.
            address_type: 'source' or 'local_destination'.
        """
        resp = self.session.get(
            f"{self.url}/api/siem/offenses/{offense_id}/{address_type}_addresses",
        )
        resp.raise_for_status()
        return resp.json()

    def get_offense_notes(self, offense_id):
        """Get notes/annotations for an offense."""
        resp = self.session.get(
            f"{self.url}/api/siem/offenses/{offense_id}/notes",
        )
        resp.raise_for_status()
        return resp.json()

    def search(self, aql_query):
        """Execute an AQL search and return results.

        This is a synchronous wrapper: starts search, waits, retrieves results.
        """
        # Start search
        resp = self.session.post(
            f"{self.url}/api/ariel/searches",
            params={"query_expression": aql_query},
        )
        resp.raise_for_status()
        search_id = resp.json()["search_id"]

        # Poll for completion
        for _ in range(60):
            resp = self.session.get(f"{self.url}/api/ariel/searches/{search_id}")
            resp.raise_for_status()
            status = resp.json().get("status")
            if status == "COMPLETED":
                break
            if status in ("FAILED", "CANCELED"):
                raise RuntimeError(f"AQL search {search_id} {status}")
            time.sleep(2)
        else:
            raise TimeoutError(f"AQL search {search_id} timed out")

        # Get results
        resp = self.session.get(f"{self.url}/api/ariel/searches/{search_id}/results")
        resp.raise_for_status()
        return resp.json()

    def lookup_ip(self, source_ip_id):
        """Resolve a source address ID to an IP string."""
        resp = self.session.get(
            f"{self.url}/api/siem/source_addresses/{source_ip_id}",
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("source_ip")

    def lookup_local_dest_ip(self, dest_ip_id):
        """Resolve a local destination address ID to an IP string."""
        resp = self.session.get(
            f"{self.url}/api/siem/local_destination_addresses/{dest_ip_id}",
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("local_destination_ip")


# ---------------------------------------------------------------------------
# Offense -> MISP Event Converter
# ---------------------------------------------------------------------------

# Map QRadar offense categories to MISP threat levels
CATEGORY_TO_THREAT_LEVEL = {
    "Command and Control": 1,       # High
    "Malware": 1,                   # High
    "Exploitation": 1,              # High
    "DDoS": 2,                      # Medium
    "Suspicious Activity": 2,       # Medium
    "Access": 2,                    # Medium
    "Authentication": 3,            # Low
    "Recon": 3,                     # Low
    "Policy Violation": 3,          # Low
}


def offense_to_misp_event(qradar, offense):
    """Convert a QRadar offense into a MISPEvent with IoC attributes.

    Args:
        qradar: QRadarClient instance.
        offense: Offense dict from QRadar API.

    Returns:
        MISPEvent ready to be submitted to MISP.
    """
    offense_id = offense["id"]
    description = offense.get("description", "No description")
    magnitude = offense.get("magnitude", 0)
    category_count = offense.get("category_count", 0)
    categories = offense.get("categories", [])
    offense_type_str = offense.get("offense_type_str", "Unknown")
    start_time = offense.get("start_time", 0)
    status = offense.get("status", "OPEN")

    # Create MISP event
    event = MISPEvent()
    event.info = f"[QRadar Offense #{offense_id}] {description[:200]}"
    event.distribution = CONFIG["MISP_DISTRIBUTION"]

    # Map threat level from offense magnitude
    if magnitude >= 8:
        event.threat_level_id = 1  # High
    elif magnitude >= 5:
        event.threat_level_id = 2  # Medium
    elif magnitude >= 3:
        event.threat_level_id = 3  # Low
    else:
        event.threat_level_id = 4  # Undefined

    # Also check category-based threat level
    for cat in categories:
        cat_level = CATEGORY_TO_THREAT_LEVEL.get(cat)
        if cat_level and cat_level < event.threat_level_id:
            event.threat_level_id = cat_level

    event.analysis = 0  # Initial

    # Set date from offense start time
    if start_time:
        event.date = datetime.fromtimestamp(start_time / 1000, tz=timezone.utc).strftime("%Y-%m-%d")

    # Add tags
    for tag in CONFIG["MISP_TAGS"]:
        event.add_tag(tag.strip())

    # Add a contextual comment attribute
    meta_comment = (
        f"QRadar Offense #{offense_id}\n"
        f"Magnitude: {magnitude}/10\n"
        f"Status: {status}\n"
        f"Type: {offense_type_str}\n"
        f"Categories: {', '.join(categories)}\n"
        f"Category count: {category_count}"
    )
    event.add_attribute(
        type="comment",
        value=meta_comment,
        category="Other",
        to_ids=False,
        comment="QRadar offense metadata",
    )

    # Extract source IPs
    source_ip_ids = offense.get("source_address_ids", [])
    for src_id in source_ip_ids:
        try:
            ip = qradar.lookup_ip(src_id)
            if ip and not _is_private_ip(ip):
                event.add_attribute(
                    type="ip-src",
                    category="Network activity",
                    value=ip,
                    to_ids=True,
                    comment=f"Source IP from QRadar offense #{offense_id}",
                )
            elif ip:
                # Private IPs are added as non-IDS (contextual, not for blocking)
                event.add_attribute(
                    type="ip-src",
                    category="Network activity",
                    value=ip,
                    to_ids=False,
                    comment=f"Internal source IP from QRadar offense #{offense_id}",
                )
        except Exception as e:
            log.warning("Failed to resolve source IP id %s: %s", src_id, e)

    # Extract destination IPs
    dest_ip_ids = offense.get("local_destination_address_ids", [])
    for dst_id in dest_ip_ids:
        try:
            ip = qradar.lookup_local_dest_ip(dst_id)
            if ip:
                event.add_attribute(
                    type="ip-dst",
                    category="Network activity",
                    value=ip,
                    to_ids=False,
                    comment=f"Local destination IP from QRadar offense #{offense_id}",
                )
        except Exception as e:
            log.warning("Failed to resolve dest IP id %s: %s", dst_id, e)

    # Extract additional IoCs via AQL if offense has associated events
    try:
        _enrich_from_aql(qradar, offense_id, event)
    except Exception as e:
        log.warning("AQL enrichment failed for offense %s: %s", offense_id, e)

    return event


def _enrich_from_aql(qradar, offense_id, event):
    """Run AQL queries to extract additional IoCs from offense events.

    Extracts domains, URLs, usernames, and other observables from the
    offense's correlated log events.
    """
    # Get unique URLs from the offense events
    aql = (
        f"SELECT DISTINCTCOUNT(URL) as url_val "
        f"FROM events WHERE INOFFENSE({offense_id}) "
        f"AND URL IS NOT NULL "
        f"LIMIT 50 LAST 24 HOURS"
    )
    try:
        results = qradar.search(aql)
        for row in results.get("events", results.get("flows", [])):
            url = row.get("url_val")
            if url and url != "N/A":
                event.add_attribute(
                    type="url",
                    category="Network activity",
                    value=url,
                    to_ids=True,
                    comment=f"URL from QRadar offense #{offense_id} events",
                )
    except Exception as e:
        log.debug("URL AQL enrichment failed: %s", e)

    # Get unique source/destination IPs with ports
    aql = (
        f"SELECT sourceip, sourceport, destinationip, destinationport "
        f"FROM events WHERE INOFFENSE({offense_id}) "
        f"GROUP BY sourceip, sourceport, destinationip, destinationport "
        f"LIMIT 100 LAST 24 HOURS"
    )
    try:
        results = qradar.search(aql)
        seen_ips = set()
        for row in results.get("events", results.get("flows", [])):
            dst_ip = row.get("destinationip")
            dst_port = row.get("destinationport")
            if dst_ip and dst_ip not in seen_ips and not _is_private_ip(dst_ip):
                seen_ips.add(dst_ip)
                if dst_port and int(dst_port) not in (0, 80, 443):
                    event.add_attribute(
                        type="ip-dst|port",
                        category="Network activity",
                        value=f"{dst_ip}|{dst_port}",
                        to_ids=True,
                        comment=f"Dest IP:Port from QRadar offense #{offense_id}",
                    )
    except Exception as e:
        log.debug("IP:Port AQL enrichment failed: %s", e)


def _is_private_ip(ip_str):
    """Check if an IP is in a private/reserved range (RFC1918, loopback, link-local)."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# State Management
# ---------------------------------------------------------------------------

def load_last_offense_id():
    """Load the last processed offense ID from state file."""
    try:
        with open(CONFIG["STATE_FILE"], "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_last_offense_id(offense_id):
    """Save the last processed offense ID to state file."""
    with open(CONFIG["STATE_FILE"], "w") as f:
        f.write(str(offense_id))


# ---------------------------------------------------------------------------
# Main Sync Logic
# ---------------------------------------------------------------------------

def sync_offenses_to_misp():
    """Poll QRadar for new offenses and create corresponding MISP events.

    Returns the number of offenses processed.
    """
    qradar = QRadarClient(
        CONFIG["QRADAR_URL"],
        CONFIG["QRADAR_TOKEN"],
        CONFIG["QRADAR_VERIFY_SSL"],
    )

    misp = PyMISP(
        CONFIG["MISP_URL"],
        CONFIG["MISP_KEY"],
        ssl=CONFIG["MISP_VERIFY_SSL"],
    )

    last_id = load_last_offense_id()
    log.info("Fetching offenses with id > %d and magnitude >= %d", last_id, CONFIG["MIN_MAGNITUDE"])

    # Query new offenses
    filter_query = f"id > {last_id} and magnitude >= {CONFIG['MIN_MAGNITUDE']}"
    fields = (
        "id,description,magnitude,categories,category_count,"
        "offense_type_str,status,source_address_ids,"
        "local_destination_address_ids,start_time"
    )

    try:
        offenses = qradar.get_offenses(
            filter_query=filter_query,
            fields=fields,
            sort="+id",
            range_header="items=0-49",
        )
    except requests.exceptions.RequestException as e:
        log.error("Failed to fetch offenses from QRadar: %s", e)
        return 0

    if not offenses:
        log.info("No new offenses found.")
        return 0

    log.info("Found %d new offense(s) to process.", len(offenses))
    processed = 0
    max_id = last_id

    for offense in offenses:
        offense_id = offense["id"]
        try:
            log.info(
                "Processing offense #%d: %s (magnitude: %s)",
                offense_id,
                offense.get("description", "")[:80],
                offense.get("magnitude"),
            )

            # Check if already imported (search by event info)
            existing = misp.search(
                controller="events",
                eventinfo=f"[QRadar Offense #{offense_id}]",
                limit=1,
                pythonify=True,
            )
            if existing:
                log.info("Offense #%d already exists in MISP, skipping.", offense_id)
                max_id = max(max_id, offense_id)
                continue

            # Convert offense to MISP event
            event = offense_to_misp_event(qradar, offense)

            # Submit to MISP
            result = misp.add_event(event, pythonify=True)

            if hasattr(result, "id") and result.id:
                log.info(
                    "Created MISP event #%s for QRadar offense #%d (%d attributes)",
                    result.id,
                    offense_id,
                    len(result.Attribute) if hasattr(result, "Attribute") else 0,
                )

                if CONFIG["AUTO_PUBLISH"]:
                    misp.publish(result.id)
                    log.info("Published MISP event #%s", result.id)

                processed += 1
            else:
                log.error("Failed to create MISP event for offense #%d: %s", offense_id, result)

        except Exception as e:
            log.error("Error processing offense #%d: %s", offense_id, e, exc_info=True)

        max_id = max(max_id, offense_id)

    # Save progress
    save_last_offense_id(max_id)
    log.info("Sync complete. Processed %d offense(s). Last ID: %d", processed, max_id)
    return processed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Sync QRadar offenses to MISP as threat intelligence events."
    )
    parser.add_argument(
        "--daemon", action="store_true",
        help="Run continuously instead of a single pass.",
    )
    parser.add_argument(
        "--interval", type=int, default=300,
        help="Polling interval in seconds for daemon mode (default: 300).",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Reset the state file and start processing from offense ID 0.",
    )
    args = parser.parse_args()

    if args.reset:
        save_last_offense_id(0)
        log.info("State reset to offense ID 0.")

    if args.daemon:
        log.info("Running in daemon mode (interval: %ds)", args.interval)
        while True:
            try:
                sync_offenses_to_misp()
            except Exception as e:
                log.error("Sync cycle failed: %s", e, exc_info=True)
            time.sleep(args.interval)
    else:
        sync_offenses_to_misp()


if __name__ == "__main__":
    main()
