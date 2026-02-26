#!/usr/bin/env python3
"""
QRadar Custom Action Script for MISP Integration

This script is designed to be used as a QRadar Custom Action, which means
it is triggered AUTOMATICALLY when a QRadar rule fires.

Setup in QRadar:
1. Admin > Custom Actions > Define Actions > Add
2. Script: Upload this file
3. Parameters: Configure the parameters below
4. Then attach this action to your offense/event rules

When QRadar triggers this script, it receives offense data as parameters
and immediately creates an IoC in MISP.

Requirements:
    pip install pymisp requests
"""

import json
import logging
import os
import sys

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("qradar-custom-action")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MISP_URL = os.environ.get("MISP_URL", "https://misp.example.com")
MISP_KEY = os.environ.get("MISP_KEY", "your-misp-api-key")
MISP_VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "true").lower() == "true"

# The MISP event ID to add IoCs to (a "collector" event).
# If set, all IoCs go into this single event.
# If empty, a new event is created per offense.
COLLECTOR_EVENT_ID = os.environ.get("MISP_COLLECTOR_EVENT_ID", "")

MISP_HEADERS = {
    "Authorization": MISP_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def add_attribute_to_event(event_id, attr_type, value, category, comment=""):
    """Add a single IoC attribute to an existing MISP event."""
    url = f"{MISP_URL}/attributes/add/{event_id}"
    payload = {
        "Attribute": {
            "type": attr_type,
            "category": category,
            "value": value,
            "to_ids": True,
            "comment": comment,
        }
    }
    resp = requests.post(url, headers=MISP_HEADERS, json=payload, verify=MISP_VERIFY_SSL)
    return resp.status_code in (200, 201), resp.text


def create_event_with_attribute(info, attr_type, value, category, comment=""):
    """Create a new MISP event with a single IoC."""
    url = f"{MISP_URL}/events/add"
    payload = {
        "Event": {
            "info": info,
            "distribution": 0,
            "threat_level_id": 2,
            "analysis": 0,
            "Tag": [
                {"name": "qradar"},
                {"name": "automated-import"},
                {"name": "tlp:amber"},
            ],
            "Attribute": [
                {
                    "type": attr_type,
                    "category": category,
                    "value": value,
                    "to_ids": True,
                    "comment": comment,
                }
            ],
        }
    }
    resp = requests.post(url, headers=MISP_HEADERS, json=payload, verify=MISP_VERIFY_SSL)
    return resp.status_code in (200, 201), resp.text


def detect_ioc_type(value):
    """Auto-detect the IoC type from the value.

    Returns (misp_type, misp_category).
    """
    import re

    value = value.strip()

    # URL
    if value.startswith(("http://", "https://", "ftp://")):
        return "url", "Network activity"

    # Email
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return "email-src", "Network activity"

    # IPv4 or IPv4/CIDR
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", value):
        return "ip-src", "Network activity"

    # SHA256
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "sha256", "Payload delivery"

    # SHA1
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "sha1", "Payload delivery"

    # MD5
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "md5", "Payload delivery"

    # Domain (simple heuristic)
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", value):
        return "domain", "Network activity"

    # Fallback
    return "text", "Other"


def main():
    """Entry point for QRadar Custom Action.

    QRadar passes parameters as command-line arguments or environment variables.
    The exact format depends on your Custom Action configuration.

    Common parameter mappings:
        $1 or OFFENSE_ID     - The QRadar offense ID
        $2 or SOURCE_IP      - Source IP of the offense
        $3 or OFFENSE_DESC   - Offense description
        $4 or MAGNITUDE      - Offense magnitude
    """
    # Parse arguments - adapt based on your QRadar Custom Action config
    if len(sys.argv) < 3:
        # Try environment variables as fallback
        offense_id = os.environ.get("OFFENSE_ID", "unknown")
        source_ip = os.environ.get("SOURCE_IP", "")
        offense_desc = os.environ.get("OFFENSE_DESC", "QRadar Alert")
        magnitude = os.environ.get("MAGNITUDE", "5")
    else:
        offense_id = sys.argv[1] if len(sys.argv) > 1 else "unknown"
        source_ip = sys.argv[2] if len(sys.argv) > 2 else ""
        offense_desc = sys.argv[3] if len(sys.argv) > 3 else "QRadar Alert"
        magnitude = sys.argv[4] if len(sys.argv) > 4 else "5"

    if not source_ip:
        log.error("No source IP provided. Nothing to submit to MISP.")
        sys.exit(1)

    # Detect the IoC type
    ioc_type, ioc_category = detect_ioc_type(source_ip)
    comment = f"QRadar Offense #{offense_id} (magnitude: {magnitude}): {offense_desc[:200]}"

    log.info(
        "Submitting IoC to MISP: type=%s, value=%s, offense=#%s",
        ioc_type, source_ip, offense_id,
    )

    if COLLECTOR_EVENT_ID:
        # Add to existing collector event
        success, response = add_attribute_to_event(
            COLLECTOR_EVENT_ID, ioc_type, source_ip, ioc_category, comment
        )
    else:
        # Create a new event per offense
        info = f"[QRadar #{offense_id}] {offense_desc[:200]}"
        success, response = create_event_with_attribute(
            info, ioc_type, source_ip, ioc_category, comment
        )

    if success:
        log.info("Successfully submitted IoC to MISP.")
    else:
        log.error("Failed to submit IoC to MISP: %s", response)
        sys.exit(1)


if __name__ == "__main__":
    main()
