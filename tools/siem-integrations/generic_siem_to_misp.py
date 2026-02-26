#!/usr/bin/env python3
"""
Generic SIEM Alert -> MISP Integration Service

A lightweight HTTP server that receives webhook/syslog alerts from ANY SIEM
(QRadar, FortiSIEM, RSA NetWitness, Splunk, etc.) and creates IoCs in MISP.

This acts as a bridge: your SIEM sends alerts via webhook -> this service
parses the alert and creates the corresponding event/attribute in MISP.

Usage:
    python3 generic_siem_to_misp.py --port 5000

    Then configure your SIEM to send webhooks to:
    POST http://this-server:5000/webhook/qradar
    POST http://this-server:5000/webhook/fortisiem
    POST http://this-server:5000/webhook/netwitness
    POST http://this-server:5000/webhook/generic

Requirements:
    pip install pymisp flask
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from pymisp import PyMISP, MISPEvent

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MISP_URL = os.environ.get("MISP_URL", "https://misp.example.com")
MISP_KEY = os.environ.get("MISP_KEY", "your-misp-api-key")
MISP_VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "true").lower() == "true"
MISP_DISTRIBUTION = int(os.environ.get("MISP_DISTRIBUTION", "0"))
WEBHOOK_AUTH_TOKEN = os.environ.get("WEBHOOK_AUTH_TOKEN", "")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("siem-to-misp")

app = Flask(__name__)


def get_misp():
    """Get a PyMISP client instance."""
    return PyMISP(MISP_URL, MISP_KEY, ssl=MISP_VERIFY_SSL)


# ---------------------------------------------------------------------------
# IoC Extraction Utilities
# ---------------------------------------------------------------------------

# Precompiled patterns for IoC extraction
IOC_PATTERNS = {
    "ip": re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
    "domain": re.compile(
        r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|gq|"
        r"cc|pw|club|online|site|work|live|buzz|icu|space))\b",
        re.IGNORECASE,
    ),
    "url": re.compile(r"(https?://[^\s\"'<>]+)", re.IGNORECASE),
    "md5": re.compile(r"\b([a-fA-F0-9]{32})\b"),
    "sha1": re.compile(r"\b([a-fA-F0-9]{40})\b"),
    "sha256": re.compile(r"\b([a-fA-F0-9]{64})\b"),
    "email": re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"),
    "cve": re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE),
}


def is_public_ip(ip_str):
    """Check if an IP address is public (not private/reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def extract_iocs(text):
    """Extract all IoCs from a text string.

    Returns a list of (type, category, value) tuples.
    """
    iocs = []
    seen = set()

    # Extract SHA256 first (to avoid substring matches with MD5/SHA1)
    for match in IOC_PATTERNS["sha256"].finditer(text):
        val = match.group(1).lower()
        if val not in seen:
            seen.add(val)
            iocs.append(("sha256", "Payload delivery", val))

    # SHA1 (exclude if already part of a SHA256)
    for match in IOC_PATTERNS["sha1"].finditer(text):
        val = match.group(1).lower()
        if val not in seen and not any(val in s for s in seen):
            seen.add(val)
            iocs.append(("sha1", "Payload delivery", val))

    # MD5 (exclude if already part of SHA1/SHA256)
    for match in IOC_PATTERNS["md5"].finditer(text):
        val = match.group(1).lower()
        if val not in seen and not any(val in s for s in seen):
            seen.add(val)
            iocs.append(("md5", "Payload delivery", val))

    # URLs
    for match in IOC_PATTERNS["url"].finditer(text):
        val = match.group(1)
        if val not in seen:
            seen.add(val)
            iocs.append(("url", "Network activity", val))

    # IPs
    for match in IOC_PATTERNS["ip"].finditer(text):
        val = match.group(1)
        if val not in seen:
            seen.add(val)
            if is_public_ip(val):
                iocs.append(("ip-src", "Network activity", val))

    # Domains
    for match in IOC_PATTERNS["domain"].finditer(text):
        val = match.group(1).lower()
        if val not in seen:
            seen.add(val)
            iocs.append(("domain", "Network activity", val))

    # Emails
    for match in IOC_PATTERNS["email"].finditer(text):
        val = match.group(1).lower()
        if val not in seen:
            seen.add(val)
            iocs.append(("email-src", "Network activity", val))

    # CVEs
    for match in IOC_PATTERNS["cve"].finditer(text):
        val = match.group(1).upper()
        if val not in seen:
            seen.add(val)
            iocs.append(("vulnerability", "External analysis", val))

    return iocs


def create_misp_event_from_alert(alert_info, source_tag, iocs, threat_level=2):
    """Create a MISP event from parsed alert data.

    Args:
        alert_info: Description string for the event.
        source_tag: Tag identifying the SIEM source.
        iocs: List of (type, category, value) tuples.
        threat_level: 1=High, 2=Medium, 3=Low, 4=Undefined.

    Returns:
        Created MISPEvent or error dict.
    """
    if not iocs:
        return {"error": "No IoCs extracted from alert"}

    misp = get_misp()

    event = MISPEvent()
    event.info = alert_info[:500]
    event.distribution = MISP_DISTRIBUTION
    event.threat_level_id = threat_level
    event.analysis = 0  # Initial

    event.add_tag(source_tag)
    event.add_tag("automated-import")
    event.add_tag("tlp:amber")

    for ioc_type, ioc_category, ioc_value in iocs:
        event.add_attribute(
            type=ioc_type,
            category=ioc_category,
            value=ioc_value,
            to_ids=(ioc_type not in ("comment", "text", "vulnerability")),
            comment=f"Auto-extracted from {source_tag} alert",
        )

    result = misp.add_event(event, pythonify=True)

    if hasattr(result, "id"):
        return {
            "success": True,
            "event_id": result.id,
            "event_uuid": result.uuid,
            "attributes_count": len(result.Attribute) if hasattr(result, "Attribute") else 0,
            "misp_url": f"{MISP_URL}/events/view/{result.id}",
        }
    return {"error": str(result)}


# ---------------------------------------------------------------------------
# Authentication middleware
# ---------------------------------------------------------------------------

def check_auth():
    """Validate webhook authentication token if configured."""
    if not WEBHOOK_AUTH_TOKEN:
        return True
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    return token == WEBHOOK_AUTH_TOKEN


# ---------------------------------------------------------------------------
# Webhook Endpoints
# ---------------------------------------------------------------------------

@app.route("/webhook/qradar", methods=["POST"])
def webhook_qradar():
    """Handle QRadar webhook alerts.

    Expected JSON payload:
    {
        "offense_id": 12345,
        "description": "Offense description",
        "magnitude": 7,
        "source_ip": "203.0.113.50",
        "destination_ip": "10.0.0.5",
        "categories": ["Malware"]
    }
    """
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    offense_id = data.get("offense_id", "unknown")
    description = data.get("description", "QRadar Alert")
    magnitude = int(data.get("magnitude", 5))

    # Determine threat level from magnitude
    if magnitude >= 8:
        threat_level = 1
    elif magnitude >= 5:
        threat_level = 2
    else:
        threat_level = 3

    # Collect IoCs from structured fields
    iocs = []
    if data.get("source_ip") and is_public_ip(data["source_ip"]):
        iocs.append(("ip-src", "Network activity", data["source_ip"]))
    if data.get("destination_ip"):
        iocs.append(("ip-dst", "Network activity", data["destination_ip"]))

    # Also extract IoCs from the description text
    text_iocs = extract_iocs(description + " " + json.dumps(data))
    seen = {v for _, _, v in iocs}
    for ioc in text_iocs:
        if ioc[2] not in seen:
            iocs.append(ioc)
            seen.add(ioc[2])

    alert_info = f"[QRadar #{offense_id}] {description[:300]}"
    result = create_misp_event_from_alert(alert_info, "qradar", iocs, threat_level)
    status_code = 201 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/webhook/fortisiem", methods=["POST"])
def webhook_fortisiem():
    """Handle FortiSIEM webhook alerts.

    Expected JSON payload:
    {
        "incidentId": "INC-123",
        "incidentTitle": "Alert title",
        "severity": 8,
        "sourceIp": "203.0.113.50",
        "destIp": "10.0.0.5",
        "rawMessage": "Full alert text..."
    }
    """
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    incident_id = data.get("incidentId", "unknown")
    title = data.get("incidentTitle", "FortiSIEM Alert")
    severity = int(data.get("severity", 5))

    if severity >= 8:
        threat_level = 1
    elif severity >= 5:
        threat_level = 2
    else:
        threat_level = 3

    iocs = []
    if data.get("sourceIp") and is_public_ip(data["sourceIp"]):
        iocs.append(("ip-src", "Network activity", data["sourceIp"]))
    if data.get("destIp"):
        iocs.append(("ip-dst", "Network activity", data["destIp"]))

    # Extract from raw message
    raw = data.get("rawMessage", "")
    text_iocs = extract_iocs(title + " " + raw + " " + json.dumps(data))
    seen = {v for _, _, v in iocs}
    for ioc in text_iocs:
        if ioc[2] not in seen:
            iocs.append(ioc)
            seen.add(ioc[2])

    alert_info = f"[FortiSIEM #{incident_id}] {title[:300]}"
    result = create_misp_event_from_alert(alert_info, "fortisiem", iocs, threat_level)
    status_code = 201 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/webhook/netwitness", methods=["POST"])
def webhook_netwitness():
    """Handle RSA NetWitness webhook alerts.

    Expected JSON payload:
    {
        "alertId": "ALERT-456",
        "name": "Alert name",
        "severity": 80,
        "source": {"ip": "203.0.113.50", "port": 4444},
        "destination": {"ip": "10.0.0.5", "port": 443},
        "indicators": ["hash1", "domain.evil.com"]
    }
    """
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    alert_id = data.get("alertId", "unknown")
    name = data.get("name", "NetWitness Alert")
    severity = int(data.get("severity", 50))

    if severity >= 80:
        threat_level = 1
    elif severity >= 50:
        threat_level = 2
    else:
        threat_level = 3

    iocs = []
    source = data.get("source", {})
    dest = data.get("destination", {})

    if source.get("ip") and is_public_ip(source["ip"]):
        if source.get("port"):
            iocs.append(("ip-src|port", "Network activity", f"{source['ip']}|{source['port']}"))
        else:
            iocs.append(("ip-src", "Network activity", source["ip"]))

    if dest.get("ip"):
        if dest.get("port"):
            iocs.append(("ip-dst|port", "Network activity", f"{dest['ip']}|{dest['port']}"))
        else:
            iocs.append(("ip-dst", "Network activity", dest["ip"]))

    # Process explicit indicators
    for indicator in data.get("indicators", []):
        detected = extract_iocs(str(indicator))
        for ioc in detected:
            iocs.append(ioc)

    # Also scan the full payload
    text_iocs = extract_iocs(json.dumps(data))
    seen = {v for _, _, v in iocs}
    for ioc in text_iocs:
        if ioc[2] not in seen:
            iocs.append(ioc)
            seen.add(ioc[2])

    alert_info = f"[NetWitness #{alert_id}] {name[:300]}"
    result = create_misp_event_from_alert(alert_info, "rsa-netwitness", iocs, threat_level)
    status_code = 201 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/webhook/generic", methods=["POST"])
def webhook_generic():
    """Handle alerts from any SIEM.

    Accepts any JSON payload. Extracts IoCs automatically from all fields.

    Minimal expected payload:
    {
        "alert_id": "ID-123",
        "description": "Alert description with IPs, domains, hashes...",
        "severity": "high"
    }
    """
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    alert_id = data.get("alert_id", data.get("id", "unknown"))
    description = data.get("description", data.get("message", data.get("name", "SIEM Alert")))
    source = data.get("source", data.get("siem", "generic-siem"))

    severity = str(data.get("severity", data.get("priority", "medium"))).lower()
    if severity in ("high", "critical", "1", "2"):
        threat_level = 1
    elif severity in ("medium", "3", "4", "5"):
        threat_level = 2
    else:
        threat_level = 3

    # Extract all IoCs from the entire payload
    full_text = json.dumps(data, default=str)
    iocs = extract_iocs(full_text)

    alert_info = f"[{source} #{alert_id}] {description[:300]}"
    result = create_misp_event_from_alert(alert_info, str(source), iocs, threat_level)
    status_code = 201 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "misp_url": MISP_URL})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generic SIEM-to-MISP webhook bridge."
    )
    parser.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Listen port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    log.info("Starting SIEM-to-MISP webhook bridge on %s:%d", args.host, args.port)
    log.info("MISP URL: %s", MISP_URL)
    log.info("Endpoints:")
    log.info("  POST /webhook/qradar")
    log.info("  POST /webhook/fortisiem")
    log.info("  POST /webhook/netwitness")
    log.info("  POST /webhook/generic")
    log.info("  GET  /health")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
