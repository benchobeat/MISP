"""Converts QRadar offenses into MISP events with enriched IoC attributes.

Handles:
- Mapping offense metadata to MISP event fields
- Converting enriched IoCs to properly typed MISP attributes
- IP classification (public vs private) to set to_ids appropriately
- Threat level mapping from offense magnitude/category
"""

import ipaddress
import logging
from datetime import datetime, timezone

from pymisp import MISPEvent

from .enrichment import EnrichedIOCs
from .misp_client import MISPClient

log = logging.getLogger(__name__)

# Map QRadar offense categories to MISP threat levels
CATEGORY_THREAT_MAP = {
    "Command and Control": 1,
    "Malware": 1,
    "Exploitation": 1,
    "Botnet": 1,
    "DDoS": 2,
    "Suspicious Activity": 2,
    "Access": 2,
    "Anomaly": 2,
    "Authentication": 3,
    "Recon": 3,
    "Policy Violation": 3,
    "Audit": 3,
    "SIM Audit": 4,
}


def is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is a public (non-private, non-reserved) address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


def magnitude_to_threat_level(magnitude: int) -> int:
    """Map QRadar offense magnitude (0-10) to MISP threat level (1-4)."""
    if magnitude >= 8:
        return 1  # High
    if magnitude >= 5:
        return 2  # Medium
    if magnitude >= 3:
        return 3  # Low
    return 4  # Undefined


class OffenseConverter:
    """Converts a QRadar offense + enriched IoCs into a MISP event.

    Args:
        misp: MISP client for building events.
        extra_tags: Additional tags to apply beyond defaults.
    """

    def __init__(self, misp: MISPClient, extra_tags: list[str] | None = None):
        self._misp = misp
        self._extra_tags = extra_tags or []

    def convert(self, offense: dict, enriched: EnrichedIOCs | None = None) -> MISPEvent:
        """Convert a QRadar offense to a MISPEvent.

        Args:
            offense: Raw offense dict from QRadar API.
            enriched: Optional AQL-enriched IoCs.

        Returns:
            MISPEvent ready to submit.
        """
        offense_id = offense["id"]
        description = offense.get("description", "No description")
        magnitude = offense.get("magnitude", 0)
        categories = offense.get("categories", [])
        offense_type_str = offense.get("offense_type_str", "Unknown")
        status = offense.get("status", "OPEN")
        start_time = offense.get("start_time", 0)

        # Determine threat level
        threat_level = magnitude_to_threat_level(magnitude)
        for cat in categories:
            cat_level = CATEGORY_THREAT_MAP.get(cat)
            if cat_level and cat_level < threat_level:
                threat_level = cat_level

        # Build event info string
        info = f"[QRadar #{offense_id}] {description[:400]}"

        # Build tags
        tags = list(self._extra_tags)
        tags.append(f"qradar:offense-id={offense_id}")
        tags.append(f"qradar:magnitude={magnitude}")
        for cat in categories:
            tags.append(f"qradar:category={cat}")

        # Determine event date
        event_date = None
        if start_time:
            event_date = datetime.fromtimestamp(start_time / 1000, tz=timezone.utc).strftime("%Y-%m-%d")

        # Create event
        event = self._misp.build_event(
            info=info,
            threat_level_id=threat_level,
            analysis=0,  # Initial
            tags=tags,
            date=event_date,
        )

        # Add offense metadata as a comment attribute
        meta_lines = [
            f"QRadar Offense #{offense_id}",
            f"Magnitude: {magnitude}/10",
            f"Status: {status}",
            f"Type: {offense_type_str}",
            f"Categories: {', '.join(categories)}",
        ]
        if start_time:
            dt = datetime.fromtimestamp(start_time / 1000, tz=timezone.utc)
            meta_lines.append(f"Start time: {dt.isoformat()}")

        event.add_attribute(
            type="comment",
            value="\n".join(meta_lines),
            category="Other",
            to_ids=False,
            comment="QRadar offense metadata",
        )

        # Add IoCs from offense metadata (source/destination address IDs are
        # resolved by the poller before calling this method)
        source_ips = offense.get("_resolved_source_ips", [])
        dest_ips = offense.get("_resolved_dest_ips", [])

        seen_values = set()

        for ip in source_ips:
            if ip not in seen_values:
                seen_values.add(ip)
                event.add_attribute(
                    type="ip-src",
                    category="Network activity",
                    value=ip,
                    to_ids=is_public_ip(ip),
                    comment=f"Source IP from offense #{offense_id}" + ("" if is_public_ip(ip) else " (internal)"),
                )

        for ip in dest_ips:
            if ip not in seen_values:
                seen_values.add(ip)
                event.add_attribute(
                    type="ip-dst",
                    category="Network activity",
                    value=ip,
                    to_ids=is_public_ip(ip),
                    comment=f"Destination IP from offense #{offense_id}" + ("" if is_public_ip(ip) else " (internal)"),
                )

        # Add enriched IoCs if available
        if enriched:
            self._add_enriched_iocs(event, offense_id, enriched, seen_values)

        return event

    def _add_enriched_iocs(self, event: MISPEvent, offense_id: int, enriched: EnrichedIOCs, seen: set):
        """Add AQL-enriched IoCs to the event."""
        comment_prefix = f"AQL enrichment from offense #{offense_id}"

        # Additional IPs from AQL (beyond what offense metadata had)
        for ip in enriched.source_ips:
            if ip not in seen:
                seen.add(ip)
                event.add_attribute(
                    type="ip-src",
                    category="Network activity",
                    value=ip,
                    to_ids=is_public_ip(ip),
                    comment=comment_prefix,
                )

        for ip in enriched.dest_ips:
            if ip not in seen:
                seen.add(ip)
                event.add_attribute(
                    type="ip-dst",
                    category="Network activity",
                    value=ip,
                    to_ids=is_public_ip(ip),
                    comment=comment_prefix,
                )

        # IP:port pairs (only for public IPs and non-standard ports)
        for ip, port, direction in enriched.ip_port_pairs:
            attr_type = f"ip-{'src' if direction == 'src' else 'dst'}|port"
            compound = f"{ip}|{port}"
            if compound not in seen and is_public_ip(ip) and port not in (80, 443, 53, 0):
                seen.add(compound)
                event.add_attribute(
                    type=attr_type,
                    category="Network activity",
                    value=compound,
                    to_ids=True,
                    comment=comment_prefix,
                )

        # URLs
        for url in enriched.urls:
            if url not in seen:
                seen.add(url)
                event.add_attribute(
                    type="url",
                    category="Network activity",
                    value=url,
                    to_ids=True,
                    comment=comment_prefix,
                )

        # Domains
        for domain in enriched.domains:
            if domain not in seen:
                seen.add(domain)
                event.add_attribute(
                    type="domain",
                    category="Network activity",
                    value=domain,
                    to_ids=True,
                    comment=comment_prefix,
                )

        # File hashes
        for h in enriched.file_hashes_sha256:
            if h not in seen:
                seen.add(h)
                event.add_attribute(
                    type="sha256",
                    category="Payload delivery",
                    value=h,
                    to_ids=True,
                    comment=comment_prefix,
                )

        for h in enriched.file_hashes_sha1:
            if h not in seen:
                seen.add(h)
                event.add_attribute(
                    type="sha1",
                    category="Payload delivery",
                    value=h,
                    to_ids=True,
                    comment=comment_prefix,
                )

        for h in enriched.file_hashes_md5:
            if h not in seen:
                seen.add(h)
                event.add_attribute(
                    type="md5",
                    category="Payload delivery",
                    value=h,
                    to_ids=True,
                    comment=comment_prefix,
                )

        # Filenames (contextual, not for IDS)
        for fname in enriched.filenames:
            if fname not in seen:
                seen.add(fname)
                event.add_attribute(
                    type="filename",
                    category="Payload delivery",
                    value=fname,
                    to_ids=False,
                    comment=comment_prefix,
                )

        # Usernames (contextual)
        for user in enriched.usernames:
            if user not in seen:
                seen.add(user)
                event.add_attribute(
                    type="target-user",
                    category="Targeting data",
                    value=user,
                    to_ids=False,
                    comment=comment_prefix,
                )

        # Email senders
        for email in enriched.email_senders:
            if email not in seen:
                seen.add(email)
                event.add_attribute(
                    type="email-src",
                    category="Payload delivery",
                    value=email,
                    to_ids=True,
                    comment=comment_prefix,
                )

        # Email subjects (contextual)
        for subject in enriched.email_subjects:
            if subject not in seen:
                seen.add(subject)
                event.add_attribute(
                    type="email-subject",
                    category="Payload delivery",
                    value=subject,
                    to_ids=False,
                    comment=comment_prefix,
                )
