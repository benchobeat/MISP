# MISP API & SIEM Integration Guide

Practical guide for Security Advisors integrating MISP with enterprise SIEMs (QRadar, RSA NetWitness, FortiSIEM, Splunk, and others).

## Table of Contents

- [1. MISP Overview for Security Teams](#1-misp-overview-for-security-teams)
- [2. Authentication](#2-authentication)
- [3. Core API Endpoints](#3-core-api-endpoints)
- [4. IoC Data Model](#4-ioc-data-model)
- [5. Export Formats for SIEMs](#5-export-formats-for-siems)
- [6. SIEM-Specific Integration](#6-siem-specific-integration)
- [7. Real-Time Integration (ZMQ/Kafka)](#7-real-time-integration-zmqkafka)
- [8. TAXII Integration](#8-taxii-integration)
- [9. Workflow Automation](#9-workflow-automation)

---

## 1. MISP Overview for Security Teams

MISP centralizes threat intelligence by storing Indicators of Compromise (IoC) as **Attributes** inside **Events**. Each Event represents an incident, campaign, or intelligence report. Attributes can be IPs, domains, hashes, URLs, email addresses, YARA rules, Snort signatures, and 150+ other types.

**Key value for SOC/SIEM teams:**

- **Enrich SIEM alerts** by querying MISP for context on observed indicators
- **Feed SIEMs** with curated threat intelligence (blocklists, detection rules)
- **Correlate** indicators automatically across events and organizations
- **Share** intelligence with trusted partners via standardized formats (STIX, TAXII)

---

## 2. Authentication

### API Key (AuthKey)

Every API call requires an authentication key sent via the `Authorization` header:

```http
Authorization: YOUR_API_KEY
Content-Type: application/json
Accept: application/json
```

### Obtaining an API Key

- **UI:** Administration > List Auth Keys > Add Authentication Key
- **API:**
  ```bash
  curl -X POST https://misp.example.com/auth_keys/add \
    -H "Authorization: ADMIN_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"AuthKey": {"user_id": 1, "comment": "SIEM integration", "read_only": false}}'
  ```

### Key Options

| Field | Description |
|-------|-------------|
| `read_only` | Restrict key to GET operations only |
| `allowed_ips` | CIDR whitelist (e.g., `["10.0.0.0/8"]`) |
| `expiration` | Auto-expiry timestamp |
| `comment` | Label for tracking purpose |

**Best practice:** Create dedicated read-only keys per SIEM integration, with IP restrictions.

---

## 3. Core API Endpoints

### 3.1 Event Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/events/add` | Create a new event |
| `GET` | `/events/view/{id}` | Retrieve an event |
| `POST` | `/events/edit/{id}` | Update an event |
| `DELETE` | `/events/delete/{id}` | Delete an event |
| `POST` | `/events/restSearch` | Search events (the main query endpoint) |
| `POST` | `/events/publish/{id}` | Publish an event |

### 3.2 Attribute (IoC) Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/attributes/add/{event_id}` | Add attribute to an event |
| `GET` | `/attributes/view/{id}` | View a single attribute |
| `POST` | `/attributes/edit/{id}` | Edit an attribute |
| `DELETE` | `/attributes/delete/{id}` | Delete an attribute |
| `POST` | `/attributes/restSearch` | Search attributes across all events |

### 3.3 Sightings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/sightings/add/{attribute_id}` | Report a sighting |
| `POST` | `/sightings/restSearch/event` | Search sightings by event |

### 3.4 Tags

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tags/attachTagToObject/{uuid}/{tag_id}` | Tag an event or attribute |
| `POST` | `/tags/search` | Search tags |

### 3.5 Feeds

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/feeds/index` | List configured feeds |
| `POST` | `/feeds/add` | Add a feed source |
| `GET` | `/feeds/fetchFromFeed/{id}` | Trigger a feed pull |

---

## 4. IoC Data Model

### Event Structure

```json
{
  "Event": {
    "info": "Campaign description",
    "threat_level_id": 2,
    "analysis": 1,
    "distribution": 1,
    "Tag": [
      {"name": "tlp:amber"},
      {"name": "misp-galaxy:mitre-attack-pattern=\"Spearphishing Attachment - T1566.001\""}
    ],
    "Attribute": [ ... ],
    "Object": [ ... ]
  }
}
```

**Fields:**

| Field | Values |
|-------|--------|
| `threat_level_id` | 1=High, 2=Medium, 3=Low, 4=Undefined |
| `analysis` | 0=Initial, 1=Ongoing, 2=Completed |
| `distribution` | 0=Your org only, 1=Community, 2=Connected communities, 3=All, 4=Sharing group |

### Attribute (IoC) Structure

```json
{
  "Attribute": {
    "type": "ip-dst",
    "category": "Network activity",
    "value": "203.0.113.50",
    "to_ids": true,
    "comment": "C2 server observed in QRadar offense #4521",
    "first_seen": "2025-01-15T00:00:00.000000+00:00",
    "last_seen": "2025-01-20T23:59:59.000000+00:00"
  }
}
```

### Common IoC Types for SIEM Integration

| Category | Types | Example |
|----------|-------|---------|
| **Network** | `ip-src`, `ip-dst`, `ip-src\|port`, `ip-dst\|port` | `192.168.1.1` |
| **Domain/DNS** | `domain`, `hostname`, `domain\|ip` | `evil.example.com` |
| **URLs** | `url`, `uri` | `https://evil.com/payload.exe` |
| **File Hashes** | `md5`, `sha1`, `sha256`, `filename\|md5` | `d41d8cd98f00b204...` |
| **Email** | `email-src`, `email-dst`, `email-subject` | `phish@evil.com` |
| **TLS/SSL** | `ja3-fingerprint-md5`, `jarm-fingerprint`, `x509-fingerprint-sha256` | |
| **Network Signatures** | `snort`, `suricata`, `zeek`, `sigma` | Full rule syntax |
| **Vulnerability** | `vulnerability` | `CVE-2024-12345` |
| **Registry** | `regkey`, `regkey\|value` | Persistence artifacts |
| **YARA** | `yara` | YARA detection rules |

### The `to_ids` Flag

This is critical for SIEM integration. When `to_ids: true`, the attribute is considered **actionable** and suitable for automated detection. Always filter on this field when feeding SIEMs.

---

## 5. Export Formats for SIEMs

MISP supports exporting via `restSearch` with the `returnFormat` parameter:

```bash
curl -X POST https://misp.example.com/attributes/restSearch \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"returnFormat": "FORMAT", "to_ids": true, "last": "1d"}'
```

### Available Formats

| Format | `returnFormat` | Best For |
|--------|---------------|----------|
| MISP JSON | `json` | General programmatic use |
| MISP XML | `xml` | Legacy integrations |
| CSV | `csv` | Universal SIEM import |
| STIX 1.x XML | `stix` | QRadar, legacy TAXII consumers |
| STIX 1.x JSON | `stix-json` | QRadar, RSA NetWitness |
| STIX 2.x | `stix2` | Modern TIP/SIEM integrations |
| Suricata | `suricata` | IDS/IPS rule generation |
| Snort | `snort` | Snort IDS rules |
| YARA | `yara` | Malware scanning rules |
| OpenIOC | `openioc` | Mandiant IOC format |
| Plain text | `text` | Simple IP/domain/hash lists |
| Hashes only | `hashes` | Hash blocklists |
| Hosts file | `hosts` | DNS sinkholing |
| RPZ | `rpz` | DNS Response Policy Zones |
| Netfilter | `netfilter` | Linux firewall rules |
| ATT&CK | `attack` | MITRE ATT&CK mapping |

### Example: Export all IPs from last 24h as plain text

```bash
curl -X POST https://misp.example.com/attributes/restSearch \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "returnFormat": "text",
    "type": ["ip-src", "ip-dst"],
    "to_ids": true,
    "last": "1d"
  }'
```

### Example: Export as STIX 2.x

```bash
curl -X POST https://misp.example.com/events/restSearch \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "returnFormat": "stix2",
    "tags": ["tlp:white", "tlp:green"],
    "last": "7d"
  }'
```

### Common restSearch Filters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `returnFormat` | Output format | `"json"`, `"csv"`, `"stix2"` |
| `type` | Attribute type(s) | `"ip-dst"` or `["ip-dst","domain"]` |
| `category` | Attribute category | `"Network activity"` |
| `value` | Specific IoC value | `"203.0.113.50"` |
| `to_ids` | Actionable indicators only | `true` |
| `tags` | Filter by tags (OR logic, `!` to exclude) | `["tlp:white", "!tlp:red"]` |
| `last` | Time window | `"1d"`, `"6h"`, `"30m"` |
| `from` / `to` | Date range | `"2025-01-01"` |
| `eventid` | Specific event(s) | `[1234, 5678]` |
| `enforceWarninglist` | Exclude known false positives | `true` |
| `includeDecayScore` | Include indicator aging score | `true` |
| `limit` / `page` | Pagination | `1000` / `1` |
| `published` | Only published events | `true` |
| `threat_level_id` | Threat level filter | `[1, 2]` (High + Medium) |

---

## 6. SIEM-Specific Integration

### 6.1 IBM QRadar

QRadar can consume MISP data via **Reference Sets** and **STIX/TAXII**.

**Option A: Feed Reference Sets via script (recommended)**

```python
#!/usr/bin/env python3
"""
MISP -> QRadar Reference Set Integration
Run via cron every 15 minutes.
"""
from pymisp import PyMISP
import requests
import json

# Configuration
MISP_URL = "https://misp.example.com"
MISP_KEY = "your-misp-api-key"
QRADAR_URL = "https://qradar.example.com"
QRADAR_TOKEN = "your-qradar-token"

# MISP connection
misp = PyMISP(MISP_URL, MISP_KEY, ssl=True)

# Map MISP types to QRadar reference sets
TYPE_TO_REFSET = {
    "ip-src": "MISP_Malicious_IPs",
    "ip-dst": "MISP_Malicious_IPs",
    "domain": "MISP_Malicious_Domains",
    "hostname": "MISP_Malicious_Domains",
    "md5": "MISP_Malicious_Hashes_MD5",
    "sha256": "MISP_Malicious_Hashes_SHA256",
    "url": "MISP_Malicious_URLs",
    "email-src": "MISP_Malicious_Emails",
}

QRADAR_HEADERS = {
    "SEC": QRADAR_TOKEN,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

def add_to_reference_set(ref_set_name, value):
    """Add a value to a QRadar reference set."""
    url = f"{QRADAR_URL}/api/reference_data/sets/{ref_set_name}"
    params = {"name": ref_set_name, "value": value}
    resp = requests.post(url, headers=QRADAR_HEADERS, params=params, verify=True)
    return resp.status_code == 200

def bulk_add_to_reference_set(ref_set_name, values):
    """Bulk add values to a QRadar reference set."""
    url = f"{QRADAR_URL}/api/reference_data/sets/bulk_load/{ref_set_name}"
    resp = requests.post(url, headers=QRADAR_HEADERS, json=values, verify=True)
    return resp.status_code == 200

def sync_misp_to_qradar(time_window="15m"):
    """Pull recent IoCs from MISP and push to QRadar reference sets."""
    for misp_type, ref_set in TYPE_TO_REFSET.items():
        results = misp.search(
            controller="attributes",
            type_attribute=misp_type,
            to_ids=True,
            last=time_window,
            enforceWarninglist=True,
            published=True,
        )

        values = []
        if "Attribute" in results:
            for attr in results["Attribute"]:
                value = attr.get("value", "")
                if value:
                    values.append(value)

        if values:
            success = bulk_add_to_reference_set(ref_set, values)
            print(f"[{'OK' if success else 'FAIL'}] {ref_set}: {len(values)} indicators")

if __name__ == "__main__":
    sync_misp_to_qradar()
```

**Option B: STIX/TAXII feed**

QRadar Threat Intelligence app supports TAXII. Configure MISP's TAXII server
(see [Section 8](#8-taxii-integration)) and add it as a TAXII source in QRadar.

---

### 6.2 RSA NetWitness

NetWitness can consume feeds as CSV or via STIX/TAXII.

**Option A: CSV feed via MISP REST API**

Configure a recurring feed in NetWitness pointing to:
```
POST https://misp.example.com/attributes/restSearch
Body: {"returnFormat": "csv", "type": ["ip-dst","domain"], "to_ids": true, "last": "1d"}
Header: Authorization: YOUR_API_KEY
```

**Option B: Script-based integration**

```python
#!/usr/bin/env python3
"""
MISP -> RSA NetWitness Feed Integration
Generates CSV files consumable by NetWitness as meta feeds.
"""
from pymisp import PyMISP
import csv
import os

MISP_URL = "https://misp.example.com"
MISP_KEY = "your-misp-api-key"
OUTPUT_DIR = "/opt/netwitness/feeds/misp"

misp = PyMISP(MISP_URL, MISP_KEY, ssl=True)

FEED_CONFIG = {
    "ip_blocklist": {
        "types": ["ip-src", "ip-dst"],
        "filename": "misp_ip_blocklist.csv",
        "nw_meta_key": "threat.source",
        "nw_meta_value": "misp-threat-intel",
    },
    "domain_blocklist": {
        "types": ["domain", "hostname"],
        "filename": "misp_domain_blocklist.csv",
        "nw_meta_key": "threat.source",
        "nw_meta_value": "misp-threat-intel",
    },
    "hash_blocklist": {
        "types": ["md5", "sha256"],
        "filename": "misp_hash_blocklist.csv",
        "nw_meta_key": "threat.source",
        "nw_meta_value": "misp-threat-intel",
    },
}

def generate_netwitness_feed(feed_name, config, time_window="1d"):
    """Generate a CSV feed file for NetWitness consumption."""
    results = misp.search(
        controller="attributes",
        type_attribute=config["types"],
        to_ids=True,
        last=time_window,
        enforceWarninglist=True,
        published=True,
        pythonify=True,
    )

    filepath = os.path.join(OUTPUT_DIR, config["filename"])
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        for attr in results:
            writer.writerow([attr.value, config["nw_meta_key"], config["nw_meta_value"]])

    print(f"[{feed_name}] Wrote {len(results)} indicators to {filepath}")

if __name__ == "__main__":
    for name, config in FEED_CONFIG.items():
        generate_netwitness_feed(name, config)
```

---

### 6.3 FortiSIEM

FortiSIEM supports external threat feeds via URL. MISP can serve as a direct feed source.

**Option A: Direct URL feed (simplest)**

In FortiSIEM, add an external threat intelligence feed pointing to MISP:

```
# IP blocklist (plain text, one per line)
POST https://misp.example.com/attributes/restSearch
Body: {"returnFormat": "text", "type": ["ip-src","ip-dst"], "to_ids": true, "last": "7d", "enforceWarninglist": true}

# Domain blocklist
POST https://misp.example.com/attributes/restSearch
Body: {"returnFormat": "text", "type": ["domain","hostname"], "to_ids": true, "last": "7d"}

# Hash blocklist
POST https://misp.example.com/attributes/restSearch
Body: {"returnFormat": "text", "type": ["md5","sha256"], "to_ids": true, "last": "7d"}
```

**Option B: File-based feed generation**

```python
#!/usr/bin/env python3
"""
MISP -> FortiSIEM Threat Feed Integration
Generates text-based blocklists for FortiSIEM external threat feed ingestion.
"""
from pymisp import PyMISP
import os

MISP_URL = "https://misp.example.com"
MISP_KEY = "your-misp-api-key"
OUTPUT_DIR = "/opt/fortisiem/feeds/misp"

misp = PyMISP(MISP_URL, MISP_KEY, ssl=True)

FEEDS = {
    "malicious_ips.txt": {"types": ["ip-src", "ip-dst"]},
    "malicious_domains.txt": {"types": ["domain", "hostname"]},
    "malicious_urls.txt": {"types": ["url"]},
    "malicious_hashes_md5.txt": {"types": ["md5"]},
    "malicious_hashes_sha256.txt": {"types": ["sha256"]},
    "malicious_emails.txt": {"types": ["email-src", "email-dst"]},
}

def generate_feeds(time_window="7d"):
    """Generate all feed files for FortiSIEM."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for filename, config in FEEDS.items():
        results = misp.search(
            controller="attributes",
            type_attribute=config["types"],
            to_ids=True,
            last=time_window,
            enforceWarninglist=True,
            published=True,
            pythonify=True,
        )

        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, "w") as f:
            for attr in results:
                f.write(f"{attr.value}\n")

        print(f"[{filename}] Wrote {len(results)} indicators")

if __name__ == "__main__":
    generate_feeds()
```

---

### 6.4 Splunk (Native Integration)

MISP includes a native Splunk HEC workflow module at
`app/Model/WorkflowModules/action/Module_splunk_hec_export.php`.

**Setup in MISP UI:**
1. Go to Administration > Workflows
2. Add trigger: "Event after publish"
3. Add action: "Splunk HEC Export"
4. Configure: HEC URL, token, source type

**Alternative: PyMISP to Splunk HEC**

```python
#!/usr/bin/env python3
"""MISP -> Splunk HEC direct integration."""
from pymisp import PyMISP
import requests
import json

MISP_URL = "https://misp.example.com"
MISP_KEY = "your-misp-api-key"
SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector/event"
SPLUNK_HEC_TOKEN = "your-hec-token"

misp = PyMISP(MISP_URL, MISP_KEY, ssl=True)

def send_to_splunk(iocs):
    """Send IoCs to Splunk HEC."""
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
    for ioc in iocs:
        event = {
            "sourcetype": "misp:ioc",
            "event": {
                "type": ioc.type,
                "category": ioc.category,
                "value": ioc.value,
                "event_id": ioc.event_id,
                "to_ids": ioc.to_ids,
                "timestamp": ioc.timestamp,
                "comment": ioc.comment,
                "uuid": ioc.uuid,
            },
        }
        requests.post(SPLUNK_HEC_URL, headers=headers, json=event, verify=True)

results = misp.search(
    controller="attributes",
    to_ids=True,
    last="15m",
    enforceWarninglist=True,
    pythonify=True,
)

send_to_splunk(results)
print(f"Sent {len(results)} IoCs to Splunk")
```

---

## 7. Real-Time Integration (ZMQ/Kafka)

MISP publishes events in real-time via ZMQ and Kafka. This is ideal for SIEMs
that need immediate notification of new threat intelligence.

### ZMQ Topics

| Topic | Content |
|-------|---------|
| `misp_json` | All changes (events, attributes, sightings) |
| `misp_json_event` | New/modified events |
| `misp_json_attribute` | New/modified attributes |
| `misp_json_sighting` | New sightings |

### ZMQ Subscriber Example

```python
#!/usr/bin/env python3
"""
Real-time MISP IoC consumer via ZMQ.
Forwards new IoCs to your SIEM immediately.
"""
import zmq
import json

ZMQ_HOST = "tcp://misp.example.com:50000"

context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect(ZMQ_HOST)
socket.setsockopt_string(zmq.SUBSCRIBE, "misp_json_attribute")

print(f"Listening for new IoCs on {ZMQ_HOST}...")

while True:
    topic = socket.recv_string()
    message = socket.recv_string()
    data = json.loads(message)

    attr = data.get("Attribute", {})
    if attr.get("to_ids"):
        ioc_type = attr.get("type")
        ioc_value = attr.get("value")
        print(f"New IoC: [{ioc_type}] {ioc_value}")
        # Forward to your SIEM API here
```

### Enable ZMQ in MISP

Administration > Server Settings > Plugin > ZMQ:
- `Plugin.ZeroMQ_enable` = true
- `Plugin.ZeroMQ_port` = 50000
- `Plugin.ZeroMQ_attribute_notifications_enable` = true
- `Plugin.ZeroMQ_event_notifications_enable` = true

---

## 8. TAXII Integration

MISP supports TAXII 2.1 for standardized threat intel sharing.

### Configure a TAXII Server in MISP

1. Go to Sync Actions > TAXII Servers > Add
2. Enter: name, URL (e.g., `https://taxii.example.com`), authentication credentials
3. Select the API root and collection
4. Push events via: Sync Actions > TAXII Servers > Push

### Push script

MISP includes `app/files/scripts/taxii/taxii_push.py` for automated TAXII push operations.

### Consuming MISP via TAXII

SIEMs that support TAXII 2.1 (QRadar TI app, RSA NetWitness, ThreatConnect) can
subscribe to MISP's TAXII collections to receive IoCs automatically.

---

## 9. Workflow Automation

MISP's workflow engine can trigger actions automatically. Key modules for SIEM integration:

| Module | Path | Purpose |
|--------|------|---------|
| Splunk HEC Export | `WorkflowModules/action/Module_splunk_hec_export.php` | Push to Splunk |
| Webhook | `WorkflowModules/action/Module_webhook.php` | POST to any REST API |
| MS Teams | `WorkflowModules/action/Module_ms_teams_webhook.php` | Alert notifications |
| Send Mail | `WorkflowModules/action/Module_send_mail.php` | Email alerts |
| ZMQ Push | `WorkflowModules/action/Module_push_zmq.php` | Real-time message bus |

### Example Workflow: Auto-push to SIEM on Event Publish

1. **Trigger:** "Event after publish"
2. **Logic:** Filter by tag (e.g., only `tlp:white` and `tlp:green`)
3. **Action:** Webhook POST to your SIEM's ingestion API

---

## Quick Reference: curl Examples

```bash
# Create an event with IoCs
curl -X POST https://misp.example.com/events/add \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "Event": {
      "info": "Phishing Campaign - 2025-01",
      "distribution": 1,
      "threat_level_id": 2,
      "analysis": 1,
      "Attribute": [
        {"type": "ip-dst", "category": "Network activity", "value": "203.0.113.50", "to_ids": true},
        {"type": "domain", "category": "Network activity", "value": "evil.example.com", "to_ids": true},
        {"type": "sha256", "category": "Payload delivery", "value": "e3b0c44298fc...", "to_ids": true}
      ]
    }
  }'

# Search for an IP across all events
curl -X POST https://misp.example.com/attributes/restSearch \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"returnFormat": "json", "value": "203.0.113.50"}'

# Get all IoCs from last 24h as CSV
curl -X POST https://misp.example.com/attributes/restSearch \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"returnFormat": "csv", "to_ids": true, "last": "1d"}'

# Export as Suricata rules
curl -X POST https://misp.example.com/events/restSearch \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"returnFormat": "suricata", "to_ids": true, "last": "7d"}'

# Report a sighting (tell MISP your SIEM observed this IoC)
curl -X POST https://misp.example.com/sightings/add \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"values": ["203.0.113.50"], "source": "QRadar"}'
```
