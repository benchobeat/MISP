# SIEM Integration Tools for MISP

Scripts and services for integrating MISP with enterprise SIEMs.

## Scripts

### `qradar_offense_to_misp.py`
Polls QRadar for new offenses and creates MISP events with extracted IoCs.
Runs as a cron job or daemon. Tracks state to avoid duplicate processing.

```bash
# Install dependencies
pip install pymisp requests

# Configure via environment variables
export QRADAR_URL="https://qradar.example.com"
export QRADAR_TOKEN="your-token"
export MISP_URL="https://misp.example.com"
export MISP_KEY="your-api-key"

# Run once
python3 qradar_offense_to_misp.py

# Run as daemon (poll every 5 minutes)
python3 qradar_offense_to_misp.py --daemon --interval 300

# Cron job (every 5 minutes)
*/5 * * * * /usr/bin/python3 /path/to/qradar_offense_to_misp.py
```

### `qradar_custom_action.py`
Designed for QRadar Custom Actions. Triggered automatically by QRadar rules.
Receives offense parameters and creates IoCs in MISP immediately.

```bash
# Setup in QRadar:
# Admin > Custom Actions > Define Actions > Add
# Upload this script and map the parameters
```

### `generic_siem_to_misp.py`
HTTP webhook bridge that accepts alerts from any SIEM and creates MISP events.
Auto-extracts IoCs (IPs, domains, hashes, URLs, emails, CVEs) from alert payloads.

```bash
# Install dependencies
pip install pymisp flask

# Configure
export MISP_URL="https://misp.example.com"
export MISP_KEY="your-api-key"
export WEBHOOK_AUTH_TOKEN="shared-secret"  # optional

# Run
python3 generic_siem_to_misp.py --port 5000

# Endpoints:
# POST /webhook/qradar      - QRadar alerts
# POST /webhook/fortisiem    - FortiSIEM alerts
# POST /webhook/netwitness   - RSA NetWitness alerts
# POST /webhook/generic      - Any SIEM
# GET  /health               - Health check
```

## Documentation

See `docs/SIEM-Integration-Guide.md` for the full integration guide including
API reference, data model, export formats, and SIEM-specific instructions.
