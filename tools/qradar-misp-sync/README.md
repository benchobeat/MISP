# QRadar -> MISP Bidirectional Sync

Daemon service that synchronizes IBM QRadar 7.5.x offenses with MISP threat intelligence platform.

## Features

- **Offense polling**: Automatically imports QRadar offenses as MISP events
- **AQL enrichment**: Extracts IPs, domains, URLs, hashes, and usernames from offense log events
- **Sighting feedback**: Reports sightings back to MISP when QRadar detects known IoCs
- **State management**: Tracks processed offenses to avoid duplicates across restarts
- **Systemd integration**: Runs as a production-ready Linux daemon

## Quick Start

```bash
# Install
pip install -e .

# Copy and edit configuration
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml with your QRadar and MISP details

# Run once (test mode)
qradar-misp-sync --config config/config.yaml --once

# Run as daemon
qradar-misp-sync --config config/config.yaml
```

## Systemd Deployment

```bash
# Install the service
sudo cp systemd/qradar-misp-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable qradar-misp-sync
sudo systemctl start qradar-misp-sync

# Check status
sudo systemctl status qradar-misp-sync
sudo journalctl -u qradar-misp-sync -f
```

## Configuration

See `config/config.example.yaml` for all options with documentation.

## Architecture

```
┌─────────────┐     poll offenses      ┌──────────────────┐
│   QRadar    │◄────────────────────────│                  │
│   7.5.x     │     AQL enrichment     │  qradar-misp-    │
│             │◄────────────────────────│  sync daemon     │
└─────────────┘                        │                  │
                                       │  (this service)  │
┌─────────────┐     create events      │                  │
│    MISP     │◄────────────────────────│                  │
│  Platform   │     report sightings   │                  │
│             │◄────────────────────────│                  │
└─────────────┘                        └──────────────────┘
```
