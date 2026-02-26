"""Command-line interface for qradar-misp-sync."""

import argparse
import logging
import logging.handlers
import sys

from .config import load_config
from .daemon import SyncDaemon


def setup_logging(level: str, log_file: str = "", max_bytes: int = 10_485_760, backup_count: int = 5):
    """Configure logging for the application."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Always log to stdout (for systemd journal)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(fmt)
    root.addHandler(stdout_handler)

    # Optionally log to a rotating file
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count,
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)


def main():
    parser = argparse.ArgumentParser(
        prog="qradar-misp-sync",
        description="Bidirectional sync between IBM QRadar 7.5.x and MISP.",
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        help="Path to YAML configuration file.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single poll cycle and exit (useful for testing/cron).",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test connections to QRadar and MISP, then exit.",
    )
    parser.add_argument(
        "--reset-state",
        action="store_true",
        help="Reset the state file (reprocess all offenses from ID 0).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    args = parser.parse_args()

    # Load config
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Setup logging
    log_level = "DEBUG" if args.verbose else config.logging.level
    setup_logging(
        level=log_level,
        log_file=config.logging.file,
        max_bytes=config.logging.max_bytes,
        backup_count=config.logging.backup_count,
    )

    log = logging.getLogger(__name__)

    # Create daemon
    daemon = SyncDaemon(config)

    if args.reset_state:
        from .state import StateManager
        state = StateManager(config.state_file)
        state.reset()
        log.info("State reset complete")
        sys.exit(0)

    if args.test:
        try:
            daemon.test_connections()
            print("All connections OK")
            sys.exit(0)
        except Exception as exc:
            print(f"Connection test failed: {exc}", file=sys.stderr)
            sys.exit(1)

    # Run
    try:
        daemon.run(once=args.once)
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception as exc:
        log.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)
