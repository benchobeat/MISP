"""Persistent state management for tracking processed offenses.

Uses a simple JSON file to survive daemon restarts. Tracks:
- Last processed offense ID (for incremental polling)
- Set of recently processed offense IDs (deduplication window)
- Sighting feedback cursor (last MISP search timestamp)
"""

import copy
import json
import logging
import os
import time
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_STATE = {
    "last_offense_id": 0,
    "last_poll_time": 0,
    "processed_offense_ids": [],
    "sighting_cursor": 0,
    "stats": {
        "total_offenses_processed": 0,
        "total_events_created": 0,
        "total_sightings_reported": 0,
        "last_error": None,
    },
}

# Keep a sliding window of recent offense IDs for deduplication
DEDUP_WINDOW_SIZE = 500


class StateManager:
    """Manages persistent daemon state via a JSON file.

    Args:
        state_file: Path to the JSON state file.
    """

    def __init__(self, state_file: str):
        self._path = Path(state_file)
        self._state = copy.deepcopy(DEFAULT_STATE)
        self._load()

    def _load(self):
        """Load state from disk, or initialize with defaults."""
        if self._path.exists():
            try:
                with open(self._path, "r") as f:
                    saved = json.load(f)
                # Merge saved state with defaults (handles schema upgrades)
                for key in DEFAULT_STATE:
                    if key in saved:
                        self._state[key] = saved[key]
                log.info("Loaded state from %s (last_offense_id=%d)", self._path, self._state["last_offense_id"])
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Failed to load state file %s, starting fresh: %s", self._path, exc)
        else:
            log.info("No state file found at %s, starting fresh", self._path)

    def save(self):
        """Persist current state to disk atomically.

        Writes to a temp file first, then renames to avoid corruption on crash.
        """
        tmp_path = self._path.with_suffix(".tmp")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp_path, "w") as f:
                json.dump(self._state, f, indent=2)
            os.replace(str(tmp_path), str(self._path))
        except OSError as exc:
            log.error("Failed to save state to %s: %s", self._path, exc)
            raise

    # ------------------------------------------------------------------
    # Offense tracking
    # ------------------------------------------------------------------

    @property
    def last_offense_id(self) -> int:
        return self._state["last_offense_id"]

    @last_offense_id.setter
    def last_offense_id(self, value: int):
        self._state["last_offense_id"] = value

    def mark_offense_processed(self, offense_id: int):
        """Mark an offense as processed and update the high-water mark."""
        ids = self._state["processed_offense_ids"]
        if offense_id not in ids:
            ids.append(offense_id)
        # Trim to dedup window
        if len(ids) > DEDUP_WINDOW_SIZE:
            self._state["processed_offense_ids"] = ids[-DEDUP_WINDOW_SIZE:]

        if offense_id > self._state["last_offense_id"]:
            self._state["last_offense_id"] = offense_id

        self._state["last_poll_time"] = int(time.time())

    def is_offense_processed(self, offense_id: int) -> bool:
        """Check if an offense has already been processed (within dedup window)."""
        return offense_id in self._state["processed_offense_ids"]

    # ------------------------------------------------------------------
    # Sighting feedback cursor
    # ------------------------------------------------------------------

    @property
    def sighting_cursor(self) -> int:
        """Unix timestamp of last sighting feedback run."""
        return self._state["sighting_cursor"]

    @sighting_cursor.setter
    def sighting_cursor(self, value: int):
        self._state["sighting_cursor"] = value

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def increment_stat(self, key: str, count: int = 1):
        """Increment a stats counter."""
        if key in self._state["stats"]:
            current = self._state["stats"][key]
            if isinstance(current, (int, float)):
                self._state["stats"][key] = current + count

    def set_last_error(self, error: str | None):
        """Record the last error message (or None to clear)."""
        self._state["stats"]["last_error"] = error

    @property
    def stats(self) -> dict:
        return dict(self._state["stats"])

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def reset(self):
        """Reset all state to defaults."""
        self._state = copy.deepcopy(DEFAULT_STATE)
        self.save()
        log.info("State reset to defaults")
