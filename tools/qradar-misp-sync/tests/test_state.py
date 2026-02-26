"""Tests for state management."""

import json
import os
import tempfile

import pytest

from qradar_misp_sync.state import StateManager


@pytest.fixture
def state_file():
    """Create a temporary state file path."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.unlink(path)  # Start fresh
    yield path
    if os.path.exists(path):
        os.unlink(path)


class TestStateManager:
    def test_fresh_state(self, state_file):
        state = StateManager(state_file)
        assert state.last_offense_id == 0
        assert state.sighting_cursor == 0

    def test_mark_offense_processed(self, state_file):
        state = StateManager(state_file)
        state.mark_offense_processed(42)

        assert state.last_offense_id == 42
        assert state.is_offense_processed(42) is True
        assert state.is_offense_processed(41) is False

    def test_persistence(self, state_file):
        # Write state
        state1 = StateManager(state_file)
        state1.mark_offense_processed(100)
        state1.save()

        # Load in new instance
        state2 = StateManager(state_file)
        assert state2.last_offense_id == 100
        assert state2.is_offense_processed(100) is True

    def test_high_water_mark(self, state_file):
        state = StateManager(state_file)
        state.mark_offense_processed(10)
        state.mark_offense_processed(5)  # Lower ID
        state.mark_offense_processed(20)

        # High water mark should be 20
        assert state.last_offense_id == 20

    def test_stats(self, state_file):
        state = StateManager(state_file)
        state.increment_stat("total_offenses_processed", 5)
        state.increment_stat("total_events_created", 3)

        assert state.stats["total_offenses_processed"] == 5
        assert state.stats["total_events_created"] == 3

    def test_reset(self, state_file):
        state = StateManager(state_file)
        state.mark_offense_processed(100)
        state.increment_stat("total_events_created", 10)
        state.save()

        state.reset()
        assert state.last_offense_id == 0
        assert state.stats["total_events_created"] == 0

    def test_atomic_save(self, state_file):
        state = StateManager(state_file)
        state.mark_offense_processed(42)
        state.save()

        # Verify the file is valid JSON
        with open(state_file) as f:
            data = json.load(f)
        assert data["last_offense_id"] == 42

    def test_corrupt_state_file_recovery(self, state_file):
        # Write corrupt data
        with open(state_file, "w") as f:
            f.write("NOT VALID JSON {{{")

        # Should recover gracefully
        state = StateManager(state_file)
        assert state.last_offense_id == 0
