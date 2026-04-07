"""Tests for the watch module."""
from __future__ import annotations

import time


from rulescope.config.settings import RuleScopeConfig
from rulescope.engine import RuleScopeEngine
from rulescope.watcher import _changed_paths, _collect_watch_snapshot, _hash_files, _score_style, _watch_once


class TestWatchHelpers:
    def test_hash_files_directory(self, tmp_path):
        (tmp_path / "a.yml").write_text("title: A")
        (tmp_path / "b.yml").write_text("title: B")
        h1 = _hash_files(tmp_path)
        assert isinstance(h1, str)
        assert len(h1) == 32  # md5 hex

    def test_hash_changes_on_modification(self, tmp_path):
        f = tmp_path / "rule.yml"
        f.write_text("title: Before")
        h1 = _hash_files(tmp_path)
        time.sleep(0.05)
        f.write_text("title: After")
        h2 = _hash_files(tmp_path)
        assert h1 != h2

    def test_hash_single_file(self, tmp_path):
        f = tmp_path / "rule.yml"
        f.write_text("title: Test")
        h = _hash_files(f)
        assert isinstance(h, str)

    def test_hash_empty_dir(self, tmp_path):
        h = _hash_files(tmp_path)
        assert isinstance(h, str)

    def test_score_style_green(self):
        assert _score_style(85) == "green"

    def test_score_style_yellow(self):
        assert _score_style(55) == "yellow"

    def test_score_style_red(self):
        assert _score_style(25) == "red"


class TestWatchCLI:
    def test_watch_command_exists(self):
        from typer.testing import CliRunner
        from rulescope.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["watch", "--help"])
        assert result.exit_code == 0
        assert "watch" in result.output.lower() or "Watch" in result.output

    def test_watch_invalid_path(self):
        from typer.testing import CliRunner
        from rulescope.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["watch", "/nonexistent/path"])
        assert result.exit_code != 0


    def test_collect_watch_snapshot_reports_changed_paths(self, tmp_path):
        f = tmp_path / "rule.yml"
        f.write_text("title: Before")
        s1 = _collect_watch_snapshot(f)
        time.sleep(0.05)
        f.write_text("title: After")
        s2 = _collect_watch_snapshot(f)
        assert _changed_paths(s1, s2) == ["rule.yml"]

    def test_watch_once_rescans_after_file_change(self, tmp_path):
        rule = tmp_path / "rule.yml"
        rule.write_text(
            """title: Watch Rule
id: 12345678-1234-1234-1234-123456789abc
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: powershell
  condition: selection
level: low
status: test
description: Watch test rule.
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Admin scripts
author: tests
date: 2024-01-01
"""
        )
        engine = RuleScopeEngine(config=RuleScopeConfig())
        renderable, previous_snapshot, previous_fs_snapshot, scan_count, changed = _watch_once(
            root=rule,
            target=str(rule),
            engine=engine,
            scan_count=0,
            previous_snapshot=None,
            previous_fs_snapshot=None,
        )
        assert renderable is not None
        assert scan_count == 1
        assert changed == []

        time.sleep(0.05)
        rule.write_text(rule.read_text() + "\nreferences:\n  - https://example.com/watch\n")
        renderable, previous_snapshot, previous_fs_snapshot, scan_count, changed = _watch_once(
            root=rule,
            target=str(rule),
            engine=engine,
            scan_count=scan_count,
            previous_snapshot=previous_snapshot,
            previous_fs_snapshot=previous_fs_snapshot,
        )
        assert renderable is not None
        assert scan_count == 2
        assert changed == ["rule.yml"]
