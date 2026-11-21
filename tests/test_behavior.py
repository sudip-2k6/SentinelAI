import json
from pathlib import Path

import pytest

from app.monitoring.behavior import MAX_REPORT, import_report


def test_normalized_inert_report() -> None:
    report = import_report(Path(__file__).parent / "fixtures" / "synthetic-behavior.json")
    assert report.events == 4 and report.processes == 2
    assert report.sequences[0] == ("process", "file", "network")
    assert report.counts["registry"] == 0


def test_sandbox_inline_counts_ignore_untrusted_arguments(tmp_path: Path) -> None:
    path = tmp_path / "sandbox.json"
    data = {
        "behavior": {
            "processes": [
                {
                    "calls": [
                        {"category": "filesystem", "arguments": {"value": "<sensitive>"}},
                        {"category": "unmapped", "api": "untrusted text"},
                    ]
                },
            ]
        }
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    report = import_report(path)
    assert report.counts["file"] == 1 and report.counts["other"] == 1
    assert "<sensitive>" not in repr(report) and "untrusted text" not in repr(report)


def test_behavior_handles_malformed_and_huge_reports(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(
        '{"schema": "sentinel-behavior-v1", "events": [{"time_ms": NaN}]}', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="Events must"):
        import_report(path)
    with path.open("wb") as stream:
        stream.truncate(MAX_REPORT + 1)
    with pytest.raises(ValueError, match="8 MiB"):
        import_report(path)
