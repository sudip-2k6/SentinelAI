import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from zipfile import ZipFile

import pytest

from app.features import elf, pe
from app.ml.datasets import load
from app.ml.model import InstalledModel, Registry
from app.ml.schema import (
    ELF,
    ELF_HISTOGRAM,
    ELF_PRECISION,
    ELF_RICH,
    PE_PRECISION,
    PE_RICH,
    extract,
)
from tests.fixtures import elf_fixture, pe_fixture


def test_ember_projection_matches_static_extractor(tmp_path: Path) -> None:
    data = pe_fixture()
    raw = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "appeared": "2018-06",
        "label": 0,
        "general": {"size": len(data)},
        "histogram": [data.count(i) for i in range(256)],
    }
    (tmp_path / "train_features_0.jsonl").write_text(json.dumps(raw), encoding="utf-8")
    (item,) = load(tmp_path, "ember")
    assert list(item.features) == pytest.approx(extract(data, pe.parse(data)))


def test_absent_distinct_models(tmp_path: Path) -> None:
    absent = Registry(tmp_path)
    data = elf_fixture()
    assessment = absent.assess(data, elf.parse(data))
    assert assessment.probability is None and len(absent.reasons) == 2


def test_ember2024_elf_uses_the_submission_week_and_live_features(tmp_path: Path) -> None:
    data = elf_fixture()
    timestamp = int(datetime(2024, 10, 5, tzinfo=UTC).timestamp())
    raw = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_type": "ELF",
        "first_submission_date": timestamp,
        "label": 0,
        "general": {"size": len(data)},
        "histogram": [data.count(i) for i in range(256)],
    }
    with ZipFile(tmp_path / "ELF_test.zip", "w") as archive:
        archive.writestr("2024-10-06_2024-10-12_ELF_test.jsonl", json.dumps(raw))
    (item,) = load(tmp_path, "ember2024-elf", test=True)
    assert item.group == "2024-09-29"
    assert list(item.features) == pytest.approx(extract(data, elf.parse(data), ELF_HISTOGRAM))
    with pytest.raises(ValueError, match="No compatible"):
        extract(pe_fixture(), pe.parse(pe_fixture()), ELF_HISTOGRAM)


def test_rich_vectors_cover_the_live_model_columns() -> None:
    pytest.importorskip("numpy")
    elf_data = elf_fixture() + b"/bin/sh process PROCESS\0process"
    elf_features = dict(
        zip(ELF_RICH.features, extract(elf_data, elf.parse(elf_data), ELF_RICH), strict=True)
    )
    assert sum(
        value for name, value in elf_features.items() if name.startswith("Local entropy bin")
    ) == pytest.approx(1)
    assert elf_features["Printable strings containing /bin/"] == 1
    assert elf_features["Printable strings containing process"] == 2
    pe_data = pe_fixture()
    pe_features = dict(
        zip(PE_RICH.features, extract(pe_data, pe.parse(pe_data), PE_RICH), strict=True)
    )
    assert pe_features["PE section count"] == 1
    assert pe_features["Executable sections"] == 1
    assert pe_features["Byte marker count MZ"] == 1
    assert pe_features["sizeof_headers"] == 512


def test_precision_vectors_add_sections_and_printable_markers() -> None:
    pytest.importorskip("numpy")
    elf_data = elf_fixture() + b"https://example.org CONNECT\0connect\0"
    elf_values = dict(
        zip(
            ELF_PRECISION.features,
            extract(elf_data, elf.parse(elf_data), ELF_PRECISION),
            strict=True,
        )
    )
    assert elf_values["Printable strings matching url"] == 1
    assert elf_values["Printable strings matching connect"] == 2
    pe_data = pe_fixture()
    values = dict(
        zip(
            PE_PRECISION.features,
            extract(pe_data, pe.parse(pe_data), PE_PRECISION),
            strict=True,
        )
    )
    assert values["PE machine"] == 0x8664
    assert values["PE subsystem"] == 3
    assert values["Largest section"] == 512
    assert values["COFF EXECUTABLE_IMAGE"] == 1


def test_ember_temporal_cutoff_accounts_for_old_benign_only_months(tmp_path: Path) -> None:
    pytest.importorskip("lightgbm")
    from app.ml.train import _split

    def rows(groups: list[tuple[str, int, int]]) -> str:
        output = []
        for month, label, count in groups:
            for index in range(count):
                tag = f"{month}-{label}-{index}"
                histogram = [0] * 256
                histogram[len(output)] = 1
                histogram[-1] = int(month.replace("-", "")) + label + index
                output.append(
                    json.dumps(
                        {
                            "sha256": hashlib.sha256(tag.encode()).hexdigest(),
                            "label": label,
                            "appeared": month,
                            "general": {"size": sum(histogram)},
                            "histogram": histogram,
                        }
                    )
                )
        return "\n".join(output)

    old_months = [(f"2017-{month:02}", 0, 1) for month in range(1, 13)]
    recent = [(f"2018-{month:02}", label, 8) for month in (1, 2, 3) for label in (0, 1)]
    (tmp_path / "train_features_0.jsonl").write_text(rows(old_months + recent), encoding="utf-8")
    (tmp_path / "test_features.jsonl").write_text(
        rows([("2018-04", 0, 8), ("2018-04", 1, 8)]), encoding="utf-8"
    )
    training, calibration, test, _ = _split(tmp_path, "ember")
    assert max(item.group for item in training) == "2018-02"
    assert {item.group for item in calibration} == {"2018-03"}
    assert {item.group for item in test} == {"2018-04"}
    assert all({item.label for item in split} == {0, 1} for split in (training, calibration, test))


def test_training_evidence_and_synthetic_promotion_gate(tmp_path: Path) -> None:
    pytest.importorskip("lightgbm")
    from app.ml.train import promote, train

    dataset = tmp_path / "synthetic.jsonl"
    examples = []
    for group in range(12):
        for index in range(20):
            label = index % 2
            vector = [2000 + group * 20 + index, 1 + label * 6, 64, 4, 12, 4, 3, 0, 2, 3, 0]
            tag = f"synthetic-{group}-{index}"
            examples.append(
                {
                    "schema": ELF.id,
                    "group": f"group-{group}",
                    "label": label,
                    "sha256": hashlib.sha256(tag.encode()).hexdigest(),
                    "features": vector,
                }
            )
    dataset.write_text("\n".join(json.dumps(item) for item in examples), encoding="utf-8")
    bundle = tmp_path / "candidate"
    meta = train(
        dataset,
        "elf",
        bundle,
        version="synthetic-test",
        provenance="Inert synthetic software test only",
        synthetic=True,
        anomaly=True,
    )
    assert meta["metrics"]["confusion_matrix"]
    assert meta["anomaly"]
    with pytest.raises(ValueError, match="non-synthetic"):
        promote(bundle, tmp_path / "models")
    with pytest.raises(ValueError, match="not been approved"):
        InstalledModel.load(bundle, ELF)
    candidate = InstalledModel.load(bundle, ELF, require_promoted=False)
    assert InstalledModel.load_for_format(bundle, "ELF", require_promoted=False).schema == ELF
    with pytest.raises(ValueError, match="format or feature schema"):
        InstalledModel.load_for_format(bundle, "PE", require_promoted=False)
    data = elf_fixture()
    evidence = candidate.assess(data, elf.parse(data), 1)
    assert evidence.probability is not None and evidence.anomaly_percentile is not None
    assert evidence.baseline is not None and evidence.evidence
    with (bundle / "booster.txt").open("a", encoding="utf-8") as handle:
        handle.write("changed")
    with pytest.raises(ValueError, match="integrity"):
        InstalledModel.load(bundle, ELF, require_promoted=False)
