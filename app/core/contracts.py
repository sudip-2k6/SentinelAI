from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Literal

FileFormat = Literal["PE", "ELF", "Unknown"]
ScanStatus = Literal["Analyzed", "Unsupported", "Malformed", "Skipped", "Error", "Cancelled"]


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(slots=True)
class Analysis:
    format: FileFormat
    headers: dict[str, str | int]
    sections: list[dict[str, str | int | float]]
    imports: list[str]
    indicators: dict[str, int]
    entropy: float


@dataclass(slots=True)
class Evidence:
    feature: str
    value: float
    contribution: float


@dataclass(slots=True)
class Assessment:
    status: str = "Unavailable"
    reason: str = "A validated model has not been installed for this feature schema."
    model_version: str | None = None
    probability: float | None = None
    threshold: float | None = None
    anomaly_percentile: float | None = None
    review: str = ""
    baseline: float | None = None
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    path: str
    status: ScanStatus
    timestamp: str = field(default_factory=utc_now)
    format: FileFormat = "Unknown"
    size: int | None = None
    sha256: str | None = None
    executable: bool | None = None
    message: str = ""
    analysis: Analysis | None = None
    assessment: Assessment = field(default_factory=Assessment)

    def to_dict(self) -> dict:
        return asdict(self)
