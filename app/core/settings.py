import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from platformdirs import user_data_path


def default_root() -> Path:
    return user_data_path("SentinelAI", appauthor=False)


@dataclass(slots=True)
class Settings:
    theme: str = "Dark"
    scan_workers: int = 2
    model_threads: int = 1
    max_mib: int = 48
    scan_duty_percent: int = 75
    retention_days: int = 90
    notifications: bool = True
    exclusions: list[str] = field(default_factory=lambda: [".git", "__pycache__", "node_modules"])
    watch_dirs: list[str] = field(default_factory=list)
    debounce_ms: int = 1200
    process_interval_ms: int = 3500

    def validate(self) -> None:
        bounds = {
            "scan_workers": (1, 4),
            "model_threads": (1, 4),
            "max_mib": (1, 128),
            "scan_duty_percent": (10, 100),
            "retention_days": (1, 3650),
            "debounce_ms": (250, 15000),
            "process_interval_ms": (1000, 30000),
        }
        for field_name, (low, high) in bounds.items():
            value = getattr(self, field_name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{field_name} must be an integer from {low} to {high}.")
        if self.theme not in {"Dark", "Light"} or type(self.notifications) is not bool:
            raise ValueError("Invalid theme or notification setting.")
        for values in (self.exclusions, self.watch_dirs):
            if not isinstance(values, list) or len(values) > 128:
                raise ValueError("Provide no more than 128 entries per list.")
            if any(
                not isinstance(item, str) or not item.strip() or len(item) > 4096 for item in values
            ):
                raise ValueError("Invalid exclusion or watch directory entry.")

    @classmethod
    def load(cls, root: Path) -> "Settings":
        path = root / "settings.json"
        try:
            with path.open(encoding="utf-8") as source:
                data = json.loads(source.read(128 * 1024 + 1))
        except FileNotFoundError:
            return cls()
        if not isinstance(data, dict):
            raise ValueError("Settings must be a JSON object.")
        settings = cls(
            **{key: value for key, value in data.items() if key in cls.__dataclass_fields__}
        )
        settings.validate()
        return settings

    def save(self, root: Path) -> None:
        self.validate()
        temporary = root / "settings.json.tmp"
        temporary.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        temporary.replace(root / "settings.json")
