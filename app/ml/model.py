import hashlib
import json
import logging
import math
import re
from pathlib import Path
from typing import Any

from app.core.contracts import Analysis, Assessment, Evidence
from app.core.files import open_regular
from app.ml.anomaly import Forest
from app.ml.schema import SCHEMAS, SCHEMAS_BY_ID, Schema, extract

log = logging.getLogger(__name__)
MAX_MODEL = 20 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
METRICS = ("precision", "recall", "f1", "roc_auc", "false_positive_rate", "brier_score")


def blob(path: Path, limit: int) -> bytes:
    with open_regular(path) as (source, size):
        if size.st_size > limit:
            raise ValueError(f"{path.name} exceeds the allowed size.")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"{path.name} exceeds the allowed size.")
        return data


def _number(value: object, low: float, high: float) -> bool:
    return type(value) in (int, float) and low <= value <= high  # type: ignore[operator]


def calibrated(raw: float, slope: float, intercept: float) -> float:
    z = max(-60.0, min(60.0, raw * slope + intercept))
    return 1 / (1 + math.exp(-z))


class InstalledModel:
    def __init__(
        self,
        schema: Schema,
        manifest: dict[str, Any],
        booster: Any,
        forest: Forest | None,
    ) -> None:
        self.schema, self.manifest, self.booster, self.forest = schema, manifest, booster, forest

    @classmethod
    def load_for_format(
        cls, package: Path, kind: str, *, require_promoted: bool = True
    ) -> "InstalledModel":
        manifest = json.loads(blob(package / "manifest.json", MAX_MANIFEST))
        if not isinstance(manifest, dict) or not isinstance(manifest.get("schema"), str):
            raise ValueError("Malformed model manifest.")
        schema = SCHEMAS_BY_ID.get(manifest["schema"])
        if schema is None or schema.format != kind:
            raise ValueError("Model format or feature schema does not match.")
        return cls.load(package, schema, require_promoted=require_promoted)

    @classmethod
    def load(
        cls, package: Path, schema: Schema, *, require_promoted: bool = True
    ) -> "InstalledModel":
        manifest = json.loads(blob(package / "manifest.json", MAX_MANIFEST))
        if not isinstance(manifest, dict) or not (
            manifest.get("package") == 1
            and manifest.get("format") == schema.format
            and manifest.get("schema") == schema.id
            and manifest.get("features") == list(schema.features)
            and manifest.get("algorithm") == "lightgbm-binary"
        ):
            raise ValueError("Model format, package version, or feature schema does not match.")
        if require_promoted and (
            manifest.get("promoted") is not True or manifest.get("synthetic") is not False
        ):
            raise ValueError("This model has not been approved for local inference.")
        if not isinstance(manifest.get("version"), str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,80}", manifest["version"]
        ):
            raise ValueError("Invalid version string.")
        for key in ("provenance", "limitations", "splits"):
            if not isinstance(manifest.get(key), str) or not manifest[key].strip():
                raise ValueError(f"Missing model {key}.")
        metrics = manifest.get("metrics", {})
        matrix = metrics.get("confusion_matrix", []) if isinstance(metrics, dict) else []
        if (
            not isinstance(metrics, dict)
            or any(not _number(metrics.get(name), 0, 1) for name in METRICS)
            or not isinstance(matrix, list)
            or len(matrix) != 2
            or any(
                not isinstance(row, list)
                or len(row) != 2
                or any(type(n) is not int or n < 0 for n in row)
                or sum(row) < 1
                for row in matrix
            )
        ):
            raise ValueError("Held-out validation metrics are missing or invalid.")
        calibration = manifest.get("calibration", {})
        if (
            not isinstance(calibration, dict)
            or calibration.get("method") != "platt"
            or not _number(calibration.get("slope"), 1e-9, 1e6)
            or not _number(calibration.get("intercept"), -1e6, 1e6)
            or not _number(manifest.get("threshold"), 0.0, 1.0)
            or manifest["threshold"] in (0.0, 1.0)
        ):
            raise ValueError("Invalid model calibration or threshold.")
        body = blob(package / "booster.txt", MAX_MODEL)
        if hashlib.sha256(body).hexdigest() != manifest.get("booster_sha256"):
            raise ValueError("Model file integrity check failed.")
        # Only local, explicitly trusted LightGBM text models reach this native parser.
        from lightgbm import Booster

        booster = Booster(model_str=body.decode("utf-8"))
        if (
            booster.feature_name() != schema.columns
            or booster.num_model_per_iteration() != 1
            or booster.num_trees() < 1
            or getattr(booster, "_Booster__num_class", 1) != 1
            or b"objective=binary" not in body[:4096]
        ):
            raise ValueError("The LightGBM booster is incompatible with this schema.")
        raw_forest = manifest.get("anomaly")
        forest = (
            Forest.from_json(raw_forest, len(schema.features))
            if isinstance(raw_forest, dict)
            else None
        )
        return cls(schema, manifest, booster, forest)

    def assess(self, data: bytes, analysis: Analysis, threads: int) -> Assessment:
        import numpy as np

        vector = extract(data, analysis, self.schema)
        # LightGBM prediction objects and native OpenMP state are owned by this predictor.
        contributions = self.booster.predict(
            np.asarray([vector], dtype=np.float32), pred_contrib=True, num_threads=threads
        )[0]
        if len(contributions) != len(vector) + 1 or not all(
            math.isfinite(value) for value in contributions
        ):
            raise ValueError("The model produced invalid SHAP values.")
        fit = self.manifest["calibration"]
        score = calibrated(float(sum(contributions)), fit["slope"], fit["intercept"])
        threshold = self.manifest["threshold"]
        anomaly = self.forest.percentile(vector) if self.forest else None
        if score >= threshold:
            review = "Elevated model score"
        elif anomaly is not None and anomaly >= 0.98:
            review = "Unusual features · review suggested"
        else:
            review = "Below classifier threshold"
        ranks = sorted(range(len(vector)), key=lambda i: -abs(contributions[i]))[:10]
        return Assessment(
            status="Available",
            reason="Calibrated classifier with TreeSHAP evidence. The experimental anomaly "
            "percentile is shown separately and only affects review priority.",
            model_version=self.manifest["version"],
            probability=score,
            threshold=threshold,
            anomaly_percentile=anomaly,
            review=review,
            baseline=float(contributions[-1]),
            evidence=[
                Evidence(self.schema.features[i], vector[i], float(contributions[i]))
                for i in ranks
                if contributions[i] != 0
            ],
        )


class Registry:
    def __init__(self, directory: Path, threads: int = 1) -> None:
        from threading import Lock

        self.threads = threads
        self.models: dict[str, InstalledModel] = {}
        self.reasons: dict[str, str] = {}
        self.predict_lock = Lock()
        for kind in SCHEMAS:
            try:
                self.models[kind] = InstalledModel.load_for_format(directory / kind.lower(), kind)
            except FileNotFoundError:
                self.reasons[kind] = "No approved model package is installed."
            except (ImportError, OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
                self.reasons[kind] = f"Model unavailable · {exc}"

    def assess(self, data: bytes, analysis: Analysis) -> Assessment:
        model = self.models.get(analysis.format)
        if model is None:
            return Assessment(reason=self.reasons.get(analysis.format, "No compatible model."))
        try:
            with self.predict_lock:
                return model.assess(data, analysis, self.threads)
        except (ImportError, OSError, ValueError, TypeError, RuntimeError):
            log.exception("Model prediction failed", extra={"operation": "model_inference"})
            return Assessment(reason="The installed model could not score this file.")
