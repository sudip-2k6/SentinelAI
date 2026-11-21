import hashlib
import json
import re
import tempfile
from collections import Counter
from pathlib import Path

import lightgbm as lgb
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from app.core.contracts import utc_now
from app.ml.anomaly import Forest
from app.ml.datasets import Example, load, schema_for, unique_partitions
from app.ml.model import MAX_MANIFEST, MAX_MODEL, InstalledModel, blob

SEED = 1748


def _limitations(adapter: str) -> str:
    details = {
        "ember-rich": "Uses byte and string statistics plus bounded PE structure and imports. "
        "The archive and live scanner use different PE parsers.",
        "ember2024-elf-rich": "Uses byte and string statistics. ELF structural fields are "
        "unavailable in the training archive.",
        "ember-precision": "Uses expanded section and import features. The archive and live "
        "scanner use different PE parsers.",
        "ember2024-elf-precision": "Uses expanded printable string and byte statistics. "
        "ELF structural fields are unavailable in the training archive.",
        "elf": "Uses structural ELF features.",
    }
    return (
        "Scores reflect labels and prevalence in the supplied data. Expect drift, "
        "label noise, false positives and false negatives. "
        + details.get(adapter, "Uses file size and a byte histogram projection.")
    )


def _has_labels(rows: list[Example]) -> bool:
    return {item.label for item in rows} == {0, 1}


def _split(path: Path, adapter: str) -> tuple[list[Example], list[Example], list[Example], str]:
    dataset = list(load(path, adapter))
    if adapter.startswith("ember"):
        official_test = list(load(path, adapter, test=True))
        if not official_test:
            raise ValueError("The official EMBER test partition is empty.")
        last_test_period = max(item.group for item in official_test)
        dataset = [item for item in dataset if item.group < last_test_period]
        periods = sorted({item.group for item in dataset})
        if len(periods) < 2:
            raise ValueError(
                "EMBER training requires at least two periods before the latest test period."
            )
        held_out = [item for item in official_test if item.group > periods[-1]]
        month_counts = Counter(item.group for item in dataset)
        target = len(dataset) * 4 // 5
        cumulative = 0
        preferred = 1
        for index, period in enumerate(periods[:-1], 1):
            cumulative += month_counts[period]
            if cumulative <= target:
                preferred = index
        candidates = sorted(range(1, len(periods)), key=lambda index: abs(index - preferred))
        for index in candidates:
            start = periods[index]
            earlier = [item for item in dataset if item.group < start]
            later = [item for item in dataset if item.group >= start]
            if not (_has_labels(earlier) and _has_labels(later) and _has_labels(held_out)):
                continue
            development, validation, test = unique_partitions(earlier, later, held_out)
            if _has_labels(development) and _has_labels(validation) and _has_labels(test):
                return (
                    development,
                    validation,
                    test,
                    f"EMBER chronological validation from {start}; "
                    f"publisher's test periods after {periods[-1]} "
                    f"({len(official_test) - len(held_out):,} overlapping rows excluded); "
                    "SHA-256 and projected-vector deduplication.",
                )
        raise ValueError("Could not build chronological partitions with both labels.")

    (dataset,) = unique_partitions(dataset)
    labels = [item.label for item in dataset]
    groups = [item.group for item in dataset]
    if len(set(groups)) < 5 or not _has_labels(dataset):
        raise ValueError("ELF requires both labels and at least five independent leakage groups.")
    outer = GroupShuffleSplit(n_splits=24, test_size=0.2, random_state=SEED)
    for working, held in outer.split(labels, labels, groups):
        test = [dataset[i] for i in held]
        if not _has_labels(test):
            continue
        dev = [dataset[i] for i in working]
        inner = GroupShuffleSplit(n_splits=8, test_size=0.25, random_state=SEED + 1)
        for train_indices, valid_indices in inner.split(dev, groups=[row.group for row in dev]):
            training = [dev[i] for i in train_indices]
            validation = [dev[i] for i in valid_indices]
            if _has_labels(training) and _has_labels(validation):
                return (
                    training,
                    validation,
                    test,
                    "Seeded group-disjoint approximately 60/20/20 "
                    "split by collection or family; SHA-256 and vector deduplication.",
                )
    raise ValueError("Could not build group-disjoint partitions with both labels.")


def _matrix(rows: list[Example]) -> tuple[np.ndarray, np.ndarray]:
    """Transfer the rows to a dense matrix and release each source vector as it is copied."""
    vectors = np.empty((len(rows), len(rows[0].features)), dtype=np.float32)
    labels = np.empty(len(rows), dtype=np.int8)
    for index in range(len(rows) - 1, -1, -1):
        row = rows.pop()
        vectors[index] = np.frombuffer(row.features, dtype=np.float32)
        labels[index] = row.label
    return vectors, labels


def _cutoff(scores: np.ndarray, target: float) -> float:
    index = len(scores) - int(len(scores) * target) - 1
    return float(np.partition(scores, index)[index])


def _validation_recall(predictions: np.ndarray, dataset: lgb.Dataset) -> tuple[str, float, bool]:
    labels = dataset.get_label()
    negative, positive = predictions[labels == 0], predictions[labels == 1]
    recall = np.mean([np.mean(positive > _cutoff(negative, target)) for target in (0.008, 0.015)])
    return "recall_at_low_fpr", float(recall), True


def _metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    predicted = scores >= threshold
    matrix = confusion_matrix(labels, predicted, labels=[0, 1])
    tn, fp, _, tp = matrix.ravel()
    return {
        "accuracy": float((tn + tp) / matrix.sum()),
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "f1": float(f1_score(labels, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, scores)),
        "false_positive_rate": float(fp / (tn + fp)),
        "brier_score": float(brier_score_loss(labels, scores)),
        "confusion_matrix": matrix.tolist(),
    }


def _forest(
    train: np.ndarray, labels: np.ndarray, valid: np.ndarray, valid_labels: np.ndarray
) -> Forest | None:
    benign = train[labels == 0]
    baseline = valid[valid_labels == 0][:4096]
    if len(benign) < 32 or len(baseline) < 16:
        return None
    fitted = IsolationForest(
        n_estimators=40, max_samples=min(128, len(benign)), n_jobs=1, random_state=SEED
    )
    fitted.fit(benign)
    trees = []
    for estimator in fitted.estimators_:
        tree = estimator.tree_
        trees.append(
            [
                [int(left), int(right), int(feature), float(threshold), int(count)]
                for left, right, feature, threshold, count in zip(
                    tree.children_left,
                    tree.children_right,
                    tree.feature,
                    tree.threshold,
                    tree.n_node_samples,
                    strict=True,
                )
            ]
        )
    forest = Forest(trees, fitted.max_samples_, [])
    forest.reference = sorted(forest.raw(row.tolist()) for row in baseline)
    return forest


def train(
    dataset: Path,
    adapter: str,
    output: Path,
    *,
    version: str,
    provenance: str,
    synthetic: bool,
    threshold: float | None = None,
    validation_fpr: float | None = None,
    anomaly: bool = False,
    threads: int = 1,
    min_accuracy: float | None = None,
    min_recall: float | None = None,
    max_test_fpr: float | None = None,
    tune_low_fpr: bool = False,
) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", version) or not provenance.strip():
        raise ValueError("A version and dataset provenance must be supplied.")
    optimize_accuracy = threshold is None and min_accuracy is not None
    threshold = 0.5 if threshold is None else threshold
    if not 0.01 <= threshold <= 0.99:
        raise ValueError("Threshold must be between 0.01 and 0.99.")
    if validation_fpr is not None and not 0 < validation_fpr < 1:
        raise ValueError("Validation false-positive rate target must be between 0 and 1.")
    if not 1 <= threads <= 8:
        raise ValueError("Training threads must be between 1 and 8.")
    for name, value in (
        ("Accuracy", min_accuracy),
        ("Recall", min_recall),
        ("Test FPR", max_test_fpr),
    ):
        if value is not None and not 0 < value <= 1:
            raise ValueError(f"{name} limit must be between 0 and 1.")
    if output.exists():
        raise FileExistsError(output)
    if tune_low_fpr and adapter != "ember2024-elf-precision":
        raise ValueError("The low-FPR model search is supported by the EMBER2024 ELF adapter.")
    schema = schema_for(adapter)
    development, validation, test, split = _split(dataset, adapter)
    if any(
        min(sum(row.label == label for row in part) for label in (0, 1)) < 5
        for part in (development, validation, test)
    ):
        raise ValueError("Each partition requires at least five samples from each class.")
    x_train, y_train = _matrix(development)
    x_valid, y_valid = _matrix(validation)
    x_test, y_test = _matrix(test)
    del development, validation, test
    low_fpr = adapter.endswith("-precision")
    rich = low_fpr or adapter.endswith("-rich")
    defaults = {
        "objective": "binary",
        "metric": "None" if low_fpr else "binary_logloss",
        "num_threads": threads,
        "seed": SEED,
        "deterministic": True,
        "force_col_wise": True,
        "verbosity": -1,
        "num_leaves": 127 if low_fpr and schema.format == "PE" else 63 if rich else 15,
        "learning_rate": 0.07 if low_fpr else 0.05,
        "feature_fraction": 0.8 if low_fpr else 1.0,
        "min_data_in_leaf": 25 if rich else 5,
    }
    profiles: list[dict[str, int | float]] = [{}]
    if tune_low_fpr:
        profiles.extend(
            [
                {"num_leaves": 63, "min_data_in_leaf": 100, "feature_fraction": 1.0},
                {"num_leaves": 31, "min_data_in_leaf": 35, "feature_fraction": 0.7},
                {"num_leaves": 95, "min_data_in_leaf": 18, "feature_fraction": 0.65},
            ]
        )
    best_score = -1.0
    booster = None
    selected = defaults
    for profile in profiles:
        parameters = defaults | profile
        training = lgb.Dataset(x_train, label=y_train, feature_name=schema.columns)
        fitted = lgb.train(
            parameters,
            training,
            num_boost_round=800 if low_fpr else 650 if rich else 90,
            feval=_validation_recall if low_fpr else None,
            valid_sets=[lgb.Dataset(x_valid, label=y_valid, reference=training)] if rich else None,
            callbacks=[
                lgb.early_stopping(100 if low_fpr else 50, verbose=False),
                lgb.log_evaluation(50),
            ]
            if rich
            else None,
        )
        score = fitted.best_score["valid_0"]["recall_at_low_fpr"] if low_fpr else 0.0
        if tune_low_fpr:
            print(f"ELF validation score {score:.4f} for {profile or 'default'}", flush=True)
        if score > best_score:
            best_score, booster, selected = score, fitted, parameters
    assert booster is not None
    margin = np.asarray(booster.predict(x_valid, raw_score=True, num_threads=threads)).reshape(
        -1, 1
    )
    calibration = LogisticRegression(random_state=SEED)
    calibration.fit(margin, y_valid)
    slope = float(calibration.coef_[0, 0])
    if slope <= 0:
        raise ValueError("Calibration failed to find a positive relationship to validation labels.")
    valid_scores = calibration.predict_proba(margin)[:, 1]
    if validation_fpr is not None:
        negatives = valid_scores[y_valid == 0]
        threshold = max(0.01, _cutoff(negatives, validation_fpr) + 1e-12)
        if threshold >= 1 or np.mean(negatives >= threshold) > validation_fpr:
            raise ValueError("Validation FPR target cannot be met at a supported threshold.")
    elif optimize_accuracy:
        # Choose the cutoff using only calibration data and predict equal scores together.
        order = np.argsort(-valid_scores, kind="stable")
        ranked = valid_scores[order]
        gains = np.cumsum(2 * y_valid[order] - 1)
        cutoffs = np.flatnonzero(
            np.r_[ranked[:-1] > ranked[1:], True] & (ranked >= 0.01) & (ranked <= 0.99)
        )
        if cutoffs.size:
            chosen = cutoffs[np.argmax(gains[cutoffs])]
            next_score = ranked[chosen + 1] if chosen + 1 < len(ranked) else 0.0
            threshold = max(0.01, float((ranked[chosen] + next_score) / 2))
    test_margin = np.asarray(booster.predict(x_test, raw_score=True, num_threads=threads)).reshape(
        -1, 1
    )
    scores = calibration.predict_proba(test_margin)[:, 1]
    metrics = _metrics(y_test, scores, threshold)
    alternatives = []
    if low_fpr:
        for target in (0.008, 0.015):
            cutoff = max(0.01, _cutoff(valid_scores[y_valid == 0], target) + 1e-12)
            alternatives.append(
                {
                    "validation_target_fpr": target,
                    "threshold": cutoff,
                    "test": _metrics(y_test, scores, cutoff),
                }
            )
    body = booster.model_to_string().encode("utf-8")
    forest = _forest(x_train, y_train, x_valid, y_valid) if anomaly else None
    metadata = {
        "package": 1,
        "format": schema.format,
        "schema": schema.id,
        "features": list(schema.features),
        "version": version,
        "algorithm": "lightgbm-binary",
        "created_utc": utc_now(),
        "provenance": provenance,
        "adapter": adapter,
        "splits": split,
        "seed": SEED,
        "training_threads": threads,
        "training_parameters": selected,
        "validation_recall_at_low_fpr": best_score if low_fpr else None,
        "class_counts": {
            name: np.bincount(labels, minlength=2).tolist()
            for name, labels in (("train", y_train), ("calibration", y_valid), ("test", y_test))
        },
        "limitations": _limitations(adapter),
        "calibration": {
            "method": "platt",
            "slope": slope,
            "intercept": float(calibration.intercept_[0]),
        },
        "metrics": metrics,
        "minimum_test_accuracy": min_accuracy,
        "minimum_test_recall": min_recall,
        "maximum_test_fpr": max_test_fpr,
        "operating_points": alternatives,
        "threshold": threshold,
        "validation_false_positive_rate": float(np.mean(valid_scores[y_valid == 0] >= threshold)),
        "validation_target_false_positive_rate": validation_fpr,
        "synthetic": synthetic,
        "promoted": False,
        "booster_sha256": hashlib.sha256(body).hexdigest(),
        "lightgbm": lgb.__version__,
        "scikit_learn": sklearn.__version__,
        "anomaly": forest.to_json() if forest else None,
    }
    _publish(output, metadata, body)
    return metadata


def _publish(output: Path, metadata: dict, body: bytes) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sentinel-model-", dir=output.parent) as directory:
        candidate = Path(directory) / "bundle"
        candidate.mkdir()
        (candidate / "booster.txt").write_bytes(body)
        (candidate / "manifest.json").write_text(
            json.dumps(metadata, indent=2, allow_nan=False),
            encoding="utf-8",
        )
        if output.exists():
            raise FileExistsError(output)
        candidate.rename(output)


def promote(candidate: Path, model_root: Path) -> Path:
    meta = json.loads(blob(candidate / "manifest.json", MAX_MANIFEST))
    if not isinstance(meta, dict) or not isinstance(meta.get("format"), str):
        raise ValueError("Malformed model manifest.")
    if meta.get("synthetic") is not False:
        raise ValueError("Only compatible models trained on non-synthetic data can be promoted.")
    checked = InstalledModel.load_for_format(candidate, meta["format"], require_promoted=False)
    for key, label in (
        ("minimum_test_accuracy", "accuracy"),
        ("minimum_test_recall", "recall"),
        ("maximum_test_fpr", "false-positive rate"),
    ):
        limit = checked.manifest.get(key)
        if limit is None:
            continue
        matrix = checked.manifest["metrics"]["confusion_matrix"]
        (tn, fp), (fn, tp) = matrix
        value = {
            "accuracy": (tn + tp) / (tn + fp + fn + tp),
            "recall": tp / (tp + fn),
            "false-positive rate": fp / (tn + fp),
        }[label]
        if (
            type(limit) not in (int, float)
            or not 0 < limit <= 1
            or (value >= limit if key == "maximum_test_fpr" else value < limit)
        ):
            raise ValueError(f"Test {label} {value:.2%} fails the package's promotion gate.")
    manifest = dict(checked.manifest)
    if manifest.get("adapter") in ("ember-rich", "ember2024-elf-rich"):
        manifest["limitations"] = _limitations(manifest["adapter"])
    manifest.update(promoted=True, promoted_utc=utc_now())
    body = blob(candidate / "booster.txt", MAX_MODEL)
    if hashlib.sha256(body).hexdigest() != manifest["booster_sha256"]:
        raise ValueError("Candidate changed during promotion.")
    destination = model_root / checked.schema.format.lower()
    _publish(destination, manifest, body)
    return destination
