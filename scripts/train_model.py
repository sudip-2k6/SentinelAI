import argparse
import json
from pathlib import Path
from zipfile import BadZipFile

from app.core.settings import default_root
from app.ml.train import promote, train


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and explicitly promote local models")
    commands = parser.add_subparsers(dest="action", required=True)
    fit = commands.add_parser("train")
    fit.add_argument(
        "adapter",
        choices=[
            "ember",
            "ember-rich",
            "ember-precision",
            "elf",
            "ember2024-elf",
            "ember2024-elf-rich",
            "ember2024-elf-precision",
        ],
    )
    fit.add_argument("dataset", type=Path)
    fit.add_argument("output", type=Path)
    fit.add_argument("--version", required=True)
    fit.add_argument("--provenance", required=True)
    cutoff = fit.add_mutually_exclusive_group()
    cutoff.add_argument("--threshold", type=float)
    cutoff.add_argument(
        "--validation-fpr", type=float, help="Tune threshold on validation data only"
    )
    fit.add_argument("--synthetic", action="store_true", help="Prevent promotion of fixture data")
    fit.add_argument("--anomaly", action="store_true")
    fit.add_argument("--threads", type=int, default=1, help="LightGBM training thread count")
    fit.add_argument("--min-accuracy", type=float, help="Minimum held-out accuracy for promotion")
    fit.add_argument("--min-recall", type=float, help="Minimum held-out recall for promotion")
    fit.add_argument(
        "--max-test-fpr", type=float, help="Exclusive held-out false-positive rate limit"
    )
    fit.add_argument(
        "--tune-low-fpr", action="store_true", help="Compare ELF fits on validation data"
    )
    install = commands.add_parser(
        "promote", help="Approve a trusted bundle after reviewing metrics"
    )
    install.add_argument("bundle", type=Path)
    install.add_argument("--model-dir", type=Path, default=default_root() / "models")
    args = parser.parse_args()
    try:
        if args.action == "train":
            manifest = train(
                args.dataset,
                args.adapter,
                args.output,
                version=args.version,
                provenance=args.provenance,
                synthetic=args.synthetic,
                threshold=args.threshold,
                validation_fpr=args.validation_fpr,
                anomaly=args.anomaly,
                threads=args.threads,
                min_accuracy=args.min_accuracy,
                min_recall=args.min_recall,
                max_test_fpr=args.max_test_fpr,
                tune_low_fpr=args.tune_low_fpr,
            )
            print(json.dumps(manifest["metrics"], indent=2))
        else:
            print(promote(args.bundle, args.model_dir))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, BadZipFile) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
