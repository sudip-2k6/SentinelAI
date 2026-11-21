# Datasets and reproducible training

## Windows PE

Obtain Elastic's published **EMBER 2018 feature archive** separately and extract it into a
directory with the raw `train_features_*.jsonl` and `test_features.jsonl` files. SentinelAI
accepts the documented raw feature schema, skips unlabeled `-1` rows, and projects
`general.size` and the normalized 256-bin `histogram` into 257 model inputs. The runtime
computes the same counts directly from file bytes under a separately versioned schema.
It does not load a standard EMBER 2,381-dimensional model. The projection avoids relying
on historical LIEF binary compatibility. The chronological split aims to train on
80% of the labeled training records while keeping whole months together. Use only
official test rows that postdate calibration and record how many
overlapping test rows were excluded. Exact SHA-256 and
float32 vector duplicates are removed across splits. The full benchmark can require several GB
of RAM during training. [Elastic EMBER dataset and feature definitions](https://github.com/elastic/ember)

## Linux ELF

The `ember2024-elf` adapter reads the authors' `ELF_train.zip` and `ELF_test.zip` from the
same directory. Keep both archives intact. The release uses revision
`9cce319e0a152cd8dfc276b6dea24f7c831df86a`. The ELF model uses a distinct schema,
`elf-ember-histogram-v1`, with file size and normalized byte counts computed identically
from scanned ELF bytes. Training and calibration use the official training archive,
split by UTC submission week. Evaluation uses the official later test archive. Exact
hash and projected-vector duplicates are excluded across splits. [Published feature archives](https://huggingface.co/datasets/joyce8/EMBER2024/tree/9cce319e0a152cd8dfc276b6dea24f7c831df86a)

| Archive | SHA-256 for the release inputs |
| --- | --- |
| `ELF_train.zip` | `3385e7c5089f04c46d42ecac8361c6d5141d4b76ba8343c06282430b21e2b06f` |
| `ELF_test.zip` | `f7449414e4993df34604b4efb64ae92c6844daafd607cb5002fb98e612bed002` |

For a custom structural ELF model, use the `elf` adapter.
Prepare one UTF-8 JSON object per line. Each row must include a lowercase SHA-256, `label`
(0 for benign or 1 for malicious), a stable `group`, and the exact `schema` string
`elf-static-v1`. Set `features` to the ordered numeric vector defined in `app/ml/schema.py`
or to an object keyed by those exact feature names. Derive the vectors with
`app.features.elf.parse` and `app.ml.schema.extract` from a trusted offline feature pipeline.
The groups should keep related samples, families, builds, or same-collection variants
together to reduce leakage. Include at least five independent groups and both classes.
The trainer requires at least five rows of each class in every partition. Use dated,
independently sourced held-out data for acceptance before relying on generalization.

## Train and promote

The 0.1.2 adapters add local byte entropy and printable string statistics for both formats.
PE also includes data directory fields, optional header fields, section statistics, and
bounded import summaries. The PE archive uses LIEF to describe structures and the local
scanner uses pefile, so unusual or malformed files may produce different features.
[EMBER 2018 features](https://github.com/elastic/ember/blob/master/ember/features.py)
[EMBER2024 features](https://github.com/FutureComputing4AI/EMBER2024/blob/main/src/thrember/features.py)

Build candidates with a minimum held-out accuracy of 94%.

```bash
python -m scripts.train_model train ember-rich /data/ember2018 models/pe-candidate --version pe-ember2018-002 --provenance "Elastic EMBER 2018 feature archive" --min-accuracy 0.94 --anomaly --threads 8
python -m scripts.train_model train ember2024-elf-rich /data/ember2024 models/elf-candidate --version elf-ember2024-002 --provenance "EMBER2024 official ELF archives" --min-accuracy 0.94 --anomaly --threads 4
```

The richer adapters stop boosting based on calibration-set log loss. With
`--min-accuracy` and the default threshold settings, the alert cutoff maximizes
accuracy on calibration data. Promotion computes accuracy from the later test
confusion matrix and rejects candidates below the requested minimum.

For a lower false-positive rate, the precision adapters add wider PE import and
section features and expanded ELF string markers. The training criterion is
mean validation recall at 0.8% and 1.5% validation false-positive rates. The
primary alert cutoff uses the 0.8% budget, with a 1.5% operating point recorded
separately for comparison. `--tune-low-fpr` compares four ELF fits using the
same validation criterion. Both operating points are decided before the later
test metrics are computed. The measured later false-positive rate can exceed
the validation budget.

```bash
python -m scripts.train_model train ember-precision /data/ember2018 models/pe-precision --version pe-ember2018-003 --provenance "Elastic EMBER 2018 feature archive" --validation-fpr 0.008 --max-test-fpr 0.02 --min-accuracy .946134 --min-recall .962504 --threads 8
python -m scripts.train_model train ember2024-elf-precision /data/ember2024 models/elf-precision --version elf-ember2024-004 --provenance "EMBER2024 official ELF archives" --validation-fpr 0.008 --max-test-fpr 0.02 --min-accuracy .942051 --min-recall .958653 --tune-low-fpr --threads 3
```

These commands require higher accuracy and recall than the 0.1.2 benchmarks
and a held-out false-positive rate strictly below 2% before promotion.

From the checkout with the virtual environment activated, run the following commands.
Use the adapter for the feature archive or custom dataset you have available.

```bash
python -m pip install -e ".[ml]"
python -m scripts.train_model train ember /data/ember2018 models/pe-candidate --version pe-001 --provenance "EMBER 2018 feature archive" --validation-fpr 0.01 --anomaly --threads 4
python -m scripts.train_model train ember2024-elf /data/ember2024 models/elf-candidate --version elf-001 --provenance "EMBER2024 official ELF archives" --validation-fpr 0.01 --anomaly
python -m scripts.train_model train elf /data/elf-features.jsonl models/elf-candidate --version elf-001 --provenance "Describe collection sources and label revision" --anomaly
```

The trainer uses a fixed split seed, a deterministic CPU LightGBM fit, a separate
validation partition for Platt calibration, and a held-out test partition for metrics.
Set `--validation-fpr` to choose an alert threshold using validation negatives. The
observed false-positive rate on the later test set can differ from that target.
Isolation Forest is optional. Its percentile uses held-out benign rows as a reference and
requires enough benign training and validation samples. Mark fixture runs with
`--synthetic`; SentinelAI prevents promotion of those bundles.

Record archive hashes, provenance, and split criteria. Review candidate metrics and check
them against the expected deployment population before promoting a trusted bundle.

```bash
python -m scripts.train_model promote models/pe-candidate
python -m scripts.train_model promote models/elf-candidate
```

Use **Reload local models** in **Model Insights**. Promotion refuses to overwrite an
active package. To replace one, close the app, move the prior format directory out of
the local models folder, and promote the replacement. Model artifacts are versioned
LightGBM text plus a JSON manifest. Serialized Python objects are unnecessary.

## Install the release models

[Download the approved PE and ELF models](https://github.com/sudip-2k6/SentinelAI/releases/download/v0.1.9/SentinelAI-0.1.2-models.zip).
The ZIP contains one approved package for each format. The public Windows installer
includes the inference runtime. Open SentinelAI once to create its application data
directory, then close it. Extract the model ZIP into that directory so `models/pe` and
`models/elf` are next to the settings and history. Keep any existing packages by moving
them to a separate folder before installing these versions.

| Platform | Default extraction directory |
| --- | --- |
| Windows | `%LOCALAPPDATA%\SentinelAI` |
| Linux | `${XDG_DATA_HOME:-$HOME/.local/share}/SentinelAI` |

Open SentinelAI, go to **Models**, and select **Reload local models**. The Dashboard
shows the formats that loaded. A new scan is required to produce scores for files
scanned before the models were loaded.

The [Windows release page](https://github.com/sudip-2k6/SentinelAI/releases/tag/v0.1.9)
also includes a model checksum and the older 0.1.1 bundle for reproducing previous
results. Install one bundle at a time.

## Behavioral reports and future training

Import a normalized JSON report from **Process Monitor**. Use schema
`sentinel-behavior-v1` and an ordered `events` array. Each event needs relative
`time_ms`, an unsigned `pid`, and a `category` from `process`, `thread`, `file`,
`registry`, `network`, `memory`, `service`, `synchronization`, or `other`.
The importer supports inline CAPE/Cuckoo-style `behavior.processes[].calls[].category`
as a convenience. It ignores raw arguments and limits reports to 8 MiB and 25,000 events.
The synthetic test report is in `tests/fixtures/synthetic-behavior.json`.

A future sequence model needs labeled benign and malicious traces from isolated,
instrumented environments. Record sandbox and agent version, guest OS, collection date,
truncation, process grouping, and the sample hash. Keep families, hashes, and closely
related builds in the same partition, separate sandbox and holdout environment where
possible, and report missing telemetry and sequence truncation. Retain normalized
categories and relative timestamps with sensitive arguments removed. Imported traces are
descriptive data and may omit behavior or include ordinary environment noise.
