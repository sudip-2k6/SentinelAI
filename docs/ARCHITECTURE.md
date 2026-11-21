# Architecture

The Qt desktop calls application services from a bounded worker pool. The scanner opens only
regular local files, hashes the same bytes it parses, and returns typed records. PE and ELF
metadata parsers are separate from versioned inference features. The SQLite repository owns
history and the quarantine manifest. Model loading, operating system telemetry, and watchdog
monitoring are independent services.

Folder scans discover paths incrementally and dispatch small file batches to the configured
number of workers. Watched scans run in bounded batches and yield to manual scans. Settings
control the per-file byte budget, the worker count, and a per-worker duty target implemented
with cancellable pauses. The duty target is approximate and does not impose an OS-wide CPU quota.
History receives a single write stream per job. A loaded model serializes inference on its
native booster while allowing concurrent parsing.

Each model package includes a manifest, a LightGBM text model and optional Isolation Forest
trees encoded in JSON. The runtime checks the schema, package metadata and digest before
providing inference. Behavior import is a separate, descriptive pipeline. Files submitted
to any workflow remain data throughout.

## Milestones

1. Build the Qt shell, static scanner, history, and executable fixtures.
2. Add reproducible dataset adapters, held-out calibration and evaluation, model validation,
   and TreeSHAP explanations.
3. Add bounded monitoring, process inspection, quarantine, and reporting.
4. Add imported behavioral summaries, platform build scripts, CI, and operating documentation.
