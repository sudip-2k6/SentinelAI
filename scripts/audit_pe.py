import argparse
import json
import subprocess
import sys
from pathlib import Path

from app.ml.model import blob


def _inspect(path: Path) -> dict:
    import lief

    data = blob(path, 16 * 1024 * 1024)
    if not data.startswith(b"MZ"):
        raise ValueError("The input is not a PE file.")
    lief.logging.disable()
    config = lief.PE.ParserConfig()
    config.parse_imports = False
    config.parse_rsrc = False
    config.parse_signature = False
    config.parse_exports = False
    config.parse_reloc = False
    binary = lief.PE.parse(data, config)
    if binary is None:
        raise ValueError("LIEF did not recognize a PE header.")
    return {
        "parser": str(lief.__version__),
        "machine": str(binary.header.machine),
        "sections": len(binary.sections),
        "entry_point_rva": int(binary.optional_header.addressof_entrypoint),
    }


def audit(path: Path) -> dict:
    command = [sys.executable, "-m", "scripts.audit_pe", "--worker", "--", str(path.absolute())]
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise OSError("The LIEF parser exceeded its time budget.") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr[:300].decode("utf-8", "replace").strip()
        raise ValueError(message or "The isolated LIEF helper could not parse this file.") from exc
    if len(completed.stdout) > 4096:
        raise ValueError("The LIEF helper returned excessive metadata.")
    return json.loads(completed.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description="Optional read-only LIEF PE header cross-check")
    parser.add_argument("path", type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        print(json.dumps((_inspect if args.worker else audit)(args.path), indent=2))
    except (OSError, ImportError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
