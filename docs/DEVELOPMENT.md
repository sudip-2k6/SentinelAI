# Development and distribution

Use CPython 3.12 or 3.13 in a virtual environment. The project pins direct dependencies in
`pyproject.toml`. Install the ML and build extras before packaging.

```bash
python -m pip install -e ".[dev,ml,build,audit]"
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest -q
```

UI and export tests use Qt's offscreen platform and generated inert inputs. Synthetic data
exercises the training interface, compatibility checks, and promotion restrictions.
On Windows, the symlink test skips if the account lacks symlink creation privileges.

## Windows packaging

Run on 64-bit Windows with the environment activated.

```powershell
.\scripts\build_windows.ps1 -SmokeTest
```

Distribute the complete `dist/SentinelAI` folder as a ZIP, or ship it with a signed installer
you produce for your organization. Open `SentinelAI.exe` inside the extracted folder. The
smoke test starts the packaged app offscreen, scans its own executable read-only, and looks
up the resulting fingerprint in a temporary SQLite history. The build script does not sign it.

## Linux packaging and AppImage

Run on the oldest distribution release and architecture you support. The Linux PyInstaller
build depends on the host system's glibc baseline. Validate on Ubuntu, Fedora, and Arch target
desktops, including opening the app and exercising file chooser, process, monitor, and
quarantine workflows. The Ubuntu CI job is configured to build and smoke-test its native artifact.

```bash
bash scripts/build_linux.sh --smoke-test
APPIMAGETOOL=/path/to/appimagetool bash scripts/build_appimage.sh
```

The AppImage script requires a trusted, independently installed `appimagetool`. Recent
versions can fetch a compatible AppImage runtime while building. For an offline build, use a
locally supplied tool/runtime combination according to its documentation.
AppImages are produced on Linux and may require FUSE on target systems. With a compatible
runtime, `APPIMAGE_EXTRACT_AND_RUN=1` can be used where FUSE is unavailable.
[AppImage tool and AppDir requirements](https://github.com/AppImage/appimagetool)
[PyInstaller operating system support](https://pyinstaller.org/en/stable/operating-mode.html)

## Local verification

Verification used Windows 11 x64 and Python 3.12. Source and packaged smoke checks used
Qt's offscreen platform. The tests covered inert file analysis, local history and reports,
quarantine and restoration, filesystem watching, process inspection, and synthetic model
training and explanations. The EMBER adapter accepted actual labeled feature rows from a
small read of the publisher's feature archive. Windows System event metadata was
inaccessible in the sandbox and the application returned its permission-limited status.

The project owner reported successful Windows 11 and Linux checks for the earlier
desktop build. Linux packaging scripts passed Bash syntax validation. The updated
Linux release, the AppImage, and Windows 10 still need native verification. The
included workflow provides Windows and Ubuntu validation when run on GitHub.

## Public releases

The MIT license covers SentinelAI's source. Dependencies, models, and datasets
have their own terms. The initial public release ships source. GitHub Actions
builds and smoke-tests the Windows and Linux desktop packages and checks the
Docker desktop.

Before publishing portable packages, include the relevant third-party notices
and exact corresponding source or applicable source offer for bundled Qt
components. For model bundles, confirm redistribution terms for the dataset
and model provenance. Attach reviewed packages and SHA-256 checksums to the
matching GitHub release.

[Qt open-source obligations](https://www.qt.io/development/open-source-lgpl-obligations) ·
[GitHub Releases](https://github.com/sudip-2k6/SentinelAI/releases)

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Qt can't initialize its display platform on Linux | Install the XCB, XKB, OpenGL and EGL runtime libraries for your distribution. Use `QT_DEBUG_PLUGINS=1` to identify missing plugin dependencies. |
| Model assessment unavailable | Inspect Model Insights. Install the ML extra for source mode, promote a matching bundle, and reload. Check the format, schema and digest in the error text. |
| Windows event log or Linux user journal unavailable | The current account may lack read access, or the OS service may be unavailable. Other scan functions remain available. |
| File can't be quarantined or restored | Confirm ownership, ensure the original directory is writable, and check for reparse points, open handles, and a same-filesystem private store. Review the manifest for integrity or recovery details. |
| Startup reports a data directory error | Close other instances. Check the local data directory permissions. Linux requires a user-owned 0700 root. If settings were manually edited, correct the invalid value in `settings.json`. |

For an optional second PE header opinion, install the `audit` extra and use
`python -m scripts.audit_pe /path/to/file.exe` within the source checkout. This helper
uses the pinned LIEF release in a subprocess and returns a bounded JSON summary.
[Official LIEF PE parser interface](https://lief.re/doc/stable/formats/pe/index.html)
