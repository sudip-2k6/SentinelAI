# Security and privacy

## Reading untrusted files

Static analysis opens regular files read-only and never invokes the scanned executable. The
scanner uses bounded byte reads, section ranges, import offsets, indicator counts, and worker
threads. Windows scans require fixed local volumes. Network shares, symbolic links, junctions,
reparse points, device paths, and alternate data streams are out of scope. Linux uses
directory handles with no-follow flags when reading the file. The application ordinarily
runs as a standard user.

Executable and imported report content never serves as a command, URL to open, or instruction.
Reports escape untrusted strings before rendering. Fields exported to HTML and PDF contain
file paths, fingerprints and other local metadata. Review reports before sharing them.

Native LightGBM model files are loaded only after local promotion and structural and digest
checks. Promote only trusted, reviewed bundles. The hash verifies consistency with the
manifest. Authentication of a package's author is the operator's responsibility.

The optional LIEF CLI uses a short-lived process and a timeout. The operating system still
grants the helper the current account's permissions. Analyze suspected live malware and
collect runtime traces in a dedicated, isolated analyst environment. Transfer only feature
tables or detached JSON reports to ordinary workstations. Keep OS security protections enabled.

## Quarantine and recovery

Quarantine is restricted to single-link user-owned regular files inside non-hidden,
non-protected home paths. Restore stays in the original directory and refuses to overwrite.
Moves require a common filesystem so isolation can use an atomic rename. Files are verified
against the SHA-256 scan record before isolation and against the manifest before restoration.
Isolation stores payloads in a private directory under opaque names. On Linux, payload mode is
0600 while isolated. On Windows, the DACL restricts payload access to the current SID and
LocalSystem. The recorded ordinary mode or Windows DACL is reapplied on restore.

The SQLite manifest records intent before a move. If a process is interrupted, startup
reconciles staging and restoring entries and checks the bytes before updating the manifest.
If validation or permission repair fails, the entry shows **Recovery required**; consult its
original path and destination. Preserve the manifest and payload while resolving the incident.
Neither failed scans nor confirmed quarantine automatically delete file data.

Moving an executable cannot undo prior execution, stop a running process, or invalidate all
previously opened handles. Files owned by another user, outside your profile, on another
filesystem, or held open by other software can be unavailable to quarantine.

## Local storage and monitoring

SQLite stores paths, hashes, scan metadata, model versions and explanations. Temporary
process and imported behavior results are held in memory. History retention removes old
records during startup and when settings are saved. Quarantine records are kept for recovery.
SQLite history cleanup is ordinary deletion and does not promise secure erasure.

Network uploads, telemetry and cloud sign-in are absent. Watchdog is a user-space signal and
events may be lost or coalesced because of quotas, inaccessible paths, high event volume,
or file changes between notification and scanning. The application shows drops it can
observe. It cannot enumerate protected processes or subscribe to privileged security
providers on an ordinary account. System event metadata is available only when the
current account can read the selected log.
