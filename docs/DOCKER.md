# Run SentinelAI with Docker

Docker Compose runs the Linux desktop and serves its display through noVNC.
Use a current Docker Engine with the Compose plugin or Docker Desktop in Linux
container mode. The first build downloads the base image and dependencies.

```sh
git clone https://github.com/sudip-2k6/SentinelAI.git
cd SentinelAI
docker compose up --build --detach --wait
docker compose exec -T sentinelai cat /tmp/sentinel-desktop/password
```

Open [the local desktop](http://127.0.0.1:6080/vnc.html?resize=scale), click
**Connect**, and enter the terminal password. The container generates a new
password on each start. Keep the browser port on loopback.

Place files in the `samples` directory next to `compose.yaml`. Choose
**Folder Scan**, then `/samples`. The container user needs read permission.
Both Windows PE and Linux ELF files can be inspected through this read-only mount.
Use the native app to quarantine host files, inspect host processes, or read
host system events.

The `sentinel-data` volume stores history, settings, and any installed models.
The container starts in static-analysis mode. To install trusted compatible
packages, copy their `models` directory into the data volume and select
**Reload local models** in **Models**.

```sh
docker compose cp ./models sentinelai:/home/sentinel/.local/share/SentinelAI/
```

If the copied files have restrictive permissions, make them readable by the
container user (UID 10001). See [model setup and provenance](DATASETS.md).
For exports, save to a path inside the container and copy the file out, for
example `docker compose cp sentinelai:/tmp/report.pdf .`.

Stop the desktop with `docker compose down`. The named volume remains available.
If the desktop does not load, check `docker compose ps` and
`docker compose logs sentinelai`. If port 6080 is in use, change the host port
in `compose.yaml` and open the matching loopback URL.
