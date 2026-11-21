FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        fonts-dejavu-core libegl1 libgl1 libgomp1 libxkbcommon-x11-0 \
        libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 libxcb-render-util0 \
        libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 novnc openbox \
        tigervnc-standalone-server tigervnc-tools websockify x11-utils \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 sentinel \
    && install -d -m 0700 -o sentinel -g sentinel /home/sentinel/.local/share/SentinelAI

WORKDIR /opt/sentinelai
COPY pyproject.toml README.md LICENSE ./
COPY app/ app/
RUN python -m pip install --no-cache-dir ".[ml]"
COPY docker/start-desktop.sh /usr/local/bin/start-desktop
RUN chmod 0755 /usr/local/bin/start-desktop

ENV HOME=/home/sentinel DISPLAY=:0 PYTHONUNBUFFERED=1
USER sentinel
ENTRYPOINT ["/usr/local/bin/start-desktop"]
