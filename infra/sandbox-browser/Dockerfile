# syntax=docker/dockerfile:1.7
#
# ---------------------------------------------------------------------------
# OmniAgent Studio — Browser Sandbox
#
# Rootless Chromium exposed over the Chrome DevTools Protocol (CDP) so the
# API (apps/api) can attach with Playwright `connect_over_cdp()`, stream the
# screen via `Page.startScreencast` and dispatch human-takeover input via
# `Input.dispatch*Event`.
#
# ffmpeg is included so the sandbox can additionally record sessions
# (e.g. pipe screencast frames / `Page.startScreencast` output to a file).
#
# Build:
#   docker build -t omniagent/sandbox-browser:latest infra/sandbox-browser/
#
# Run (per-graph sandbox, CDP on 9222):
#   docker run -d --name browser-<graph_id> \
#       --shm-size=1g \
#       -p 9222:9222 \
#       -e HEADLESS=1 -e VIEWPORT_WIDTH=1280 -e VIEWPORT_HEIGHT=720 \
#       omniagent/sandbox-browser:latest
#
# Security notes:
#   * The container runs as an unprivileged user ("sandbox", uid 1000).
#     Chromium's setuid sandbox cannot work without CAP_SYS_ADMIN /
#     unprivileged user namespaces, so we pass --no-sandbox. In production,
#     isolate this container with gVisor/Kata or a strict seccomp profile and
#     NEVER expose port 9222 outside the trusted cluster network.
#   * --shm-size=1g (or --disable-dev-shm-usage, already set) is required to
#     avoid renderer crashes under memory pressure.
# ---------------------------------------------------------------------------

ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim AS sandbox-browser

# Keep in sync with the playwright pin in apps/api/pyproject.toml so the CDP
# wire protocol versions always match on both sides.
ARG PLAYWRIGHT_VERSION=1.63.0

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Base tooling:
#   dumb-init : PID 1 signal forwarding / zombie reaping
#   ffmpeg    : session recording / frame transcoding
#   xvfb+xauth: optional headed mode (HEADLESS=0) for anti-bot fidelity
#   procps    : debugging (ps/top) inside the sandbox
#   fonts     : sane glyph coverage incl. emoji
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        dumb-init \
        ffmpeg \
        fonts-dejavu-core \
        fonts-liberation \
        fonts-noto-color-emoji \
        fonts-unifont \
        procps \
        xauth \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "playwright==${PLAYWRIGHT_VERSION}"

# Installs the full Chromium build (supports --headless=new, required for
# screencast) plus every system library Chromium needs on Debian slim.
RUN playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user.
RUN groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid sandbox --shell /bin/bash --create-home sandbox \
    && mkdir -p /home/sandbox/chrome-data /home/sandbox/.cache \
    && chown -R sandbox:sandbox /home/sandbox /ms-playwright

COPY sandbox-entrypoint.sh /usr/local/bin/sandbox-entrypoint.sh
RUN chmod 0755 /usr/local/bin/sandbox-entrypoint.sh

# Runtime configuration (overridable via -e / compose environment).
ENV CDP_PORT=9222 \
    HEADLESS=1 \
    VIEWPORT_WIDTH=1280 \
    VIEWPORT_HEIGHT=720 \
    CHROME_USER_DATA_DIR=/home/sandbox/chrome-data \
    CHROME_LANG=en-US

USER sandbox
WORKDIR /home/sandbox

EXPOSE 9222

# CDP /json/version responds as soon as the browser accepts connections.
HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=3 \
    CMD python3 -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('CDP_PORT', '9222') + '/json/version', timeout=4)"

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/local/bin/sandbox-entrypoint.sh"]
