# syntax=docker/dockerfile:1.7
#
# ---------------------------------------------------------------------------
# OmniAgent Studio — Browser Sandbox
#
# Chromium + a token-authenticating CDP guard, exposed over the Chrome DevTools
# Protocol so the API (apps/api) can attach with Playwright
# `connect_over_cdp()`, stream the screen via `Page.startScreencast` and
# dispatch human-takeover input via `Input.dispatch*Event`.
#
# ffmpeg is included so the sandbox can additionally record sessions.
#
# Build:
#   docker build -t omniagent/sandbox-browser:latest infra/sandbox-browser/
#
# Run (one container == one session == one browser profile):
#   docker run -d --name browser-<graph_id> \
#       --user 1000:1000 \
#       --cap-drop=ALL --security-opt=no-new-privileges:true \
#       --read-only \
#       --tmpfs /tmp:size=2g,mode=1777 \
#       --tmpfs /home/sandbox/.cache:size=512m,mode=0700,uid=1000,gid=1000 \
#       --shm-size=1g \
#       --memory=2g --cpus=2 --pids-limit=256 \
#       -e SESSION_ID=<graph_id> \
#       -e CDP_GUARD_TOKEN=<per-session-secret> \
#       -e HEADLESS=1 -e VIEWPORT_WIDTH=1280 -e VIEWPORT_HEIGHT=720 \
#       omniagent/sandbox-browser:latest
#
#   # the API then connects with:
#   #   OMNIAGENT_BROWSER_SANDBOX_CDP_URL=http://browser-<graph_id>:9222
#   #   OMNIAGENT_BROWSER_SANDBOX_CDP_AUTH_TOKEN=<per-session-secret>
#
# Never publish port 9222 on a public interface: the guard requires a bearer
# token, but network reachability is the first line of defence. Use
# `infra/docker-compose.sandbox.yml` (internal network, no published ports) or
# a Kubernetes NetworkPolicy that only allows the API to reach 9222.
#
# ---------------------------------------------------------------------------
# Isolation notes
# ---------------------------------------------------------------------------
# * Runs as the unprivileged user `sandbox` (uid/gid 1000); the entrypoint
#   *refuses* to run as root.
# * Chromium's own sandbox is enabled whenever unprivileged user namespaces
#   are available (CHROMIUM_SANDBOX=auto). Without them the container must be
#   isolated by the runtime (gVisor/Kata/Firecracker) or by an explicit,
#   audited opt-out (CHROMIUM_SANDBOX=off + SANDBOX_ALLOW_NO_SANDBOX=1).
#   Docker's *default* seccomp profile blocks clone(CLONE_NEWUSER), so to use
#   real Chromium sandbox, supply a reviewed profile that allows the required
#   clone/clone3/unshare syscalls or use a gVisor/Kata runtime. Do not use
#   seccomp=unconfined on a conventional runc host.
# * One `--user-data-dir` per session, created 0700 at start and deleted at
#   exit — cookies, localStorage, IndexedDB, service workers, HTTP auth caches
#   and the GPU/cache dirs never cross a session (or tenant) boundary.
# * The container is `--read-only` friendly: everything writable lives under
#   /tmp and /home/sandbox/.cache, both of which should be tmpfs.
# * `--shm-size=1g` (or the already-set --disable-dev-shm-usage) avoids
#   renderer crashes under memory pressure.
# ---------------------------------------------------------------------------

ARG PYTHON_VERSION=3.11
# Pin by digest in production for reproducible, auditable builds, e.g.
#   FROM python:3.11-slim@sha256:<digest> AS sandbox-browser
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
#   util-linux: `unshare` — the entrypoint probes user namespaces with it
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
        util-linux \
        xauth \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "playwright==${PLAYWRIGHT_VERSION}"

# Installs the full Chromium build (supports --headless=new, required for
# screencast) plus every system library Chromium needs on Debian slim.
RUN playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user + writable, session-scoped directories.
RUN groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid sandbox --shell /bin/bash --create-home sandbox \
    && mkdir -p /tmp/sandbox-profiles /home/sandbox/.cache \
    && chmod 0700 /tmp/sandbox-profiles /home/sandbox/.cache \
    && chown -R sandbox:sandbox /home/sandbox /tmp/sandbox-profiles /ms-playwright

COPY sandbox-entrypoint.sh /usr/local/bin/sandbox-entrypoint.sh
COPY cdp_guard.py /usr/local/bin/cdp_guard.py
RUN chmod 0755 /usr/local/bin/sandbox-entrypoint.sh /usr/local/bin/cdp_guard.py

# Runtime configuration (overridable via -e / compose environment).
ENV CDP_PORT=9222 \
    CDP_INTERNAL_PORT=9223 \
    CDP_GUARD_ENABLED=1 \
    CDP_GUARD_MAX_CLIENTS=8 \
    CDP_GUARD_HEALTH_LOCALHOST_ONLY=1 \
    HEADLESS=1 \
    VIEWPORT_WIDTH=1280 \
    VIEWPORT_HEIGHT=720 \
    CHROME_USER_DATA_DIR=/tmp/sandbox-profiles \
    PROFILE_EPHEMERAL=1 \
    PROFILE_REUSE=0 \
    CHROMIUM_SANDBOX=auto \
    SANDBOX_ALLOW_NO_SANDBOX=0 \
    CHROME_LANG=en-US

USER sandbox
WORKDIR /home/sandbox

EXPOSE 9222

STOPSIGNAL SIGTERM

# The guard answers /healthz from loopback without a token; a 200 means the
# proxy is up. Chromium readiness is checked through it as well.
HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=3 \
    CMD python3 -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('CDP_PORT', '9222') + '/healthz', timeout=4)"

LABEL org.opencontainers.image.title="omniagent-sandbox-browser" \
      org.opencontainers.image.description="Isolated Chromium + authenticated CDP guard for OmniAgent Studio" \
      org.opencontainers.image.source="https://github.com/dangtuanlinhsina-beep/omniagent-studio" \
      org.opencontainers.image.licenses="MIT" \
      dev.omniagent.security.run-as-non-root="true" \
      dev.omniagent.security.cdp-authenticated="true" \
      dev.omniagent.security.profile-per-session="true"

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/local/bin/sandbox-entrypoint.sh"]
