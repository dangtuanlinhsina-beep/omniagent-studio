#!/usr/bin/env bash
#
# OmniAgent Studio — Browser Sandbox entrypoint.
#
# Launches a rootless Chromium with the CDP endpoint listening on
# 0.0.0.0:${CDP_PORT}. Runs as the unprivileged "sandbox" user; Chromium's
# own sandbox is disabled (container isolation — see Dockerfile notes).
set -euo pipefail

CDP_PORT="${CDP_PORT:-9222}"
HEADLESS="${HEADLESS:-1}"
VIEWPORT_WIDTH="${VIEWPORT_WIDTH:-1280}"
VIEWPORT_HEIGHT="${VIEWPORT_HEIGHT:-720}"
CHROME_USER_DATA_DIR="${CHROME_USER_DATA_DIR:-/home/sandbox/chrome-data}"
PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/ms-playwright}"

resolve_chrome_binary() {
    # 1) Explicit override.
    if [[ -n "${CHROME_BIN:-}" ]]; then
        echo "${CHROME_BIN}"
        return 0
    fi
    # 2) Ask Playwright for the exact binary it installed (version-safe).
    local bin=""
    bin="$(python3 - <<'PY' 2>/dev/null || true
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    print(p.chromium.executable_path)
PY
)"
    if [[ -n "${bin}" && -x "${bin}" ]]; then
        echo "${bin}"
        return 0
    fi
    # 3) Fallback: scan the browser registry directory.
    bin="$(find "${PLAYWRIGHT_BROWSERS_PATH}" -type f -name chrome \
        -path '*/chromium-*/chrome-linux*/chrome' 2>/dev/null | sort -V | tail -n 1)"
    if [[ -n "${bin}" ]]; then
        echo "${bin}"
        return 0
    fi
    echo "FATAL: could not locate a Chromium binary under ${PLAYWRIGHT_BROWSERS_PATH}" >&2
    exit 1
}

CHROME="$(resolve_chrome_binary)"
mkdir -p "${CHROME_USER_DATA_DIR}"

CHROME_ARGS=(
    --remote-debugging-port="${CDP_PORT}"
    --remote-debugging-address=0.0.0.0
    # Chromium >= 111 rejects DevTools WS handshakes without a known Origin
    # unless this is set. Restrict it if the sandbox network is not trusted.
    "--remote-allow-origins=*"
    --user-data-dir="${CHROME_USER_DATA_DIR}"
    --window-size="${VIEWPORT_WIDTH},${VIEWPORT_HEIGHT}"
    --no-first-run
    --no-default-browser-check
    # Container runs unprivileged: no setuid sandbox, no user namespaces.
    --no-sandbox
    --disable-setuid-sandbox
    # /dev/shm is 64KB by default in Docker; avoid renderer OOM crashes.
    --disable-dev-shm-usage
    --disable-gpu
    # Background tabs/pages must keep rendering for the screencast to work.
    --disable-background-timer-throttling
    --disable-backgrounding-occluded-windows
    --disable-renderer-backgrounding
    --hide-crash-restore-bubble
    --mute-audio
    --password-store=basic
    --lang="${CHROME_LANG:-en-US}"
)

echo "[sandbox-browser] chromium=${CHROME} headless=${HEADLESS} cdp=0.0.0.0:${CDP_PORT} viewport=${VIEWPORT_WIDTH}x${VIEWPORT_HEIGHT}"

# EXTRA_CHROME_ARGS is intentionally word-split to allow extra flags via env.
if [[ "${HEADLESS}" == "1" ]]; then
    # shellcheck disable=SC2086
    exec "${CHROME}" --headless=new "${CHROME_ARGS[@]}" ${EXTRA_CHROME_ARGS:-} about:blank
else
    # Headed mode inside Xvfb (better anti-bot fidelity; screencast identical).
    # shellcheck disable=SC2086
    exec xvfb-run --auto-servernum \
        --server-args="-screen 0 ${VIEWPORT_WIDTH}x${VIEWPORT_HEIGHT}x24" \
        "${CHROME}" "${CHROME_ARGS[@]}" ${EXTRA_CHROME_ARGS:-} about:blank
fi
