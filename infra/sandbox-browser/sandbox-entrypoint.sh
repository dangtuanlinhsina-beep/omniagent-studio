#!/usr/bin/env bash
#
# OmniAgent Studio — Browser Sandbox entrypoint.
#
# Isolation model (see infra/sandbox-browser/README.md):
#
#   ┌─────────────────────────── container (uid 1000, no caps) ───────────┐
#   │  0.0.0.0:${CDP_PORT}          cdp_guard.py (bearer token, allow-list)│
#   │        │                                                            │
#   │        └──▶ 127.0.0.1:${CDP_INTERNAL_PORT}   chromium (--user-data-dir│
#   │                                                = per-session profile)│
#   └──────────────────────────────────────────────────────────────────────┘
#
#   * Chromium's DevTools port is **loopback-only**; the only way in from
#     another container is the guard, which requires a bearer token, applies a
#     path allow-list and enforces an Origin policy.
#   * Every session gets its own ``--user-data-dir`` (0700, created at start,
#     deleted at exit).  No cookies, localStorage, service workers, cached
#     credentials or HTTP auth caches ever cross a session boundary.
#   * The script refuses to run as root and refuses to start when the Chromium
#     sandbox cannot be enabled unless the operator explicitly accepts
#     ``--no-sandbox`` (fail closed).
set -euo pipefail

log()  { echo "[sandbox-browser] $*"; }
warn() { echo "[sandbox-browser] WARN: $*" >&2; }
die()  { echo "[sandbox-browser] FATAL: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Basic sanity
# ---------------------------------------------------------------------------

if [[ "$(id -u)" == "0" ]]; then
    die "refusing to run as root — the image ships a uid 1000 'sandbox' user; \
run the container with --user 1000:1000 (see docker-compose.sandbox.yml)"
fi

# Secrets (profile dirs, CDP token) must not be world-readable.
umask 077

CDP_PORT="${CDP_PORT:-9222}"
CDP_INTERNAL_PORT="${CDP_INTERNAL_PORT:-9223}"
CDP_GUARD_ENABLED="${CDP_GUARD_ENABLED:-1}"
#: Location of the guard (overridable for tests / custom image layouts).
CDP_GUARD_SCRIPT="${CDP_GUARD_SCRIPT:-/usr/local/bin/cdp_guard.py}"
if [[ "${CDP_GUARD_ENABLED}" == "1" && ! -r "${CDP_GUARD_SCRIPT}" ]]; then
    die "CDP guard script not found at ${CDP_GUARD_SCRIPT}"
fi
HEADLESS="${HEADLESS:-1}"
VIEWPORT_WIDTH="${VIEWPORT_WIDTH:-1280}"
VIEWPORT_HEIGHT="${VIEWPORT_HEIGHT:-720}"
PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/ms-playwright}"

if [[ "${CDP_PORT}" == "${CDP_INTERNAL_PORT}" ]]; then
    die "CDP_PORT and CDP_INTERNAL_PORT must differ (both are ${CDP_PORT})"
fi

# ---------------------------------------------------------------------------
# 1. Per-session browser profile (no cookie/session leakage between users)
# ---------------------------------------------------------------------------

#: Identity of *this* session. The orchestrator should pass the graph/run id so
#: profiles, logs and audit lines correlate.
SESSION_ID="${SESSION_ID:-${GRAPH_ID:-}}"
if [[ -n "${SESSION_ID}" && ! "${SESSION_ID}" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
    warn "SESSION_ID '${SESSION_ID}' contains unsafe characters; using a random id"
    SESSION_ID=""
fi
if [[ -z "${SESSION_ID}" ]]; then
    SESSION_ID="anon-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

#: Profile *root*. Defaults to /tmp (mount it as tmpfs — see the compose file)
#: so profiles never touch the container's writable layer or a shared volume.
PROFILE_ROOT="${CHROME_USER_DATA_DIR:-${PROFILE_ROOT:-/tmp/sandbox-profiles}}"
PROFILE_DIR="${PROFILE_ROOT}/${SESSION_ID}"
#: Delete the profile when the browser exits (default: yes).
PROFILE_EPHEMERAL="${PROFILE_EPHEMERAL:-1}"
#: Refuse to start on a dirty profile unless explicitly allowed.
PROFILE_REUSE="${PROFILE_REUSE:-0}"

mkdir -p "${PROFILE_ROOT}" || die "cannot create profile root ${PROFILE_ROOT}"
chmod 700 "${PROFILE_ROOT}" 2>/dev/null || true

if [[ -d "${PROFILE_DIR}" ]] && [[ -n "$(ls -A "${PROFILE_DIR}" 2>/dev/null)" ]]; then
    if [[ "${PROFILE_REUSE}" != "1" ]]; then
        die "profile ${PROFILE_DIR} already exists and is not empty — reusing a \
profile would leak cookies/storage into this session. Set PROFILE_REUSE=1 only \
if you really mean it (and never across tenants)."
    fi
    warn "reusing an existing profile at ${PROFILE_DIR} (PROFILE_REUSE=1)"
fi

mkdir -p "${PROFILE_DIR}" || die "cannot create profile ${PROFILE_DIR}"
chmod 700 "${PROFILE_DIR}" 2>/dev/null || true

if grep -qE "[[:space:]]${PROFILE_ROOT}[[:space:]]" /proc/mounts 2>/dev/null; then
    log "profile root ${PROFILE_ROOT} is a mount point (persistent storage)"
    if [[ "${PROFILE_EPHEMERAL}" == "1" ]]; then
        warn "PROFILE_EPHEMERAL=1 will delete the profile at exit even though \
${PROFILE_ROOT} is mounted — set PROFILE_EPHEMERAL=0 to keep sessions"
    fi
fi

cleanup() {
    local rc=$?
    if [[ "${PROFILE_EPHEMERAL}" == "1" && -d "${PROFILE_DIR}" ]]; then
        rm -rf "${PROFILE_DIR}" && log "removed session profile ${PROFILE_DIR}"
    fi
    exit "${rc}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 2. Chromium sandbox policy (fail closed)
# ---------------------------------------------------------------------------

#: ``auto`` (default) = enable Chromium's own sandbox when user namespaces work,
#: otherwise fall back to --no-sandbox **only** if SANDBOX_ALLOW_NO_SANDBOX=1.
#: ``on``  = require the real sandbox; die if it cannot be enabled.
#: ``off`` = always pass --no-sandbox (container-isolation-only; loud warning).
CHROMIUM_SANDBOX="${CHROMIUM_SANDBOX:-auto}"
SANDBOX_ALLOW_NO_SANDBOX="${SANDBOX_ALLOW_NO_SANDBOX:-0}"

userns_available() {
    # Chromium's setuid-less sandbox needs unprivileged user namespaces.
    if [[ -r /proc/sys/kernel/unprivileged_userns_clone ]] \
       && [[ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" == "0" ]]; then
        return 1
    fi
    if command -v unshare >/dev/null 2>&1; then
        unshare --user --pid --fork-proc true >/dev/null 2>&1 && return 0
        return 1
    fi
    return 1
}

USE_CHROMIUM_SANDBOX=0
case "${CHROMIUM_SANDBOX}" in
    on)
        if userns_available; then
            USE_CHROMIUM_SANDBOX=1
            log "chromium sandbox: ENABLED (user namespaces available)"
        else
            die "CHROMIUM_SANDBOX=on but unprivileged user namespaces are not \
available. Allow them (kernel.unprivileged_userns_clone=1 + a seccomp profile \
permitting clone/unshare/clone3) or run under gVisor/Kata."
        fi
        ;;
    off)
        warn "CHROMIUM_SANDBOX=off — running with --no-sandbox. A renderer RCE \
then equals a container escape unless the runtime is gVisor/Kata/Firecracker."
        ;;
    auto|*)
        if userns_available; then
            USE_CHROMIUM_SANDBOX=1
            log "chromium sandbox: ENABLED (auto-detected user namespaces)"
        elif [[ "${SANDBOX_ALLOW_NO_SANDBOX}" == "1" ]]; then
            warn "user namespaces unavailable; falling back to --no-sandbox \
(SANDBOX_ALLOW_NO_SANDBOX=1). Isolate this container at the runtime level."
        else
            die "cannot enable the Chromium sandbox (no unprivileged user \
namespaces) and SANDBOX_ALLOW_NO_SANDBOX is not set. Refusing to start a \
browser without any sandbox. Set CHROMIUM_SANDBOX=off + \
SANDBOX_ALLOW_NO_SANDBOX=1 to accept container-only isolation."
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# 3. Chromium launch flags
# ---------------------------------------------------------------------------

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
    die "could not locate a Chromium binary under ${PLAYWRIGHT_BROWSERS_PATH}"
}

CHROME="$(resolve_chrome_binary)"

#: Only the guard may reach Chromium, so a wildcard here is contained: the
#: DevTools port is loopback-only and the guard enforces the real Origin policy
#: (CDP_GUARD_ALLOWED_ORIGINS). Restrict it anyway if you prefer belt & braces.
CDP_ALLOWED_ORIGINS="${CDP_ALLOWED_ORIGINS:-*}"

CHROME_ARGS=(
    # Loopback ONLY — cdp_guard.py is the sole public entry point.
    --remote-debugging-port="${CDP_INTERNAL_PORT}"
    --remote-debugging-address=127.0.0.1
    "--remote-allow-origins=${CDP_ALLOWED_ORIGINS}"
    # Session-scoped profile (0700, created above, deleted on exit).
    --user-data-dir="${PROFILE_DIR}"
    --window-size="${VIEWPORT_WIDTH},${VIEWPORT_HEIGHT}"
    --no-first-run
    --no-default-browser-check
    # /dev/shm is 64KB by default in Docker; avoid renderer OOM crashes.
    --disable-dev-shm-usage
    --disable-gpu
    # Background tabs/pages must keep rendering for the screencast to work.
    --disable-background-timer-throttling
    --disable-backgrounding-occluded-windows
    --disable-renderer-backgrounding
    --hide-crash-restore-bubble
    --disable-session-crashed-bubble
    --mute-audio
    # ---- hardening: no Google services, no crash reporting, no extensions ----
    --disable-background-networking
    --disable-sync
    --disable-translate
    --disable-extensions
    --disable-component-update
    --disable-default-apps
    --disable-domain-reliability
    --disable-breakpad
    --disable-crash-reporter
    --no-service-autorun
    --no-pings
    --metrics-recording-only
    # Credentials must never land in an OS keychain inside a shared image.
    --password-store=basic
    --use-mock-keychain
    --disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider,InterestFeedContentSuggestions
    --lang="${CHROME_LANG:-en-US}"
)

if [[ "${USE_CHROMIUM_SANDBOX}" != "1" ]]; then
    CHROME_ARGS+=(--no-sandbox --disable-setuid-sandbox)
fi

# Optional resource ceilings (defense against a runaway page).
if [[ -n "${MAX_RENDERER_PROCESSES:-}" ]]; then
    CHROME_ARGS+=(--renderer-process-limit="${MAX_RENDERER_PROCESSES}")
fi
if [[ -n "${MAX_JS_HEAP_MB:-}" ]]; then
    CHROME_ARGS+=(--js-flags="--max-old-space-size=${MAX_JS_HEAP_MB}")
fi
# Optional egress policy: "MAP * ~NOTFOUND, EXCLUDE allow.example.com"
if [[ -n "${HOST_RESOLVER_RULES:-}" ]]; then
    CHROME_ARGS+=(--host-resolver-rules="${HOST_RESOLVER_RULES}")
fi
if [[ -n "${PROXY_SERVER:-}" ]]; then
    CHROME_ARGS+=(--proxy-server="${PROXY_SERVER}")
fi

# Parse extra flags as whitespace-separated words (never `eval` them), and
# reject any option that can bypass a core isolation boundary. Warning is not
# enough here: Chrome generally lets later duplicate flags win.
EXTRA_CHROME_ARGS_ARRAY=()
if [[ -n "${EXTRA_CHROME_ARGS:-}" ]]; then
    read -r -a EXTRA_CHROME_ARGS_ARRAY <<< "${EXTRA_CHROME_ARGS}"
    for arg in "${EXTRA_CHROME_ARGS_ARRAY[@]}"; do
        case "${arg}" in
            --user-data-dir|--user-data-dir=*|            --remote-debugging-port|--remote-debugging-port=*|            --remote-debugging-address|--remote-debugging-address=*|            --remote-allow-origins|--remote-allow-origins=*|            --no-sandbox|--disable-setuid-sandbox|--disable-sandbox)
                die "EXTRA_CHROME_ARGS contains isolation-critical flag ${arg}; configure the supported environment variable instead"
                ;;
        esac
    done
fi

# ---------------------------------------------------------------------------
# 4. Start the CDP guard + Chromium
# ---------------------------------------------------------------------------

CHROME_PID=""
GUARD_PID=""

stop_children() {
    local pid
    for pid in "${CHROME_PID:-}" "${GUARD_PID:-}"; do
        [[ -n "${pid}" ]] && kill -TERM "${pid}" 2>/dev/null || true
    done
}
trap 'stop_children' TERM INT

start_guard() {
    if [[ "${CDP_GUARD_ENABLED}" != "1" ]]; then
        warn "CDP_GUARD_ENABLED=0 — Chromium's DevTools port would be exposed \
unauthenticated; refusing unless CDP_GUARD_ALLOW_ANONYMOUS=1 is also set."
        if [[ "${CDP_GUARD_ALLOW_ANONYMOUS:-0}" != "1" ]]; then
            die "cannot disable the CDP guard without CDP_GUARD_ALLOW_ANONYMOUS=1"
        fi
        # Guard disabled *and* anonymous accepted: expose Chromium directly.
        CHROME_ARGS=( "${CHROME_ARGS[@]/--remote-debugging-address=127.0.0.1/--remote-debugging-address=0.0.0.0}" )
        CHROME_ARGS=( "${CHROME_ARGS[@]/--remote-debugging-port=${CDP_INTERNAL_PORT}/--remote-debugging-port=${CDP_PORT}}" )
        return 1
    fi
    if [[ -z "${CDP_GUARD_TOKEN:-}" && "${CDP_GUARD_ALLOW_ANONYMOUS:-0}" != "1" ]]; then
        die "CDP_GUARD_TOKEN is not set. The API sends it as \
OMNIAGENT_BROWSER_SANDBOX_CDP_AUTH_TOKEN[_TEMPLATE]; set CDP_GUARD_ALLOW_ANONYMOUS=1 \
for local development only."
    fi
    CDP_PORT="${CDP_PORT}" \
    CDP_INTERNAL_PORT="${CDP_INTERNAL_PORT}" \
    python3 "${CDP_GUARD_SCRIPT}" &
    GUARD_PID=$!
    log "cdp guard pid=${GUARD_PID} public=0.0.0.0:${CDP_PORT} upstream=127.0.0.1:${CDP_INTERNAL_PORT}"
    return 0
}

start_chrome() {
    if [[ "${HEADLESS}" == "1" ]]; then
        "${CHROME}" --headless=new "${CHROME_ARGS[@]}" "${EXTRA_CHROME_ARGS_ARRAY[@]}" about:blank &
    else
        # Headed mode inside Xvfb (better anti-bot fidelity; screencast identical).
        xvfb-run --auto-servernum \
            --server-args="-screen 0 ${VIEWPORT_WIDTH}x${VIEWPORT_HEIGHT}x24" \
            "${CHROME}" "${CHROME_ARGS[@]}" "${EXTRA_CHROME_ARGS_ARRAY[@]}" about:blank &
    fi
    CHROME_PID=$!
}

log "session=${SESSION_ID} chromium=${CHROME} headless=${HEADLESS} sandbox=$([[ ${USE_CHROMIUM_SANDBOX} == 1 ]] && echo chromium || echo none) \
profile=${PROFILE_DIR} viewport=${VIEWPORT_WIDTH}x${VIEWPORT_HEIGHT} cdp=${CDP_PORT}->${CDP_INTERNAL_PORT}"

start_guard || true
start_chrome
log "chromium pid=${CHROME_PID}"

# Wait for whichever child dies first, then take the other one down with it so
# the container exits and the orchestrator restarts a *clean* sandbox.
wait -n "${CHROME_PID}" "${GUARD_PID:-${CHROME_PID}}" 2>/dev/null || true
if [[ -n "${CHROME_PID}" ]] && ! kill -0 "${CHROME_PID}" 2>/dev/null; then
    wait "${CHROME_PID}" 2>/dev/null || true
    log "chromium exited; shutting down"
elif [[ -n "${GUARD_PID}" ]] && ! kill -0 "${GUARD_PID}" 2>/dev/null; then
    log "cdp guard exited; shutting down"
fi
stop_children
sleep 1
# Anything still alive gets SIGKILL (the EXIT trap wipes the profile).
for pid in "${CHROME_PID:-}" "${GUARD_PID:-}"; do
    [[ -n "${pid}" ]] && kill -KILL "${pid}" 2>/dev/null || true
done
