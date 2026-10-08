# Browser Sandbox — isolation model

One container = one browser session = one user profile. This directory builds
that container and defines the security boundary around Chromium and the Chrome
DevTools Protocol (CDP).

```
┌──────────────────────────── sandbox container (uid 1000) ────────────────────────────┐
│                                                                                       │
│  API (FastAPI, another container)                                                     │
│     │  HTTP/WS  ── Authorization: Bearer $CDP_GUARD_TOKEN                             │
│     ▼                                                                                 │
│  0.0.0.0:9222  cdp_guard.py      authenticate → path allow-list → origin policy       │
│     │                            → client cap → rewrite Host / webSocketDebuggerUrl   │
│     ▼                                                                                 │
│  127.0.0.1:9223  chromium --user-data-dir=/tmp/sandbox-profiles/$SESSION_ID           │
│                  (loopback only: unreachable from outside the container)              │
│                                                                                       │
│  /tmp                       tmpfs   session profiles, wiped on exit                   │
│  /home/sandbox/.cache       tmpfs   playwright/GPU/shader caches                      │
│  everything else            read-only image layer                                     │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

## Threat model

| Threat | Mitigation in this image |
|---|---|
| Anyone reaching `:9222` owns the browser (CDP has **no** auth) | `cdp_guard.py` requires a bearer token on every connection before a single byte reaches Chromium; Chromium itself listens on loopback only |
| Cookie / localStorage / credential leakage **between users** | Fresh `--user-data-dir` per `SESSION_ID`, mode `0700`, created at start and deleted at exit; the entrypoint **refuses** to start on a dirty profile (`PROFILE_REUSE=0`) |
| A rogue client spawning tabs / driving other targets | `/json/new`, `/json/close`, `/json/activate` are denied unless `CDP_GUARD_ALLOW_TARGET_MANAGEMENT=1` |
| Cross-site DevTools access from a browser page | `CDP_GUARD_ALLOWED_ORIGINS` allow-list + Chromium's `--remote-allow-origins` (now contained, since the port is loopback-only) |
| Renderer RCE ⇒ container escape ⇒ node | Non-root uid 1000, `cap_drop: ALL`, `no-new-privileges`, read-only root FS, seccomp/AppArmor, `pids_limit`, memory/CPU ceilings, and Chromium's own sandbox when user namespaces are available; gVisor/Kata recommended for untrusted traffic |
| Resource exhaustion (fork bombs, memory hogs, huge caches) | `pids_limit`, `mem_limit` (= `memswap_limit`, no swap), `ulimits`, `--renderer-process-limit`, `--js-flags=--max-old-space-size`, tmpfs size caps |
| Secrets/core dumps persisted on disk | `umask 077`, profiles on tmpfs, `ulimits.core=0`, tokens never logged (only SHA-256 prefixes) |
| Unbounded egress from a compromised page | `internal: true` network by default; `HOST_RESOLVER_RULES` / `PROXY_SERVER` for DNS-level or proxy-level allow-lists |

## Session isolation contract

1. The orchestrator picks a `SESSION_ID` (use the `graph_id`) and a fresh
   `CDP_GUARD_TOKEN` (`openssl rand -hex 32`) **per session**.
2. It starts the container with those two values and passes the same token to
   the API as `OMNIAGENT_BROWSER_SANDBOX_CDP_AUTH_TOKEN_TEMPLATE` (or
   `..._CDP_AUTH_TOKEN` for a single sandbox).
3. The API's Playwright client sends it as `Authorization: Bearer …` on both
   the `/json/version` probe and the DevTools WebSocket upgrade
   (`ScreencastStreamer` does this automatically — see `cdp_headers`).
4. When the session ends the container is **destroyed**, not reused: the
   profile is deleted on exit and a restart starts from an empty profile.

> Never mount a host volume at `/tmp/sandbox-profiles`. If you must persist a
> session (e.g. to keep a login alive between runs), give that profile its own
> per-tenant volume, set `PROFILE_EPHEMERAL=0`, and treat it as secret material
> (encrypted at rest, never shared between tenants).

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `SESSION_ID` / `GRAPH_ID` | random | Session identity; also the profile directory name (validated against `^[A-Za-z0-9_-]{1,64}$`) |
| `CDP_PORT` | `9222` | Public (guard) port |
| `CDP_INTERNAL_PORT` | `9223` | Chromium's loopback CDP port |
| `CDP_GUARD_ENABLED` | `1` | `0` only with `CDP_GUARD_ALLOW_ANONYMOUS=1` (dev) |
| `CDP_GUARD_TOKEN` | — | **Required.** Bearer token for every CDP connection |
| `CDP_GUARD_ALLOW_ANONYMOUS` | `0` | Dev escape hatch; logs loudly |
| `CDP_GUARD_ALLOWED_ORIGINS` | any | Comma-separated `Origin` allow-list for WS upgrades |
| `CDP_GUARD_ALLOW_TARGET_MANAGEMENT` | `0` | Allow `/json/new|close|activate` |
| `CDP_GUARD_MAX_CLIENTS` | `8` | Concurrent proxied connections |
| `CDP_GUARD_HEALTH_LOCALHOST_ONLY` | `1` | `/healthz`, `/readyz`, `/metrics` only from loopback |
| `CDP_GUARD_IDLE_TIMEOUT` | `0` | Close silent pipes after N seconds |
| `CDP_GUARD_ADVERTISED_HOST` | request `Host` | Value used when rewriting `webSocketDebuggerUrl` |
| `CHROME_USER_DATA_DIR` / `PROFILE_ROOT` | `/tmp/sandbox-profiles` | Profile root (should be tmpfs) |
| `PROFILE_EPHEMERAL` | `1` | Delete the profile on exit |
| `PROFILE_REUSE` | `0` | Refuse to start on a dirty profile |
| `CHROMIUM_SANDBOX` | `auto` | `auto` / `on` (fail closed) / `off` (loud warning) |
| `SANDBOX_ALLOW_NO_SANDBOX` | `0` | Permit the `--no-sandbox` fallback under `auto` |
| `HEADLESS` | `1` | `0` runs headed inside Xvfb |
| `VIEWPORT_WIDTH` / `VIEWPORT_HEIGHT` | `1280` / `720` | Window + X screen size |
| `MAX_RENDERER_PROCESSES` | unset | `--renderer-process-limit` |
| `MAX_JS_HEAP_MB` | unset | `--js-flags=--max-old-space-size=…` |
| `HOST_RESOLVER_RULES` | unset | DNS-level egress allow-list |
| `PROXY_SERVER` | unset | Forced egress proxy |
| `EXTRA_CHROME_ARGS` | unset | Extra whitespace-separated flags; isolation-critical flags are rejected |

## Enabling Chromium's own sandbox

`CHROMIUM_SANDBOX=on` requires unprivileged user namespaces:

```bash
# host
sysctl -w kernel.unprivileged_userns_clone=1     # Debian/Ubuntu
sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # Ubuntu 24.04+
```

Docker's **default seccomp profile blocks `clone(CLONE_NEWUSER)`**, so also run
with a profile that allows `clone`, `clone3` and `unshare` (start from Docker's
`profiles/seccomp/default.json` and add those syscalls), or run the container on
**gVisor / Kata / Firecracker**, where the VM boundary replaces both.

With `CHROMIUM_SANDBOX=auto` (default) the entrypoint probes user namespaces at
startup: if they work, Chromium's sandbox is enabled; if they do not, it starts
with `--no-sandbox` **only** when `SANDBOX_ALLOW_NO_SANDBOX=1`, and otherwise
refuses to start at all. Compose defaults this opt-out to `0` (fail closed), so
provide a reviewed user-namespace seccomp profile or a gVisor/Kata runtime
before deploying. Set the opt-out to `1` only after an explicit security review
accepts container-only isolation.

## Verification checklist

```bash
# 1. the guard requires a token
curl -s -o /dev/null -w '%{http_code}\n' http://sandbox:9222/json/version   # 401
curl -s -H "Authorization: Bearer $CDP_GUARD_TOKEN" \
     http://sandbox:9222/json/version | jq .webSocketDebuggerUrl            # rewritten to :9222

# 2. target management is denied
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $CDP_GUARD_TOKEN" \
     "http://sandbox:9222/json/new?about:blank"                             # 403

# 3. Chromium is not reachable directly
docker exec browser nc -z 127.0.0.1 9223 && echo "loopback only ✔"
nc -z <container-ip> 9223 || echo "not exposed ✔"

# 4. one profile per session, 0700, gone after exit
docker exec browser stat -c '%a %n' /tmp/sandbox-profiles/*                 # 700 …/SESSION_ID
docker rm -f browser && docker run --rm -v $PWD:/out … ls /tmp/sandbox-profiles

# 5. no caps, non-root, read-only
docker inspect browser --format '{{.HostConfig.CapDrop}} {{.Config.User}} {{.HostConfig.ReadonlyRootfs}}'
```

## Kubernetes

* `securityContext`: `runAsNonRoot: true`, `runAsUser: 1000`,
  `allowPrivilegeEscalation: false`, `capabilities: {drop: ["ALL"]}`,
  `seccompProfile: {type: RuntimeDefault}` (or `Localhost` with the userns
  profile), `readOnlyRootFilesystem: true`.
* `volumes`: `emptyDir {medium: Memory, sizeLimit: 2Gi}` on `/tmp`,
  `512Mi` on `/home/sandbox/.cache`, `1Gi` on `/dev/shm`.
* `NetworkPolicy`: allow ingress to `9222` **only** from the API's pods; deny
  all other ingress; egress via a proxy with a domain allow-list.
* One Pod per session, `restartPolicy: Never`, and delete the Pod when the
  graph run finishes — never recycle a Pod between tenants.
* `runtimeClassName: gvisor` (or Kata) for untrusted web traffic.
