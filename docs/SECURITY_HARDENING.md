# Báo cáo hardening bảo mật OmniAgent Studio

**Phạm vi:** WebSocket FastAPI/RBAC, cô lập Chromium/CDP, và tích hợp xác thực Next.js ↔ FastAPI.

**Ngày rà soát:** 07-10-2026
**Trạng thái:** mã nguồn hardening đã áp dụng trên nhánh hiện tại; các giới hạn triển khai production được liệt kê ở cuối báo cáo.

---

## 1. Tóm tắt điều hành

Trước thay đổi, WebSocket stream có thể chấp nhận kết nối mà không có danh tính đáng tin cậy khi static token chưa cấu hình; phân quyền theo `graph_id` chưa chặt; browser input và việc chiếm quyền chưa có quota đủ để chống lạm dụng; CDP có thể bị lộ trực tiếp; profile Chrome dùng chung có nguy cơ làm lẫn cookie giữa các session.

Bản hardening bổ sung:

- JWT access/refresh và JWT ticket WebSocket ngắn hạn, dùng một lần, bind theo graph; role và quyền được kiểm tra ở cả handshake, mỗi input, takeover lease và luồng outbound.
- Giới hạn kết nối, kích thước payload, thời gian nhàn rỗi/vòng đời, handshake, input, control và tổng quota theo graph; coalesce `mouseMoved` trước khi gọi CDP.
- BFF Next.js lưu access/refresh JWT trong cookie `httpOnly`; browser không đọc được hai JWT này. Chỉ ticket WebSocket graph-bound được đưa vào `Sec-WebSocket-Protocol`.
- Sandbox chạy non-root, profile `0700` riêng theo session trên `tmpfs`, CDP chỉ nghe loopback phía Chromium và được bảo vệ bởi proxy bearer-token; Docker Compose bỏ publish port, read-only root filesystem, drop capabilities, giới hạn tài nguyên, network nội bộ mặc định.
- Thêm login UI, auth API routes, stream client/hook cho React Flow, security headers, schema Prisma tham khảo và báo cáo cấu hình production.

### Ma trận quyền

| Hành động | VIEWER | OPERATOR | ADMIN |
|---|:---:|:---:|:---:|
| Xem `SCREEN_FRAME` | ✅ | ✅ | ✅ |
| Gửi `MOUSE_EVENT` / `KEYBOARD_EVENT` | ❌ | ✅, cần takeover lease | ✅, cần takeover lease |
| Gửi `SET_TAKEOVER` | ❌ | ✅ | ✅ |
| Quản lý graph / đọc audit | ❌ | ❌ | ✅ |
| Nhận `TAKEOVER_STATE` | ❌ | ✅ | ✅ |

`VIEWER` là read-only: stream có thể kèm các envelope tối thiểu của giao thức như `SESSION_READY`, `PONG`, lỗi và trạng thái stream để client kết nối/duy trì phiên; không được nhận `TAKEOVER_STATE` và không được điều khiển browser. Quyền thật luôn được enforce ở API — UI không phải ranh giới bảo mật.

---

## 2. Rủi ro ban đầu và cách khắc phục

| Khu vực | Rủi ro trước hardening | Bản sửa |
|---|---|---|
| WebSocket auth | Static token dùng chung; cấu hình trống có thể tạo luồng không có identity/expiry/revocation phù hợp | JWT `access`/`refresh`/`ws-ticket`, kiểm tra type, issuer, audience, expiry, `jti`, graph claim và replay; legacy token bị tắt mặc định |
| Handshake | Có thể accept socket trước khi hoàn tất kiểm tra credential; dễ tốn tài nguyên cho caller không hợp lệ | `routes_stream.py` chạy origin/rate/graph/credential preflight trước `accept()` khi cấu hình `api_ws_reject_before_accept=true` |
| Object-level access | `graph_id` là input do client chọn, tạo nguy cơ IDOR | Regex allow-list cho graph id và authorizer kiểm tra `gph` claim; endpoint ticket chỉ cấp ticket cho graph caller có quyền |
| Input/RBAC | Một VIEWER có thể thử gửi input/takeover hoặc làm quá tải CDP | Choke point kiểm tra permission, lease và token bucket trước dispatch; viewer outbound filter chặn takeover state |
| WebSocket DoS | Thiếu giới hạn đầy đủ về kích thước message, idle, lifetime, số kết nối và spam input | Giới hạn payload, connection caps, handshake limiter, per-message buckets, graph aggregate bucket, strike limit và watchdog |
| CDP | Chromium DevTools Protocol không có auth mặc định; bind `0.0.0.0` làm tăng khả năng chiếm browser | `cdp_guard.py` yêu cầu bearer token; Chromium chỉ bind `127.0.0.1` trên port nội bộ riêng; guard chỉ expose port CDP đã xác thực |
| Cookie giữa session | `--user-data-dir` cố định có thể giữ cookie/localStorage từ người dùng trước | `--user-data-dir=/tmp/sandbox-profiles/$SESSION_ID`, thư mục `0700`, từ chối reuse profile bẩn và xóa profile ephemeral khi tiến trình dừng |
| BFF | Token nằm trong JavaScript/localStorage sẽ dễ bị XSS lấy | Next.js BFF giữ access/refresh token trong cookie `httpOnly`, `SameSite=Lax`, `Secure` ở production; browser chỉ gọi same-origin `/api/auth/*` |

---

## 3. WebSocket Security & RBAC

### 3.1 Luồng kiểm tra kết nối

`apps/api/src/omniagent/api/routes_stream.py` xử lý handshake theo thứ tự:

1. Kiểm tra `Origin` qua `check_origin`.
2. Ghi nhận quota handshake theo IP.
3. Validate `graph_id` theo `^[A-Za-z0-9_-]{1,64}$`.
4. Trích credential từ subprotocol (ưu tiên), `Authorization: Bearer` hoặc query token nếu cấu hình cho phép.
5. Xác minh JWT (signature, `typ`, issuer/audience, expiry, replay, graph binding), graph authorization và quyền `screen:view` **trước** khi accept; credential sai/thiếu hoặc ticket dùng lại không nhận HTTP `101`.
6. Chỉ principal hợp lệ mới được accept; sau đó áp giới hạn connection theo graph/principal trước khi khởi động streamer/CDP.

Ticket được mint ở `POST /api/auth/ws-ticket`; `routes_auth.py` xác thực principal, role và phạm vi graph trước khi cấp token chỉ bind vào graph đó. Ticket mặc định có TTL 60 giây, dùng một lần và được gửi qua WebSocket subprotocol, không đặt trong URL:

```ts
const ticket = await requestWsTicket(graphId);
const socket = new WebSocket(wsUrl, ['omniagent.v1', ticket.ticket]);
```

Server `ws_auth.py` hỗ trợ hai dạng giao thức tương thích: hai subprotocol `['omniagent.v1', '<ticket>']` hoặc dạng JWT subprotocol đơn theo cấu hình. Không ghi ticket thô vào log; audit chỉ ghi fingerprint đã rút gọn.

### 3.2 Enforce quyền tại mỗi input

Các message quan trọng được kiểm tra server-side, bất kể UI có ẩn nút hay không:

- `SET_TAKEOVER` cần `takeover:control`; một holder duy nhất mỗi graph, lease có TTL và tự hết hạn.
- `MOUSE_EVENT` / `KEYBOARD_EVENT` cần `input:send`, đồng thời phải giữ takeover lease hợp lệ.
- `VIEWER` chỉ có `screen:view`; `_outbound_allowed()` không chuyển `TAKEOVER_STATE` cho viewer.
- `ADMIN` có thêm quyền quản lý graph và đọc audit; role lạ bị hạ về quyền thấp nhất thay vì tự nâng quyền.

Bản thân lease cũng được xác nhận trong `_prepare_input_dispatch()` trước khi streamer gọi CDP. Không dùng trạng thái React/React Flow làm quyết định cấp quyền.

### 3.3 Throttling, kích thước và vòng đời

Giá trị mặc định trong `apps/api/src/omniagent/sandboxes/browser/config.py`:

| Hạn mức | Mặc định |
|---|---:|
| Tin nhắn tổng | burst 200, refill 120/giây |
| Input `MOUSE_EVENT` / `KEYBOARD_EVENT` | burst 120, refill 90/giây |
| Control/takeover | burst 8, refill 1/giây |
| Ping | burst 6, refill 0.5/giây |
| Auth refresh | burst 5, refill 0.2/giây |
| Tổng input của một graph | burst 160, refill 120/giây |
| Mouse move coalescing | 16 ms (xấp xỉ 60 Hz) |
| Handshake | 12 lần / 60 giây / IP |
| Số socket đồng thời | tối đa 8 / graph, 3 / principal |
| Strike trước khi đóng do spam | 5 |
| Message tối đa | 65,536 byte |
| Idle timeout / lifetime | 120 giây / 3,600 giây |
| Grace trả lời `AUTH_REQUIRED` | 30 giây |

Payload bị giới hạn trước JSON decode. Client có token bucket/coalescing riêng trong `src/lib/ws/wsClient.ts`, nhưng đây chỉ là tối ưu trải nghiệm và giảm tải; quota server là nguồn quyết định.

### 3.4 Mã lỗi và audit

Server dùng application error code và close code ổn định; ví dụ `40300` (forbidden), `41301` (message quá lớn), `42901` (rate limit), close `4401` (unauthenticated), `4403` (forbidden), `4413` (payload quá lớn), `4429` (throttle). Lỗi handshake trả public message chung, không gửi exception/CDP URL/raw token về client. `security/audit.py` ghi sự kiện có redaction email và fingerprint token.

---

## 4. Browser sandbox isolation

### 4.1 Luồng CDP

```text
FastAPI / Playwright
    │ Authorization: Bearer <per-session secret>
    ▼
CDP guard :9222 (auth, path/origin allow-list, client cap)
    │ rewrite Host + webSocketDebuggerUrl
    ▼
Chromium 127.0.0.1:9223 (--user-data-dir per SESSION_ID)
```

`infra/sandbox-browser/cdp_guard.py` dùng Python stdlib/asyncio, từ chối request không có token hợp lệ, allow-list path CDP, chặn endpoint quản lý target theo mặc định, giới hạn số client, kiểm tra origin khi được cấu hình và rewrite địa chỉ DevTools WebSocket để client luôn quay lại qua guard. `/healthz`, `/readyz` và metrics chỉ cho truy cập cục bộ theo mặc định. Log chỉ ghi fingerprint token, không ghi token gốc.

`CDP_PORT` và `CDP_INTERNAL_PORT` phải khác nhau; guard nghe port public trong container, Chromium chỉ nghe loopback port nội bộ. Docker Compose không khai báo `ports:` nên CDP không bị publish ra host.

### 4.2 Profile và quyền tiến trình

`sandbox-entrypoint.sh`:

- Từ chối chạy bằng root; thiết lập `umask 077`.
- Tạo profile `/tmp/sandbox-profiles/$SESSION_ID`, chmod `0700`.
- Từ chối profile cũ không rỗng nếu `PROFILE_REUSE=0`; mặc định profile ephemeral được xóa khi exit.
- `CHROMIUM_SANDBOX=auto` bật Chromium user-namespace sandbox nếu host cho phép; nếu không có user namespace, mặc định **fail closed**. `--no-sandbox` chỉ được chấp nhận khi operator đặt `SANDBOX_ALLOW_NO_SANDBOX=1` một cách tường minh.
- Từ chối `EXTRA_CHROME_ARGS` nếu chứa option có thể ghi đè `--user-data-dir`, cổng/địa chỉ debugging, origin CDP hoặc tắt sandbox.
- Giám sát cả guard lẫn Chromium, dọn profile và dừng child process khi nhận TERM/INT.

Dockerfile/Compose chạy uid `1000:1000`, `cap_drop: [ALL]`, `no-new-privileges`, read-only root, tmpfs cho `/tmp`, cache và `/dev/shm`, giới hạn memory/CPU/PID/ulimit, không core dump. Network Docker `internal` mặc định bật; muốn cho browser egress cần đặt proxy/egress policy có allow-list và đổi `SANDBOX_NETWORK_INTERNAL` có chủ đích.

> **Lưu ý triển khai:** Docker seccomp mặc định thường chặn `clone(CLONE_NEWUSER)`. Compose do đó mặc định từ chối chạy sandbox nếu Chromium sandbox không khởi tạo được. Cần một seccomp profile đã được review cho user namespaces hoặc gVisor/Kata/Firecracker. Không bật `SANDBOX_ALLOW_NO_SANDBOX=1` trên workload không tin cậy nếu chưa chấp nhận rõ rủi ro container-only.

### 4.3 Hợp đồng session isolation

1. Orchestrator cấp một `SESSION_ID`/graph riêng cho từng session.
2. Mỗi sandbox nhận `CDP_GUARD_TOKEN` ngẫu nhiên, riêng session (ví dụ tạo bằng `openssl rand -hex 32` qua secret manager; không commit vào repo).
3. API nhận cùng secret bằng `OMNIAGENT_BROWSER_SANDBOX_CDP_AUTH_TOKEN` hoặc cơ chế template/secret injection per-sandbox.
4. Sandbox không được tái sử dụng profile giữa hai user; khi kết thúc session xóa profile/pod/volume tương ứng.

`infra/sandbox-browser/README.md` có threat model, biến môi trường, checklist kiểm chứng và `securityContext`/NetworkPolicy tham khảo cho Kubernetes.

---

## 5. Tích hợp xác thực Next.js ↔ FastAPI

### 5.1 Kiến trúc

```text
Browser / React Flow
  ├── POST /api/auth/login ──────┐
  ├── GET  /api/auth/me          │ same-origin, JSON, Origin checked
  ├── POST /api/auth/ticket      ▼
  └── WS /ws/graph/{graph_id}  Next.js BFF ── Bearer access JWT ── FastAPI
      Sec-WebSocket-Protocol:                                    │
      omniagent.v1, <one-time ticket>                            └─ auth/ticket + stream
```

- `src/lib/auth/session.ts` là module **server-only**: cookie `omniagent_at`/`omniagent_rt`, `httpOnly`, `SameSite=Lax`, `Secure` ở production; `apiFetch()` chỉ nhận đường dẫn relative `/api/...`, dùng timeout và `cache: no-store`.
- `src/app/api/auth/{login,logout,refresh,me,ticket,register,config}/route.ts` là BFF. Các POST kiểm tra Origin và `Content-Type: application/json`. Browser không bao giờ nhận access/refresh JWT. Cookie access có tuổi thọ access token; refresh cookie tồn tại lâu hơn và có thể xoay vòng sau khi access cookie hết hạn.
- `src/lib/auth/client.ts` và `useAuth.ts` cung cấp browser helpers/session state; các request dùng `credentials: 'same-origin'`. Refresh được coalesce ở client khi nhiều graph cùng xin ticket.
- `src/lib/ws/wsClient.ts` xin ticket mới trước mỗi kết nối/reconnect, đưa ticket vào `Sec-WebSocket-Protocol`, heartbeat, reconnect có backoff+jitter và gửi ticket mới bằng message `AUTH` khi server yêu cầu re-auth.
- `src/canvas/hooks/useBrowserStream.ts` nối `SCREEN_FRAME` vào stream store theo graph; `BrowserNode.tsx` vẽ live frame nếu bật streaming, nếu không tiếp tục dùng mock. Mỗi node live phải có `data.graphId` bằng graph/session ID thật được cấp quyền; thiếu trường này chỉ fallback sang node id cho demo. Nút takeover chỉ bật khi backend xác nhận quyền điều khiển; pointer/keyboard listener chỉ được gắn khi có quyền input **và** takeover lease đang active.
- `NEXT_PUBLIC_OMNIAGENT_STREAMING` mặc định `false`; bật `true` khi API/WS route và graph session được provision. `NEXT_PUBLIC_OMNIAGENT_WS_BASE_URL` để trống nếu reverse proxy cùng origin; nếu API ở origin riêng, cần cấu hình proxy/CSP/origin allow-list tương ứng.

### 5.2 Quy trình token

1. Browser gửi email/password qua `/api/auth/login`; Next BFF chuyển tiếp tới FastAPI `/api/auth/login`.
2. FastAPI trả access JWT ngắn hạn (mặc định 15 phút) và refresh JWT. BFF ghi chúng vào cookie `httpOnly`; browser chỉ nhận `subject`, `role`, `permissions` và `user` public.
3. Với mỗi graph, browser gọi `/api/auth/ticket` bằng cookie. BFF gửi access JWT tới FastAPI. FastAPI kiểm tra graph scope rồi phát one-time ticket, mặc định 60 giây.
4. Browser kết nối WS bằng protocol `['omniagent.v1', ticket]`. Ticket không nằm trong URL/query string, browser history hay Referer.
5. Trước expiry/nhận `AUTH_REQUIRED`, client xin ticket khác và gửi `AUTH` trong WS hiện tại; FastAPI áp replay/fingerprint/expiry/graph checks.
6. Khi access token hết hạn, client gọi `/api/auth/refresh`; FastAPI xoay refresh token, BFF thay cả hai cookie rồi retry request ticket.
7. Logout gọi FastAPI để revoke session, sau đó xóa hai cookie phía BFF.

### 5.3 Biến môi trường và cấu hình bắt buộc

Ví dụ production — thay domain/secret bằng secret manager, không dùng giá trị minh họa:

```dotenv
# FastAPI
OMNIAGENT_AUTH_ENABLED=true
OMNIAGENT_JWT_SECRET=<random-secret-at-least-43-characters>
OMNIAGENT_JWT_ISSUER=omniagent-studio
OMNIAGENT_JWT_AUDIENCE=omniagent-api
OMNIAGENT_API_WS_ALLOWED_ORIGINS=["https://studio.example.com"]
OMNIAGENT_API_WS_TOKEN_IN_QUERY=false
OMNIAGENT_API_CORS_ALLOW_ORIGINS=["https://studio.example.com"]
OMNIAGENT_AUTH_ALLOW_SELF_REGISTRATION=false
OMNIAGENT_AUTH_REGISTRATION_GRAPH_IDS=<per-tenant-graph-scope>
OMNIAGENT_BROWSER_SANDBOX_REQUIRE_REMOTE=true
OMNIAGENT_BROWSER_SANDBOX_CDP_REJECT_LOOPBACK=true
OMNIAGENT_BROWSER_SANDBOX_CDP_AUTH_TOKEN_TEMPLATE=<secret-manager-backed-value>
OMNIAGENT_API_DOCS_ENABLED=false

# Next.js server-only / browser-safe
OMNIAGENT_API_URL=https://api.internal.example
NEXT_PUBLIC_OMNIAGENT_STREAMING=true
# Prefer same-origin reverse proxy for /ws; only set a separate WSS origin if needed.
NEXT_PUBLIC_OMNIAGENT_WS_BASE_URL=
```

- `OMNIAGENT_JWT_SECRET` cần tối thiểu 43 ký tự entropy cao (ví dụ sinh 48 bytes ngẫu nhiên); với nhiều issuer có thể dùng RS256/ES256 private/public key thay HS256.
- `api_ws_allowed_origins` mặc định rỗng để hỗ trợ dev và phát cảnh báo; **production phải đặt allow-list chính xác**. Tắt query credential trong production vì URL có thể bị log.
- Không cấp `auth_registration_graph_ids="*"` cho tenant/user production. Mặc định đăng ký self-service tắt, role đăng ký là VIEWER.
- Chỉ bật `api_trust_proxy_headers` khi FastAPI đứng sau proxy tin cậy đã xóa/ghi lại forwarding headers.
- Không đặt `NEXT_PUBLIC_` trước API URL hoặc JWT; chỉ URL WS public (nếu cần) và cờ stream được phép đưa ra browser.
- `next.config.ts` thêm CSP, `X-Content-Type-Options`, `X-Frame-Options`, Referrer/Permissions Policy, COOP, HSTS ở production, `no-store` cho `/api/*`; CSP hiện còn `unsafe-inline`/`unsafe-eval` để tương thích app hiện tại. Cần triển khai nonce CSP sau khi có kiểm thử CSP report-only.

---

## 6. Kiểm thử và kiểm chứng

### Đã chạy

- `python -m pytest apps/api/tests -q` → **74 passed, 3 skipped**.
- `tsc --noEmit` → **pass** sau khi cho Git track lại `src/lib/**` (pattern Python `lib/` trong `.gitignore` trước đó đã ignore nhầm nguồn frontend).
- `npm run build` → **pass** (Next.js standalone build + auth BFF routes). Build trước đó bị chặn bởi cấu hình standalone/script copy và Google Fonts fetch; script/config đã được sửa để build hermetic.
- `bash -n infra/sandbox-browser/sandbox-entrypoint.sh` → pass.
- CDP guard đã được kiểm tra với fake upstream: từ chối thiếu/sai bearer, 403 target-management/path không cho phép, rewrite `webSocketDebuggerUrl`, `/healthz`, WebSocket upgrade/pipe, trả 502 khi upstream chết; log không lộ raw token.
- `infra/docker-compose.sandbox.yml` đã được parse/validate bằng PyYAML; service browser không publish port. Docker Compose CLI không có trong sandbox nên chưa chạy `docker compose config`.
- Dry-run entrypoint xác nhận `EXTRA_CHROME_ARGS=--user-data-dir=...` bị từ chối, exit non-zero và profile tạm bị xóa.
- `npx prisma generate` chưa hoàn tất được trong sandbox vì Prisma CLI cần tải schema engine từ `binaries.prisma.sh` (host này không nằm trong allow-list outbound); schema là cơ sở cho bước adapter/migration sau này.
- ESLint chưa chạy được: repo chưa có `eslint.config.*` cho ESLint 9, nên script `npm run lint` hiện lỗi cấu hình trước khi lint source.

### Lệnh kiểm tra trước deploy

```bash
# API tests
python -m pytest apps/api/tests -q

# Frontend type-check / build
./node_modules/.bin/tsc --noEmit
npm run build

# Shell syntax + cấu hình container
bash -n infra/sandbox-browser/sandbox-entrypoint.sh
docker compose -f infra/docker-compose.sandbox.yml config

# Runtime: không phải root, read-only, cap drop, không publish 9222
# Profile mode 0700, guard 401 nếu thiếu bearer, Chromium port chỉ loopback
```

---

## 7. Giới hạn còn lại và việc cần hoàn tất trước production

1. **State phân tán:** `JtiStore` (replay/revocation), `LoginThrottle`, handshake limiter và graph limiter hiện ở process memory. Nhiều worker/replica hoặc restart cần Redis/DB-backed shared store và limiter, nếu không replay/revocation có thể không đồng nhất giữa instance. Không scale ngang chỉ bằng tăng worker.
2. **User store:** API hiện hỗ trợ `InMemoryUserStore`/file store cho dev/test. `prisma/schema.prisma` định nghĩa hướng lưu `User`, `GraphMembership`, `Session`, `AuditEvent`, nhưng **chưa thay thế user store của FastAPI**. Cần adapter/migration, transaction cho refresh rotation, backup và account lifecycle trước production.
3. **Seccomp userns:** repo không vendor một profile seccomp custom; Docker Compose fail closed mặc định. Cần profile đã review hoặc runtime gVisor/Kata; không bật no-sandbox fallback mặc định.
4. **CDP secret provisioning:** triển khai orchestrator phải phát token riêng mỗi sandbox, inject an toàn cho cả API và container, rotate/xóa cùng vòng đời graph; không dùng chung một secret fleet-wide.
5. **Origin/proxy:** khai báo chính xác origin của frontend ở cả WS Origin allow-list và CORS; reverse proxy phải chuyển tiếp WS, dùng TLS, đặt giới hạn kết nối/timeout và chỉ tin `X-Forwarded-*` từ proxy tin cậy.
6. **CSP:** CSP tương thích hiện tại dùng inline/eval và scheme `wss:`; nên kiểm tra report-only, dùng nonce và pin `connect-src` vào origin WS cụ thể trước khi go-live.
7. **Screencast:** cần kiểm tra tải băng thông/memory ở số session thực tế; giảm resolution/FPS hoặc frame queue theo ngân sách tài nguyên thực tế.
8. **Audit/privacy:** điều chỉnh `audit_ip_addresses` theo chính sách dữ liệu cá nhân, bảo vệ log store và thiết lập retention/alerting.

---

## 8. Mã nguồn chính đã chỉnh sửa

### Backend FastAPI

- `apps/api/src/omniagent/api/routes_stream.py` — handshake gauntlet, writer outbound RBAC, payload guard, input dispatch guard, watchdog.
- `apps/api/src/omniagent/api/routes_auth.py` — login/register/refresh/logout/me/ws-ticket/config và object-level ticket scope.
- `apps/api/src/omniagent/security/{roles,tokens,ws_auth,ratelimit,user_store,audit}.py` — RBAC, JWT, handshake auth, limiter, password store và audit.
- `apps/api/src/omniagent/api/{graph_access,connection_registry}.py` — graph authorization, CDP endpoint guard, connection caps và takeover lease.

### Browser runtime / frontend

- `infra/sandbox-browser/{Dockerfile,sandbox-entrypoint.sh,cdp_guard.py}` và `infra/docker-compose.sandbox.yml`.
- `src/lib/auth/{session.ts,client.ts,useAuth.ts}`, `src/app/api/auth/**/route.ts`, `src/app/login/page.tsx`.
- `src/lib/ws/{protocol.ts,wsClient.ts}`, `src/canvas/{hooks/useBrowserStream.ts,store/streamStore.ts,nodes/BrowserNode.tsx}`.
- `src/app/page.tsx`, `src/app/layout.tsx`, `src/app/globals.css`, `src/canvas/components/TopBar.tsx`, `next.config.ts`, `postcss.config.mjs`, `.env.example`, `package.json` (standalone build/start scripts), `prisma/schema.prisma`.
