# OmniAgent Studio — Worklog

---

Task ID: 1 (full build, single agent session)
Agent: Z.ai Code (main)
Task: Scaffold và xây dựng hoàn chỉnh giao diện Frontend "OmniAgent Studio" — React Flow infinite canvas + 3 custom nodes (Browser/Analyst/Dashboard) + Zustand store + mock data flow Browser→Analyst→Dashboard, dark-mode Cyberpunk/Modern Dev Tool.

Work Log:
- Khảo sát dự án Next.js 16 (App Router) sẵn có; quyết định giữ nguyên Next.js thay vì Vite (môi trường sandbox chỉ hỗ trợ Next.js trên port 3000) — toàn bộ yêu cầu chức năng được đáp ứng tương đương.
- Cài `@xyflow/react@12.12.0`, `echarts@6.1.0` (zustand 5, lucide-react có sẵn).
- Viết theme Cyberpunk vào `src/app/globals.css`: palette neon cyan/fuchsia/emerald/amber, `.cyber-grid` (grid + nebula glows), `.scanlines`, `.vignette`, `.node-shell` (glass console panel), corner brackets, override React Flow Controls/MiniMap/Handles/Edges/Selection, `.type-caret`, `.scrollbar-thin`, keyframes `alertPulse`/`glowBreathe`/`urlProgress`.
- Tạo `src/canvas/types.ts`: typed node data (BrowserNodeData/AnalystNodeData/DashboardNodeData) theo pattern `Node<T, 'type'>` của React Flow v12.
- Tạo `src/canvas/data/mockFlow.ts`: node ids, NAV_URLS (4 URL xoay vòng), THOUGHT_SCRIPT (12 dòng thought/tool/result), deterministic mulberry32 PRNG cho dữ liệu line chart ban đầu (tránh hydration mismatch), `buildInitialFlow()` trả về 3 nodes + 2 edges có label ("cdp screencast", "structured insights").
- Tạo `src/canvas/store/graphStore.ts` (Zustand): onNodesChange/onEdgesChange/onConnect (addEdge), running/ticks, toggleRunning, resetFlow, addNode (3 loại), removeNode, và các simulation mutations: bumpTick, toggleTakeover, setBrowserStatus, navigateBrowser, pushThought, tickDashboard (live line chart rolling window 26 điểm + events counter).
- Shared components (`src/canvas/components/`): `NodeShell.tsx` (NodeShell + CornerBrackets + StatusBadge + accent tokens static strings), `EChart.tsx` (wrapper echarts init/dispose + ResizeObserver + setOption notMerge), `TopBar.tsx` (brand, session pill, insert-node group, reset, Pause/Resume), `StatusBar.tsx` (runtime state, node/edge counts, ticks, latency, clock — sticky footer).
- Custom nodes (`src/canvas/nodes/`):
  - `BrowserNode.tsx`: URL bar (Lock + URL + bitrate), progress bar khi Browsing, `<canvas>` 680×400 @2x vẽ fake page theo hash URL + scanline động + captcha overlay 3×3 (CaptchaDetected) + paused overlay + crosshair takeover (mouse-follow), badge Browsing/CaptchaDetected/Paused, node alert border pulse khi captcha, nút TAKEOVER/RELEASE CONTROL.
  - `AnalystNode.tsx`: LLM Thought Stream (max-h scroll + autoscroll), typing effect 48 bước/16ms chỉ trên dòng mới nhất (pattern "adjust state during render" — không setState trong effect body, pass eslint react-hooks/set-state-in-effect), badge Reasoning/ToolCall/Idle/Done, telemetry tokens/model/ctx/temp.
  - `DashboardNode.tsx`: auto-render từ schema JSON — 4 KPI cards (delta tốt/xấu emerald/rose) + Line chart (LinearGradient area, 2 series sessions/errors, tooltip neon) + Bar chart (rounded, gradient). ECharts option useMemo theo schema.
- `src/canvas/hooks/useAgentRuntime.ts`: engine mô phỏng tick 1500ms — push thought mỗi 2 tick, navigate URL mỗi 7 tick (kèm tool log), captcha window mỗi 11 tick (tự giải sau 4 tick), live chart mỗi tick; dừng khi `running === false`; toàn bộ randomness nằm trong interval (SSR ổn định).
- `src/canvas/FlowCanvas.tsx`: ReactFlow + Background dots + Controls + MiniMap (pannable/zoomable, nodeColor theo type) + Panel breadcrumb/legend + panel hints; nodeTypes module-scope; fitView.
- `src/app/page.tsx`: layout h-screen flex-col (TopBar / canvas flex-1 / StatusBar mt-auto — sticky footer chuẩn).
- `src/app/layout.tsx`: metadata OmniAgent Studio, `className="dark"` trên html.
- Fix bug QA: BrowserNode thiếu `<Handle type="source">` → edge browser→analyst không render (console warning #008). Đã thêm handle.
- Fix lint: setState đồng bộ trong effect ở AnalystNode → refactor theo React pattern.
- QA bằng agent-browser: desktop 1280×720 (render đẹp, 2 edges có label, thought stream chạy, 10→29 ticks tăng), click TAKEOVER → RELEASE CONTROL + crosshair + "HUMAN TAKEOVER", click PAUSE → RUNTIME HALTED + nút RESUME, Insert Browser node → 4 nodes + legend ×2, Reset workspace → 3 nodes, mobile 390×844 (TopBar thu gọn, layout ổn). 0 page errors, console sạch sau fix.

Stage Summary:
- App chạy tại `/` (Next.js dev port 3000), lint + tsc sạch (lỗi tsc còn lại chỉ ở `examples/`, `skills/` của scaffold, không thuộc app).
- Toàn bộ yêu cầu chức năng hoàn thành: infinite canvas, Zustand graphStore, 3 custom nodes đúng spec, mock flow Browser→Analyst→Dashboard chạy ngay khi mở, dark cyberpunk UI, lucide-react icons, code modular theo `src/canvas/`.
- Ảnh QA: qa-desktop.png, qa-desktop2.png, qa-takeover.png, qa-pause-insert.png, qa-mobile.png.
- Rủi ro/đề xuất tiếp theo: (1) thêm mini-service WebSocket thật để stream screencast/thay simulation; (2) node context menu + edge deletion UX; (3) persistence graph qua Prisma; (4) fitView tối ưu cho mobile (padding lớn hơn); (5) export/import graph JSON.
